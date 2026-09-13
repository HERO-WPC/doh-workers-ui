/* DoH Proxy 控制台前端。Vanilla JS,所有数据来自 /admin/api/*。 */
(() => {
  "use strict";

  const TOKEN_KEY = "doh_admin_token";
  const api = (path) => "/admin/api" + path;

  const $ = (sel) => document.querySelector(sel);
  const el = (id) => document.getElementById(id);

  function token() {
    return sessionStorage.getItem(TOKEN_KEY) || "";
  }

  async function request(path, options = {}) {
    const headers = { authorization: "Bearer " + token(), ...(options.headers || {}) };
    if (options.body !== undefined) headers["content-type"] = "application/json";
    const res = await fetch(api(path), { ...options, headers });
    if (res.status === 401) {
      showLogin("登录已失效,请重新登录");
      throw new Error("unauthorized");
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const msg = data && data.error ? data.error : "HTTP " + res.status;
      throw new Error(msg);
    }
    return data;
  }

  const get = (path) => request(path);
  const send = (path, method, body) => request(path, { method, body: JSON.stringify(body) });

  function toast(msg, isError) {
    const t = el("toast");
    t.textContent = msg;
    t.style.borderColor = isError ? "var(--red)" : "var(--border)";
    t.classList.remove("hidden");
    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => t.classList.add("hidden"), 2600);
  }

  function showLogin(errText) {
    sessionStorage.removeItem(TOKEN_KEY);
    el("app-view").classList.add("hidden");
    el("login-view").classList.remove("hidden");
    if (errText) {
      const e = el("login-error");
      e.textContent = errText;
      e.classList.remove("hidden");
    }
  }

  function showApp() {
    el("login-view").classList.add("hidden");
    el("app-view").classList.remove("hidden");
    switchTab("dashboard");
    refreshAll();
  }

  // ------------------------------------------------------------------
  // Tabs
  // ------------------------------------------------------------------
  function switchTab(name) {
    document.querySelectorAll(".panel").forEach((p) => p.classList.add("hidden"));
    el("tab-" + name).classList.remove("hidden");
    document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
  }
  el("tabs").addEventListener("click", (e) => {
    const btn = e.target.closest(".tab");
    if (btn) switchTab(btn.dataset.tab);
  });

  function copyText(text) {
    navigator.clipboard.writeText(text).then(
      () => toast("已复制"),
      () => toast("复制失败", true),
    );
  }
  document.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-copy]");
    if (btn) copyText($(btn.dataset.copy).textContent.trim());
  });

  // ------------------------------------------------------------------
  // Dashboard
  // ------------------------------------------------------------------
  let currentConfig = null;

  function badgeFor(healthy) {
    if (healthy === true) return '<span class="badge green">健康</span>';
    if (healthy === false) return '<span class="badge red">异常</span>';
    return '<span class="badge gray">未知</span>';
  }

  function statCard(label, value, sub) {
    return `<div class="stat"><div class="label">${label}</div><div class="value">${value}</div>${sub ? `<div class="sub">${sub}</div>` : ""}</div>`;
  }

  async function refreshDashboard() {
    const [health, stats, config, usage] = await Promise.all([
      get("/health"), get("/stats"), get("/config"), get("/usage").catch(() => null),
    ]);
    currentConfig = config.config;
    el("worker-version").textContent = "v" + (health.version || "");
    el("doh-url").textContent = config.dohUrl;

    el("health-cards").innerHTML =
      statCard("状态", health.status === "ok" ? "正常" : "降级") +
      statCard("KV", health.kvReachable ? "可达" : "不可达") +
      statCard("配置版本", "v" + health.configVersion, config.config.updatedAt || "") +
      statCard("L1 缓存条目", health.cache.entries, bytesHuman(health.cache.bytes)) +
      statCard("运行时间", fmtDuration(health.isolate.uptimeSeconds), "本 isolate");

    const s = stats.global || {};
    el("stats-cards").innerHTML =
      statCard("总请求", s.requests ?? 0) +
      statCard("缓存命中", s.cacheHits ?? 0) +
      statCard("Stale 服务", s.cacheStale ?? 0) +
      statCard("缓存未命中", s.cacheMisses ?? 0) +
      statCard("上游成功", s.upstreamOk ?? 0, s.upstreamAvgRttMs != null ? "平均 " + s.upstreamAvgRttMs + " ms" : "") +
      statCard("上游失败", (s.upstreamFail ?? 0) + (s.upstreamTimeouts ? ` (超时 ${s.upstreamTimeouts})` : ""));
    el("isolate-note").textContent =
      `本 isolate:已处理 ${stats.isolate.requests} 次请求,存活 ${fmtDuration(stats.isolate.uptimeSeconds)}(计数器随 isolate 回收重置,全局累计见上)`;

    renderUsage(usage);

    el("upstream-health").innerHTML = stats.upstreams
      .map(
        (u) => `<div class="row">
          <span style="min-width:120px">${escapeHtml(u.name)}</span>
          ${badgeFor(u.enabled ? (u.ok >= u.fail + u.timeoutCount ? true : u.ok + u.fail + u.timeoutCount > 0 ? false : null) : null)}
          <span class="muted">RTT ${u.rttEmaMs != null ? u.rttEmaMs + " ms" : "?"} · score ${u.score} · 优先级 ${u.priority}</span>
        </div>`,
      )
      .join("");

    renderCacheForm(currentConfig);
    renderEcsForm(currentConfig);
    el("path-box").textContent = currentConfig.doh.path;
  }

  function bytesHuman(n) {
    if (n == null) return "";
    return n > 1048576 ? (n / 1048576).toFixed(1) + " MB" : Math.round(n / 1024) + " KB";
  }

  function quotaBar(label, used, quota, unit) {
    const pct = Math.min(100, Math.round(((used / quota) * 100)));
    const cls = pct >= 90 ? "danger" : pct >= 60 ? "warn" : "";
    return `<div class="quota-row">
      <span class="quota-label">${label}</span>
      <div class="quota-track"><div class="quota-fill ${cls}" style="width:${pct}%"></div></div>
      <span class="quota-num">${used.toLocaleString()} / ${quota.toLocaleString()} ${unit || ""} (${pct}%)</span>
    </div>`;
  }

  function renderUsage(u) {
    if (!u || !u.workers) {
      el("usage-cards").innerHTML = "";
      el("usage-bars").innerHTML = "";
      el("usage-note").textContent = "用量数据暂不可用。";
      return;
    }
    const w = u.workers, k = u.kv;
    el("usage-cards").innerHTML =
      statCard("Workers 请求 · 今日", (w.requestsToday ?? 0).toLocaleString(), "免费额度 " + w.freeTierPerDay.toLocaleString() + "/日") +
      statCard("Workers 请求 · 累计", (w.requestsTotal ?? 0).toLocaleString(), "自统计开启以来") +
      statCard("KV 读 · 今日", (k.readsToday ?? 0).toLocaleString(), "累计 " + (k.readsTotal ?? 0).toLocaleString()) +
      statCard("KV 写 · 今日", (k.writesToday ?? 0).toLocaleString(), "累计 " + (k.writesTotal ?? 0).toLocaleString()) +
      statCard("KV 键数量", k.keyCount ?? "?", "写入流量 " + bytesHuman(k.writeBytesTotal) + " · 读取 " + bytesHuman(k.readBytesTotal));
    el("usage-bars").innerHTML =
      quotaBar("Workers 请求(今日)", w.requestsToday ?? 0, w.freeTierPerDay, "次") +
      quotaBar("KV 写(今日)", k.writesToday ?? 0, k.freeWritesPerDay, "次") +
      quotaBar("KV 读(今日)", k.readsToday ?? 0, k.freeReadsPerDay, "次");
    el("usage-note").textContent =
      `统计日 ${u.day}(UTC)· 计数为本 Worker 自报近似值:内存累积、每 10 分钟批量写入 KV,尾部请求可能未计入`;
  }
  function fmtDuration(sec) {
    if (sec < 60) return sec + "s";
    if (sec < 3600) return Math.round(sec / 60) + "m";
    return Math.round(sec / 3600) + "h";
  }
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  // ------------------------------------------------------------------
  // Upstreams
  // ------------------------------------------------------------------
  let editingId = null;

  async function refreshUpstreams() {
    const [stats, cfgResp] = await Promise.all([get("/stats"), get("/config")]);
    const byId = Object.fromEntries(stats.upstreams.map((u) => [u.id, u]));
    const rows = cfgResp.config.upstreams
      .map((u) => {
        const m = byId[u.id] || {};
        const rel = m.reliability != null ? Math.round(m.reliability * 100) + "%" : "?";
        return `<tr>
          <td>${escapeHtml(u.name)}</td>
          <td><code>${escapeHtml(u.url)}</code></td>
          <td><input type="checkbox" ${u.enabled ? "checked" : ""} data-toggle="${u.id}" /></td>
          <td>${u.priority}</td>
          <td>${u.timeout}</td>
          <td>${m.rttEmaMs != null ? m.rttEmaMs + " ms" : "?"}</td>
          <td>${rel}</td>
          <td>${m.score ?? "?"}</td>
          <td>
            <button class="btn small" data-test="${u.id}">测试</button>
            <button class="btn small" data-edit="${u.id}">编辑</button>
            <button class="btn small danger" data-del="${u.id}">删除</button>
          </td>
        </tr>`;
      })
      .join("");
    $("#upstreams-table tbody").innerHTML = rows;
  }

  el("upstreams-table").addEventListener("click", async (e) => {
    const test = e.target.closest("[data-test]");
    if (test) {
      test.disabled = true;
      try {
        const r = await send("/test-upstream", "POST", { id: test.dataset.test });
        toast(r.ok ? `上游正常,RTT ${r.rttMs} ms` : `测试失败: ${r.error || "未知错误"}`, !r.ok);
      } catch (err) {
        toast(err.message, true);
      }
      test.disabled = false;
      return;
    }
    const del = e.target.closest("[data-del]");
    if (del) {
      if (!confirm("确定删除该上游?")) return;
      try {
        await send("/upstreams/" + encodeURIComponent(del.dataset.del), "DELETE");
        toast("已删除");
        refreshUpstreams();
      } catch (err) {
        toast(err.message, true);
      }
      return;
    }
    const edit = e.target.closest("[data-edit]");
    if (edit) {
      const cfgResp = await get("/config");
      const u = cfgResp.config.upstreams.find((x) => x.id === edit.dataset.edit);
      if (!u) return;
      editingId = u.id;
      el("upstream-form-title").textContent = "编辑上游";
      const f = el("upstream-form");
      f.name.value = u.name;
      f.url.value = u.url;
      f.priority.value = u.priority;
      f.timeout.value = u.timeout;
      f.enabled.checked = u.enabled;
      el("upstream-submit").textContent = "保存";
      el("upstream-cancel").classList.remove("hidden");
    }
  });

  el("upstreams-table").addEventListener("change", async (e) => {
    const toggle = e.target.closest("[data-toggle]");
    if (toggle) {
      try {
        await send("/upstreams/" + encodeURIComponent(toggle.dataset.toggle), "PUT", { enabled: toggle.checked });
        toast("已更新");
      } catch (err) {
        toast(err.message, true);
      }
      refreshUpstreams();
    }
  });

  el("upstream-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = e.target;
    const body = {
      name: f.name.value.trim(),
      url: f.url.value.trim(),
      priority: Number(f.priority.value),
      timeout: Number(f.timeout.value),
      enabled: f.enabled.checked,
    };
    try {
      if (editingId) {
        await send("/upstreams/" + encodeURIComponent(editingId), "PUT", body);
        toast("已保存");
      } else {
        await send("/upstreams", "POST", body);
        toast("已添加");
      }
      resetUpstreamForm();
      refreshUpstreams();
    } catch (err) {
      showFormError("upstream-msg", err.message);
    }
  });

  el("upstream-cancel").addEventListener("click", resetUpstreamForm);
  function resetUpstreamForm() {
    editingId = null;
    el("upstream-form").reset();
    el("upstream-form").priority.value = 100;
    el("upstream-form").timeout.value = 2500;
    el("upstream-form").enabled.checked = true;
    el("upstream-form-title").textContent = "添加上游";
    el("upstream-submit").textContent = "添加";
    el("upstream-cancel").classList.add("hidden");
    el("upstream-msg").classList.add("hidden");
  }
  function showFormError(id, msg) {
    const e = el(id);
    e.textContent = msg;
    e.classList.remove("hidden");
  }

  // ------------------------------------------------------------------
  // Cache & ECS forms
  // ------------------------------------------------------------------
  function renderCacheForm(cfg) {
    const f = el("cache-form");
    f.minTTL.value = cfg.cache.minTTL;
    f.maxTTL.value = cfg.cache.maxTTL;
    f.staleTTL.value = cfg.cache.staleTTL;
    f.jitterPercent.value = cfg.cache.jitterPercent;
    f.maxBody.value = cfg.cache.maxBody;
    f.mode.value = cfg.routing.mode;
    f.raceCount.value = cfg.routing.raceCount;
  }

  el("cache-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = e.target;
    try {
      await send("/config", "PUT", {
        cache: {
          minTTL: Number(f.minTTL.value),
          maxTTL: Number(f.maxTTL.value),
          staleTTL: Number(f.staleTTL.value),
          jitterPercent: Number(f.jitterPercent.value),
          maxBody: Number(f.maxBody.value),
        },
        routing: { mode: f.mode.value, raceCount: Number(f.raceCount.value) },
      });
      toast("缓存/路由配置已保存");
    } catch (err) {
      toast(err.message, true);
    }
  });

  function renderEcsForm(cfg) {
    const f = el("ecs-form");
    f.mode.value = cfg.ecs.mode;
    f.ipv4Prefix.value = cfg.ecs.ipv4Prefix;
    f.ipv6Prefix.value = cfg.ecs.ipv6Prefix;
    f.fixedSubnet.value = cfg.ecs.fixedSubnet;
  }

  el("ecs-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = e.target;
    try {
      await send("/config", "PUT", {
        ecs: {
          mode: f.mode.value,
          ipv4Prefix: Number(f.ipv4Prefix.value),
          ipv6Prefix: Number(f.ipv6Prefix.value),
          fixedSubnet: f.fixedSubnet.value.trim(),
        },
      });
      toast("ECS 配置已保存");
    } catch (err) {
      toast(err.message, true);
    }
  });

  // ------------------------------------------------------------------
  // Custom path
  // ------------------------------------------------------------------
  el("path-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await send("/config", "PUT", { doh: { path: el("path-form").path.value.trim() } });
      toast("路径已保存,旧路径即将失效");
      refreshAll();
    } catch (err) {
      showFormError("path-msg", err.message);
    }
  });

  el("regen-btn").addEventListener("click", async () => {
    if (!confirm("确定重新生成随机路径?所有已配置客户端都需要更新 DoH URL。")) return;
    try {
      const r = await send("/regenerate-path", "POST", {});
      el("regen-result").classList.remove("hidden");
      el("regen-url").textContent = r.dohUrl;
      toast("新路径已生成");
      refreshAll();
    } catch (err) {
      toast(err.message, true);
    }
  });

  // ------------------------------------------------------------------
  // Login / logout
  // ------------------------------------------------------------------
  el("login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    sessionStorage.setItem(TOKEN_KEY, el("login-secret").value);
    try {
      await get("/health");
      el("login-secret").value = "";
      showApp();
    } catch (err) {
      if (err.message !== "unauthorized") {
        sessionStorage.removeItem(TOKEN_KEY);
        showLogin("登录失败:" + err.message);
      } else {
        showLogin("ADMIN_SECRET 不正确");
      }
    }
  });

  el("logout-btn").addEventListener("click", () => showLogin());

  function refreshAll() {
    refreshDashboard().catch((e) => console.error(e));
    refreshUpstreams().catch((e) => console.error(e));
  }

  // Auto-login when a token is already present.
  if (token()) {
    get("/health")
      .then(showApp)
      .catch(() => showLogin());
  } else {
    showLogin();
  }
})();
