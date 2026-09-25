/* DoH Proxy 登录页。独立、极简:只负责提交 ADMIN_SECRET、用一次 Bearer
   校验请求让服务端种下 HttpOnly 会话 cookie,然后进入控制台。
   这个页面可被任何未认证请求到达,所以绝不能触碰任何管理 API 数据。 */
(() => {
  "use strict";

  const TOKEN_KEY = "doh_admin_token";
  const form = document.getElementById("login-form");
  const input = document.getElementById("login-secret");
  const btn = form.querySelector("button[type=submit]");
  const err = document.getElementById("login-error");

  function showError(msg) {
    err.textContent = msg;
    err.classList.remove("hidden");
  }

  async function login(e) {
    e.preventDefault();
    const secret = input.value.trim();
    btn.disabled = true;
    btn.textContent = "登录中…";
    err.classList.add("hidden");
    try {
      // 校验密码。成功响应会带 Set-Cookie 建立会话,从而让服务端在后续
      // 页面请求时下发真正的控制台(/ 再次请求即会命中 index.html)。
      const res = await fetch("/admin/api/health", {
        headers: { authorization: "Bearer " + secret },
      });
      if (res.ok) {
        sessionStorage.setItem(TOKEN_KEY, secret);
        location.href = "/";
      } else if (res.status === 401) {
        showError("ADMIN_SECRET 不正确");
      } else {
        showError("登录失败:HTTP " + res.status);
      }
    } catch (ex) {
      showError("登录失败:" + (ex && ex.message ? ex.message : String(ex)));
    } finally {
      btn.disabled = false;
      btn.textContent = "登录";
    }
  }

  form.addEventListener("submit", login);

  // 会话已有效(例如新标签页、或直接访问 /login.html)时直接进入控制台。
  // HttpOnly cookie 对 JS 不可见,所以不带凭据探活:命中有效 cookie 即跳转。
  fetch("/admin/api/health")
    .then((res) => {
      if (res.ok) location.href = "/";
    })
    .catch(() => {});
})();
