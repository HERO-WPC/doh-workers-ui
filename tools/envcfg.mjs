// tools/envcfg.mjs — 读取本地私有部署标识(tools/.monitor.env)。
//
// 为什么:真实 DoH 域名 / DoH 路径 在公开仓库里等同于凭据,不能写进源码。
// 真实值只放 tools/.monitor.env(已 gitignore);环境变量同名可覆盖。
// 缺失时返回 "your-" 开头的占位符,调用方用 requireReal() 硬校验后再动手写 DNS。
//
// 格式:KEY=VALUE,一行一个,# 开头为注释。见 tools/.monitor.env.example

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));

/** 私有配置文件路径(与 monitor.py 用的是同一个文件)。 */
export const ENV_FILE = path.join(HERE, ".monitor.env");

export const PLACEHOLDER_HOST = "your-doh-domain.example";
export const PLACEHOLDER_PATH = "/your-doh-path/dns-query";
export const PLACEHOLDER_AUTH = "your-auth-path";

function loadEnvFile(file) {
  const out = {};
  let text;
  try {
    text = fs.readFileSync(file, "utf8");
  } catch {
    return out; // 文件不存在是正常情况:交给占位符 + requireReal 报错
  }
  for (const line of text.split(/\r?\n/)) {
    const s = line.trim();
    if (!s || s.startsWith("#")) continue;
    const i = s.indexOf("=");
    if (i < 0) continue;
    out[s.slice(0, i).trim()] = s.slice(i + 1).trim().replace(/^["']|["']$/g, "");
  }
  return out;
}

const FILE_ENV = loadEnvFile(ENV_FILE);

/** 取配置:环境变量 > 配置文件 > fallback。 */
export function cfg(key, fallback) {
  const v = process.env[key] || FILE_ENV[key];
  return v && String(v).trim() ? String(v).trim() : fallback;
}

/** 空值, 或以 your- 开头的占位符(路径类占位符前面带 /, 故先剥掉 /)。 */
export function isPlaceholder(v) {
  const s = String(v ?? "").trim();
  if (!s) return true;
  return s.replace(/^\/+/, "").startsWith("your-");
}

/**
 * DoH 端点 URL:显式传入的 --url 优先,否则由 DOH_HOST + DOH_PATH 拼出。
 * 注意:返回占位 URL 是允许的(只读脚本),写 DNS 的脚本请再调 requireReal()。
 */
export function dohUrl(explicit) {
  if (explicit) return explicit;
  return `https://${cfg("DOH_HOST", PLACEHOLDER_HOST)}${cfg("DOH_PATH", PLACEHOLDER_PATH)}`;
}

/** DoH 路径,已保证以 / 开头。 */
export function dohPath(explicit) {
  const p = explicit || cfg("DOH_PATH", PLACEHOLDER_PATH);
  return p.startsWith("/") ? p : "/" + p;
}

/** DoH 域名(可能是占位符,调用方自行 requireReal)。 */
export function dohHost(explicit) {
  return explicit || cfg("DOH_HOST", PLACEHOLDER_HOST);
}

/**
 * 硬校验:仍是占位符/为空的关键值直接抛错。
 * 用于会写真实 DNS 或对真实端点发请求的脚本 —— 宁可报错也不要动错域名。
 */
export function requireReal(entries) {
  const bad = entries.filter(([, v]) => isPlaceholder(v)).map(([k]) => k);
  if (!bad.length) return;
  throw new Error(
    `缺少本地私有配置: ${bad.join(", ")}\n` +
      `  请在 ${ENV_FILE} 里设置(模板: tools/.monitor.env.example)\n` +
      `  真实域名 / DoH 路径 / 面板路径 等同凭据, 不要写回源码或提交进仓库。`
  );
}
