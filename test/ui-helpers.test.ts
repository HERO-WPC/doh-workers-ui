// 前端工具函数存在性守卫。
//
// public/app.js 是纯浏览器脚本(vitest 不加载执行),一次重构曾误删
// fmtDuration / escapeHtml,导致控制台 refreshDashboard 抛 ReferenceError、
// 其后的面板全部空白。这里对"被调用的工具函数定义"做静态断言,防止再犯。
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const appJs = readFileSync(join(__dirname, "..", "public", "app.js"), "utf8");

const HELPERS = ["fmtDuration", "escapeHtml", "bytesHuman", "statCard", "quotaBar", "badgeFor", "el"];

/** 函数可能写成 function 声明,也可能写成 const 箭头函数 */
function isDefined(fn: string): boolean {
  return appJs.includes(`function ${fn}(`) || appJs.includes(`const ${fn} = (`);
}

describe("public/app.js helper definitions", () => {
  for (const fn of HELPERS) {
    it(`defines ${fn}()`, () => {
      expect(isDefined(fn)).toBe(true);
    });
  }

  it("refreshDashboard 用到的函数都已定义", () => {
    for (const fn of ["fmtDuration", "escapeHtml", "bytesHuman", "statCard", "badgeFor"]) {
      expect(isDefined(fn)).toBe(true);
    }
  });
});
