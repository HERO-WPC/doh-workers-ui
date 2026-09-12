import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    environment: "node",
    // Upstream timeouts inside tests must not stall the suite.
    testTimeout: 20_000,
  },
});
