/**
 * 掌心窗 MCP：隔離唯讀驗收模式。
 *
 * Enabled by default. Only explicit LINJIAN_MCP_READ_ONLY=false disables it.
 * This mode registers exactly two tools and makes only backend GET calls.
 * No phone commands, no screenshot requests, no wallet writes and no activity
 * logging. It applies to /mcp, /mcp-wallet and legacy /sse because both
 * server factories use it when enabled.
 *
 * OAuth verification still happens in oauth-auth.js before MCP routing.
 */
export const readOnlyEnabled = process.env.LINJIAN_MCP_READ_ONLY !== "false";

function textResult(payload, isError = false) {
  return {
    isError,
    content: [{ type: "text", text: JSON.stringify(payload, null, 2) }],
  };
}

/**
 * The caller passes its existing McpServer, zod, and linjianFetch references.
 * This keeps the new module independent from the main 2,000+ line server.
 */
export function makeReadOnlyServer({ McpServer, z, fetchBackend, defaultDevice }) {
  if (!readOnlyEnabled) {
    throw new Error("makeReadOnlyServer must not be used outside read-only mode");
  }
  const server = new McpServer({ name: "掌心窗（唯讀安全測試）", version: "0.3.9.0-ro1" });

  server.tool(
    "linjian_status",
    "唯讀：只讀取掌心窗後端 /health，檢查 Token 能否通過後端驗證；不操作手機。",
    {},
    async () => {
      try {
        const response = await fetchBackend("/health", { method: "GET" });
        const health = await response.json();
        return textResult({
          ok: health?.ok === true,
          read_only: true,
          backend_reachable: true,
          backend_healthy: health?.ok === true,
          service: String(health?.service || ""),
          version: String(health?.version || ""),
        });
      } catch (error) {
        return textResult({
          ok: false,
          read_only: true,
          backend_reachable: false,
          error: "backend_health_check_failed",
          detail: String(error?.message || error).slice(0, 300),
        }, true);
      }
    }
  );

  server.tool(
    "get_phone_state",
    "唯讀：只讀取後端已快取的手機狀態，不要求手機即時回報、不敲門、不截圖、不寫活動紀錄。",
    { device_id: z.string().default(defaultDevice) },
    async ({ device_id = defaultDevice }) => {
      try {
        const response = await fetchBackend(
          `/api/device/state?device_id=${encodeURIComponent(device_id)}`,
          { method: "GET" }
        );
        const state = await response.json();
        return textResult({ ...state, read_only: true, source: "backend_cached_state" });
      } catch (error) {
        return textResult({
          ok: false,
          read_only: true,
          error: "cached_state_fetch_failed",
          detail: String(error?.message || error).slice(0, 300),
        }, true);
      }
    }
  );

  return server;
}
