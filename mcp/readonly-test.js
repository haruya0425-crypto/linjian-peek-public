/**
 * 掌心窗 MCP：隔離限制模式（v2，新增可選通知）。
 *
 * - LINJIAN_MCP_READ_ONLY=true (or unset): only tools defined here are registered.
 * - LINJIAN_MCP_ALLOW_NOTIFICATION is OFF by default. Setting it to "true"
 *   adds exactly one writing tool: send_notification.
 * - Do NOT set LINJIAN_MCP_READ_ONLY=false: that enables legacy tool factories.
 * - OAuth is enforced by oauth-auth.js before MCP routes.
 * - This module never logs activity using the legacy MCP helpers.
 */
export const readOnlyEnabled = process.env.LINJIAN_MCP_READ_ONLY !== "false";
export const notificationEnabled = readOnlyEnabled && process.env.LINJIAN_MCP_ALLOW_NOTIFICATION === "true";

// Best-effort single-instance accidental-spam protection. A process restart resets it.
let lastNotificationAttemptAt = 0;
const NOTIFICATION_COOLDOWN_MS = 30_000;

function textResult(payload, isError = false) {
  return {
    isError,
    content: [{ type: "text", text: JSON.stringify(payload, null, 2) }],
  };
}

function limitedError(error) {
  return String(error?.message || error).slice(0, 300);
}

/** The main server injects its existing SDK types and authenticated backend fetch. */
export function makeReadOnlyServer({ McpServer, z, fetchBackend, defaultDevice }) {
  if (!readOnlyEnabled) {
    throw new Error("makeReadOnlyServer must not be used outside restricted mode");
  }
  const server = new McpServer({ name: "掌心窗（限制權限沙盒）", version: "0.3.9.0-ro2" });

  server.tool(
    "linjian_status",
    "查詢掌心窗後端 /health（唯讀）；不操作手機。此端點為公開健康檢查，不能單獨驗證手機 Token。",
    {},
    async () => {
      try {
        const response = await fetchBackend("/health", { method: "GET" });
        const health = await response.json();
        return textResult({
          ok: health?.ok === true,
          restricted_mode: true,
          read_only: !notificationEnabled,
          notification_allowed: notificationEnabled,
          backend_reachable: true,
          backend_healthy: health?.ok === true,
          service: String(health?.service || ""),
          version: String(health?.version || ""),
          token_verified_by_this_check: false,
        });
      } catch (error) {
        return textResult({
          ok: false,
          restricted_mode: true,
          read_only: !notificationEnabled,
          notification_allowed: notificationEnabled,
          backend_reachable: false,
          error: "backend_health_check_failed",
          detail: limitedError(error),
        }, true);
      }
    }
  );

  server.tool(
    "get_phone_state",
    "唯讀：取得後端已快取的手機狀態。不要求手機即時回報、不截圖、不送指令。",
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
          detail: limitedError(error),
        }, true);
      }
    }
  );

  // Explicit opt-in: notification ONLY. No arbitrary action, device ID, paths,
  // wallet operation, screenshot request, or general phone-control tool exposed.
  if (notificationEnabled) {
    server.tool(
      "send_notification",
      "在使用者授權下，僅向預設手機傳送一則系統通知。不能開啟其他 App、截圖、鎖定手機或操作錢包。",
      {
        title: z.string().trim().min(1).max(80).default("掌心窗提醒"),
        message: z.string().trim().min(1).max(400),
      },
      async ({ title = "掌心窗提醒", message }) => {
        // Validate again at runtime; don't rely on upstream JSON Schema alone.
        if (typeof title !== "string" || typeof message !== "string") {
          return textResult({ ok: false, error: "invalid_notification_text" }, true);
        }
        const safeTitle = title.trim();
        const safeMessage = message.trim();
        if (!safeTitle || safeTitle.length > 80 || !safeMessage || safeMessage.length > 400) {
          return textResult({ ok: false, error: "notification_text_out_of_bounds" }, true);
        }
        const now = Date.now();
        if (now - lastNotificationAttemptAt < NOTIFICATION_COOLDOWN_MS) {
          return textResult({ ok: false, error: "notification_cooldown", retry_after_seconds: Math.ceil((NOTIFICATION_COOLDOWN_MS - (now - lastNotificationAttemptAt)) / 1000) }, true);
        }
        lastNotificationAttemptAt = now;
        try {
          const response = await fetchBackend("/api/command", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              action: "send_notification",
              device_id: defaultDevice,
              payload: { title: safeTitle, message: safeMessage },
            }),
          });
          const queued = await response.json();
          const accepted = queued?.ok === true && queued?.command?.action === "send_notification";
          return textResult({
            ok: accepted,
            restricted_mode: true,
            action: "send_notification",
            queued: accepted,
            delivered: "unverified",
            command_id: typeof queued?.command?.id === "string" ? queued.command.id : null,
            note: "已排入指令佇列不代表手機已顯示通知；請在手機上確認。",
          }, !accepted);
        } catch (error) {
          return textResult({
            ok: false,
            restricted_mode: true,
            action: "send_notification",
            error: "notification_queue_failed",
            detail: limitedError(error),
          }, true);
        }
      }
    );
  }

  return server;
}
