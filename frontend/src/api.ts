const API_BASE_URL =
  "http://127.0.0.1:8000";


export interface SecurityAlert {
  alert_id: string;

  alert_name: string;

  severity:
    | "low"
    | "medium"
    | "high"
    | "critical";

  source: string;

  source_ip?: string;

  username?: string;

  hostname?: string;

  failed_attempts?: number;

  time_window_minutes?: number;

  description?: string;

  process_name?: string;

  command_line?: string;
}


export async function getBackendHealth() {
  const response = await fetch(
    `${API_BASE_URL}/health`
  );

  if (!response.ok) {
    throw new Error(
      "Backend health check failed"
    );
  }

  return response.json();
}


export async function getRiskScore(
  alert: SecurityAlert
) {
  const response = await fetch(
    `${API_BASE_URL}/risk/score`,
    {
      method: "POST",

      headers: {
        "Content-Type":
          "application/json",
      },

      body: JSON.stringify(alert),
    }
  );

  if (!response.ok) {
    throw new Error(
      "Risk analysis failed"
    );
  }

  return response.json();
}