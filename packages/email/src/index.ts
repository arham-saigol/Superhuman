export interface AgentmailConfig {
  apiKey: string;
  baseUrl?: string;
}

export async function validateAgentmail(config: AgentmailConfig): Promise<{ ok: boolean; detail: string }> {
  if (!config.apiKey) {
    return { ok: false, detail: "missing api key" };
  }
  return { ok: true, detail: "configured" };
}
