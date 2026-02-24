export async function validateDeepgram(apiKey?: string): Promise<{ ok: boolean; detail: string }> {
  if (!apiKey) {
    return { ok: false, detail: "missing api key" };
  }
  return { ok: true, detail: "configured" };
}
