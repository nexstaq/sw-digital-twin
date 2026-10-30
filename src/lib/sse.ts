/**
 * Server-sent events over fetch. EventSource cannot carry the BotID token (BotID patches fetch/XHR), cannot send headers, and hides
 * the reason for a non-200. This reads the same `data: …` frames and surfaces error replies too.
 */

/** Splits a buffer into complete `data:` payloads and the unfinished remainder. Pure, so it is easy to test. */
export function parseSse(buffer: string): { events: string[]; rest: string } {
  const frames = buffer.replace(/\r\n/g, "\n").split("\n\n");
  const rest = frames.pop() ?? "";
  const events: string[] = [];
  for (const f of frames) {
    const data = f.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).replace(/^ /, "")).join("\n");
    if (data) events.push(data);
  }
  return { events, rest };
}

/** Resolves with the HTTP status when the stream ends. Throws only on a network failure or abort. */
export async function streamSse(url: string, onData: (data: string) => void, signal: AbortSignal): Promise<number> {
  const res = await fetch(url, { headers: { accept: "text/event-stream" }, signal, cache: "no-store" });
  if (!res.body) return res.status;
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    const { events, rest } = parseSse(buf);
    buf = rest;
    for (const e of events) onData(e);
  }
  return res.status;
}
