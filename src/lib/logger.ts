import { getConfig } from "./config";

/**
 * Minimal structured JSON logger. Any field whose key looks sensitive is
 * redacted, so passwords, hashes, tokens and secrets never reach the logs.
 */

type Level = "debug" | "info" | "warn" | "error";
const ORDER: Record<Level | "silent", number> = { debug: 10, info: 20, warn: 30, error: 40, silent: 100 };

const SENSITIVE_KEY = /pass|secret|token|authorization|hash|cookie|api[-_]?key|signature|credential/i;

export function redact(value: unknown, depth = 0): unknown {
  if (depth > 5) return "[truncated]";
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
  if (value instanceof Error) return { name: value.name, message: value.message };
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = SENSITIVE_KEY.test(k) ? "[redacted]" : redact(v, depth + 1);
    }
    return out;
  }
  return value;
}

function currentLevel(): Level | "silent" {
  try {
    return getConfig().logLevel;
  } catch {
    return "info";
  }
}

function write(level: Level, msg: string, fields?: Record<string, unknown>) {
  if (ORDER[level] < ORDER[currentLevel()]) return;
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    level,
    msg,
    ...(fields ? (redact(fields) as Record<string, unknown>) : {}),
  });
  if (level === "error" || level === "warn") console.error(line);
  else console.log(line);
}

export const logger = {
  debug: (msg: string, fields?: Record<string, unknown>) => write("debug", msg, fields),
  info: (msg: string, fields?: Record<string, unknown>) => write("info", msg, fields),
  warn: (msg: string, fields?: Record<string, unknown>) => write("warn", msg, fields),
  error: (msg: string, fields?: Record<string, unknown>) => write("error", msg, fields),
};
