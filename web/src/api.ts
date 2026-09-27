// Typed fetch wrapper for the admin API.
//
// - Attaches the Bearer token from sessionStorage (key "ou_token").
// - 401 is handled centrally here (the auth flow surfaces it, not the data
//   pills): the token is cleared and the console is parked on the token box
//   via the onUnauthorized hook (wired by useAuth) — so the request that
//   401'd also installs the zero-request guard state.
// - Non-2xx bodies carry the user-facing error text when parseable
//   ({ "error": "..." }); otherwise a generic "HTTP <status>" error.

/** Registered by useAuth (called from the 401 path; no component involved). */
let onUnauthorized: (() => void) | null = null;

/** useAuth wires the park transition (needToken + showToken) here. */
export function setUnauthorizedHandler(fn: () => void): void {
  onUnauthorized = fn;
}

export interface RequestOptions {
  method?: string;
  /** JSON-serialized when present (adds Content-Type: application/json). */
  body?: unknown;
}

/** e instanceof Error check for the "unauthorized (401)" marker (401
 *  suppression: callers skip their error pills when is401(e) — the auth
 *  flow already surfaced it). */
export function is401(e: unknown): boolean {
  return e instanceof Error && e.message.includes("401");
}

async function readJson(res: Response): Promise<unknown> {
  try {
    return await res.json();
  } catch {
    throw new Error("HTTP " + res.status + " (unparseable body)");
  }
}

/** The error a non-2xx response turns into: the body's "error" string when
 *  present, else "HTTP <status>" (unparseable bodies hit readJson's error).
 *  Never resolves — it exists to be awaited-and-thrown. */
async function errorFrom(res: Response): Promise<never> {
  const body = await readJson(res);
  if (body !== null && typeof body === "object" && "error" in body) {
    const err = (body as { error: unknown }).error;
    if (typeof err === "string") {
      throw new Error(err);
    }
  }
  throw new Error("HTTP " + res.status);
}

function rawFetch(path: string, opts: RequestOptions): Promise<Response> {
  const headers: Record<string, string> = {};
  const token = window.sessionStorage.getItem("ou_token");
  if (token) {
    headers["Authorization"] = "Bearer " + token;
  }
  const init: RequestInit = { method: opts.method ?? "GET", headers };
  if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.body);
  }
  return window.fetch(path, init).then((res) => {
    if (res.status === 401) {
      window.sessionStorage.removeItem("ou_token");
      if (onUnauthorized !== null) {
        onUnauthorized();
      }
      throw new Error("unauthorized (401)");
    }
    return res;
  });
}

/** A request whose 2xx body is JSON-decoded into T (the GET endpoints). */
export async function api<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const res = await rawFetch(path, opts);
  if (!res.ok) {
    throw await errorFrom(res);
  }
  const body = await readJson(res);
  if (body !== null && typeof body === "object" && "error" in body) {
    const err = (body as { error: unknown }).error;
    if (typeof err === "string") {
      throw new Error(err);
    }
  }
  // The wire shape is declared at the call site (T); the JSON is the data.
  return body as T;
}

/** A status-only request (POST/PATCH/DELETE): the 2xx body is intentionally
 *  NOT parsed — the old console consumed these without getJSON too. */
export async function request(path: string, opts: RequestOptions = {}): Promise<void> {
  const res = await rawFetch(path, opts);
  if (!res.ok) {
    throw await errorFrom(res);
  }
}
