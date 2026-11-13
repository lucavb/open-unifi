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
const TOKEN_KEY = "ou_token";
let authGeneration = 0;
export const REQUEST_TIMEOUT_MS = 15_000;

/** useAuth wires the park transition (needToken + showToken) here. */
export function setUnauthorizedHandler(fn: () => void): void {
  onUnauthorized = fn;
}

/** Store a replacement token and invalidate 401 responses from older requests. */
export function setAuthToken(token: string): void {
  window.sessionStorage.setItem(TOKEN_KEY, token);
  authGeneration += 1;
}

export interface RequestOptions {
  method?: string;
  /** JSON-serialized when present (adds Content-Type: application/json). */
  body?: unknown;
}

/** HTTP failure with its status kept separate from presentation text. */
export class ApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

/** A bounded request failure, distinct from HTTP/auth failures. */
export class ApiTimeoutError extends Error {
  constructor(path: string) {
    super("Request timed out after " + REQUEST_TIMEOUT_MS + "ms: " + path);
    this.name = "ApiTimeoutError";
  }
}

/** The auth flow already surfaces 401s in the token gate. */
export function is401(e: unknown): boolean {
  return e instanceof ApiError && e.status === 401;
}

async function readJson(res: Response): Promise<unknown> {
  try {
    return await res.json();
  } catch {
    throw new ApiError("HTTP " + res.status + " (unparseable body)", res.status);
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
      throw new ApiError(err, res.status);
    }
  }
  throw new ApiError("HTTP " + res.status, res.status);
}

function rawFetch(path: string, opts: RequestOptions, signal: AbortSignal): Promise<Response> {
  const headers: Record<string, string> = {};
  const token = window.sessionStorage.getItem(TOKEN_KEY);
  const requestAuthGeneration = authGeneration;
  if (token) {
    headers["Authorization"] = "Bearer " + token;
  }
  const init: RequestInit = { method: opts.method ?? "GET", headers };
  if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.body);
  }
  init.signal = signal;
  return window.fetch(path, init).then((res) => {
    // A fetch implementation may ignore AbortSignal and settle after the
    // request deadline. Such a late response must not trigger auth effects.
    if (signal.aborted) {
      throw new ApiTimeoutError(path);
    }
    if (res.status === 401) {
      // A delayed failure from a request made with an older credential must
      // not erase a replacement token or park an already reauthenticated UI.
      if (
        authGeneration === requestAuthGeneration &&
        window.sessionStorage.getItem(TOKEN_KEY) === token
      ) {
        window.sessionStorage.removeItem(TOKEN_KEY);
        authGeneration += 1;
        if (onUnauthorized !== null) {
          onUnauthorized();
        }
      }
      throw new ApiError("unauthorized (401)", 401);
    }
    return res;
  });
}

/** Bound both the network wait and all response processing to one deadline. */
function withRequestTimeout<T>(path: string, operation: (signal: AbortSignal) => Promise<T>): Promise<T> {
  const controller = new AbortController();
  let timeout: number | undefined;
  const deadline = new Promise<never>((_resolve, reject) => {
    timeout = window.setTimeout(() => {
      // Reject first so an abort-aware fetch/body cannot win the race with an
      // AbortError and disguise the timeout as a different failure.
      reject(new ApiTimeoutError(path));
      controller.abort();
    }, REQUEST_TIMEOUT_MS);
  });
  return Promise.race([operation(controller.signal), deadline]).finally(() => {
    if (timeout !== undefined) {
      window.clearTimeout(timeout);
    }
  });
}

/** A request whose 2xx body is JSON-decoded into T (the GET endpoints). */
export function api<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  return withRequestTimeout(path, async (signal) => {
    const res = await rawFetch(path, opts, signal);
    if (!res.ok) {
      throw await errorFrom(res);
    }
    const body = await readJson(res);
    if (body !== null && typeof body === "object" && "error" in body) {
      const err = (body as { error: unknown }).error;
      if (typeof err === "string") {
        throw new ApiError(err, res.status);
      }
    }
    // The wire shape is declared at the call site (T); the JSON is the data.
    return body as T;
  });
}

/** A status-only request (POST/PATCH/DELETE): the 2xx body is intentionally
 *  NOT parsed — the old console consumed these without getJSON too. */
export function request(path: string, opts: RequestOptions = {}): Promise<void> {
  return withRequestTimeout(path, async (signal) => {
    const res = await rawFetch(path, opts, signal);
    if (!res.ok) {
      throw await errorFrom(res);
    }
  });
}
