// The auth gate: token storage (sessionStorage "ou_token"), the token-box
// prompt, and the 401 park transition. No network calls live here — the
// park is installed by api.ts (onUnauthorized, any endpoint) and by the
// whoami probe in useConsole.refreshAll (auth configured without a token).
// useConsole is the single composition root, so exactly one useAuth exists
// per page and setUnauthorizedHandler is wired during its setup.
import { nextTick, ref } from "vue";
import { setUnauthorizedHandler } from "./api";

const TOKEN_KEY = "ou_token";

export function useAuth() {
  const whoami = ref("loading\u2026");
  const showTokenBox = ref(false);
  const tokenInput = ref("");
  /** True once auth is known to be required and the console is parked on
   *  the token box. Together with the saved token it feeds the
   *  zero-request guard (halted). */
  const needToken = ref(false);

  // TokenGate registers the focus hook: showToken must focus the box's
  // input only once the box has actually been rendered (v-show applies on
  // the next tick, so an immediate focus would hit a hidden element — the
  // same reason the old console focused right after un-hiding the box).
  let focusTokenInput: (() => void) | null = null;
  function registerTokenFocus(fn: (() => void) | null): void {
    focusTokenInput = fn;
  }

  function showToken(msg: string): void {
    showTokenBox.value = true;
    if (msg) {
      whoami.value = msg;
    }
    nextTick(() => {
      if (focusTokenInput !== null) {
        focusTokenInput();
      }
    });
  }

  // Zero-request guard: parked (needToken) and no token saved. An empty
  // saved token counts as absent — the falsy check matches the old
  // console's sessionStorage reads exactly.
  function halted(): boolean {
    return needToken.value && !window.sessionStorage.getItem(TOKEN_KEY);
  }

  // Any 401 (any endpoint) parks the console: the token is already cleared
  // by api.ts when this runs.
  setUnauthorizedHandler(() => {
    needToken.value = true;
    showToken("401 unauthorized \u2014 enter the admin token");
  });

  return { whoami, showTokenBox, tokenInput, needToken, registerTokenFocus, showToken, halted };
}
