<script setup lang="ts">
import { onBeforeUnmount } from "vue";
import { useConsoleStore } from "../useConsole";

const c = useConsoleStore();

// showToken must focus the box's input only once the box has actually been
// rendered (v-show applies on the next tick) — register the focus hook the
// store's auth layer calls. The element id is stable markup, not a Vue ref.
c.registerTokenFocus(() => {
  const input = document.getElementById("token");
  if (input instanceof HTMLInputElement) {
    input.focus();
  }
});
onBeforeUnmount(() => {
  c.registerTokenFocus(null);
});
</script>

<template>
  <header class="top">
    <h1>open-unifi controller</h1>
    <span class="sub" id="whoami">{{ c.whoami }}</span>
    <span class="spacer"></span>
    <div class="tokenbox" id="tokenbox" v-show="c.showTokenBox">
      <label for="token" class="sub">Admin token</label>
      <input
        type="password"
        id="token"
        v-model="c.tokenInput"
        placeholder="Bearer token"
        autocomplete="off"
        @keydown.enter="c.saveToken"
      >
      <button type="button" class="btn btn-small" id="tokenSave" @click="c.saveToken">Save</button>
    </div>
  </header>
</template>
