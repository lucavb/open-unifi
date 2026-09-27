<script setup lang="ts">
import { provide } from "vue";
import AddDeviceCard from "./components/AddDeviceCard.vue";
import DevicesCard from "./components/DevicesCard.vue";
import PendingCard from "./components/PendingCard.vue";
import TokenGate from "./components/TokenGate.vue";
import WirelessCard from "./components/WirelessCard.vue";
import { CONSOLE_KEY, useConsole } from "./useConsole";

// The single composition root: exactly one store for the lifetime of the
// page, provided down to the section components.
const store = useConsole();
provide(CONSOLE_KEY, store);
</script>

<template>
  <div class="container">
    <TokenGate />
    <span class="pill" id="globalError" v-show="store.globalError">{{ store.globalError }}</span>

    <DevicesCard />
    <PendingCard />
    <AddDeviceCard />
    <WirelessCard />

    <footer>
      Endpoints: <a href="/api/v1/devices">/api/v1/devices</a> &middot;
      <a href="/api/v1/pending">/api/v1/pending</a> &middot;
      <span class="mono">/api/v1/devices/{mac}/wireless</span> &middot;
      <a href="/metrics">/metrics</a> &middot;
      <a href="/healthz">/healthz</a>
    </footer>
  </div>
</template>
