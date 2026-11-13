<script setup lang="ts">
import { useConsoleStore } from "../useConsole";
import type { ClientView } from "../types";

const c = useConsoleStore();
defineProps<{ clients: ClientView[]; hasData: boolean; loading: boolean; error: string; mac: string }>();
</script>

<template>
  <tr class="clients-row">
    <td colspan="11">
      <div v-if="error" class="empty" role="alert">Could not load client sessions: {{ error }} <button type="button" class="btn-ghost btn-small" @click="c.refreshDeviceClients(mac)">Try again</button></div>
      <div v-if="loading && !hasData" class="empty" role="status">Loading client sessions&hellip;</div>
      <div v-else-if="hasData && !clients.length" class="empty">no client sessions recorded</div>
      <table v-if="hasData && clients.length" class="clients-table">
        <thead><tr><th>Client</th><th>State</th><th>Last seen</th></tr></thead>
        <tbody>
          <tr v-for="cl in clients" :key="cl.mac">
            <td class="mono">{{ cl.mac }}</td>
            <td>
              <span v-if="cl.connected" class="badge live">connected</span>
              <span v-else class="badge state-unknown">disconnected</span>
            </td>
            <td class="mono">{{ c.lastSeenText(cl.last_seen) }}</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</template>
