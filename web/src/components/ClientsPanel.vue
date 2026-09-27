<script setup lang="ts">
import { useConsoleStore } from "../useConsole";
import type { ClientView } from "../types";

const c = useConsoleStore();
defineProps<{ clients: ClientView[] }>();
</script>

<template>
  <tr class="clients-row">
    <td colspan="11">
      <div v-if="!clients.length" class="empty">no client sessions recorded</div>
      <table v-else class="clients-table">
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
