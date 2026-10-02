<script setup lang="ts">
import { apText, clientName, dateTimeText, intervalAp, sinceText, spanText } from "../clients";
import { useConsoleStore } from "../useConsole";

const c = useConsoleStore();
</script>

<template>
  <section class="card" id="clientsSection">
    <h2>Clients</h2>
    <p class="hint">
      Every WiFi client reported by your APs, with the AP it is on now (or was last seen on). Select a client to see
      which APs it has been assigned to over time; the history needs client history enabled
      (<code>--client-history</code> or <code>OPEN_UNIFI_CLIENT_HISTORY=true</code>).
    </p>
    <div class="filter-row">
      <input v-model="c.clientSearch" type="search" placeholder="Search name, MAC, AP, SSID" aria-label="Search clients" />
    </div>
    <div class="scroll" tabindex="0" role="region" aria-label="Clients table">
      <table class="data-table" aria-label="Clients" id="clientRows">
        <thead><tr><th>Client</th><th>State</th><th>AP</th><th>SSID</th><th>Channel</th><th>Connected</th><th>Last seen</th></tr></thead>
        <tbody>
          <template v-if="c.filteredClients.length">
            <template v-for="cl in c.filteredClients" :key="cl.mac">
              <tr class="client-line" :class="{ selected: c.selectedClient === cl.mac }" @click="c.selectClient(cl.mac)">
                <td>
                  <div>{{ clientName(cl.hostname, cl.mac) }}</div>
                  <div v-if="cl.hostname" class="mono sub">{{ cl.mac }}</div>
                </td>
                <td>
                  <span v-if="cl.connected" class="badge live">connected</span>
                  <span v-else class="badge state-unknown">disconnected</span>
                </td>
                <td>{{ apText(cl.ap_name, cl.ap) }}</td>
                <td>{{ cl.ssid || "\u2014" }}</td>
                <td>{{ cl.channel ? cl.channel + (cl.radio ? " (" + cl.radio + ")" : "") : "\u2014" }}</td>
                <td>{{ cl.connected ? sinceText(cl.since) : "\u2014" }}</td>
                <td class="mono">{{ cl.last_seen ? new Date(cl.last_seen * 1000).toLocaleTimeString() : "\u2014" }}</td>
              </tr>
              <tr v-if="c.selectedClient === cl.mac" class="clients-row">
                <td colspan="7">
                  <div v-if="!c.clientHistory" class="empty">loading history&hellip;</div>
                  <div v-else-if="!c.clientHistory.enabled" class="empty">
                    AP history is off. Start the controller with <code>--client-history</code> (or set
                    <code>OPEN_UNIFI_CLIENT_HISTORY=true</code>) to record which AP this client used over time.
                  </div>
                  <div v-else-if="!c.clientHistory.intervals.length" class="empty">no AP history recorded for this client yet</div>
                  <table v-else class="clients-table">
                    <thead><tr><th>AP</th><th>SSID</th><th>Channel</th><th>From</th><th>To</th><th>Duration</th></tr></thead>
                    <tbody>
                      <tr v-for="(iv, i) in [...c.clientHistory.intervals].reverse()" :key="i">
                        <td>{{ intervalAp(iv) }}</td>
                        <td>{{ iv.ssid || "\u2014" }}</td>
                        <td>{{ iv.channel || "\u2014" }}</td>
                        <td class="mono">{{ dateTimeText(iv.from) }}</td>
                        <td class="mono">{{ iv.to ? dateTimeText(iv.to) : "now" }}</td>
                        <td>{{ spanText(iv.from, iv.to) }}</td>
                      </tr>
                    </tbody>
                  </table>
                </td>
              </tr>
            </template>
          </template>
          <tr v-else><td colspan="7" class="empty">no clients recorded</td></tr>
        </tbody>
      </table>
    </div>
    <span class="pill" id="clientsError" v-show="c.clientsError">{{ c.clientsError }}</span>
  </section>
</template>
