<script setup lang="ts">
import DeviceRow from "./DeviceRow.vue";
import { useConsoleStore } from "../useConsole";

const c = useConsoleStore();
</script>

<template>
  <section class="card" id="devSection">
    <h2>Devices</h2>
    <p class="hint">Polled every 5&nbsp;s. State: pending &rarr; adopting &rarr; adopted (green &ldquo;live&rdquo; badge) &rarr; lost. &ldquo;Clients&rdquo; expands a device's client sessions (connected state and last seen, from full informs). LED bar (adopted only): brightness 0&ndash;100 (empty&nbsp;=&nbsp;keep), color verbatim, e.g. #ff8c00 (empty&nbsp;=&nbsp;default blue). Regulatory country (adopted only): ISO 3166-1 numeric code; <code>0</code> clears override (render default 840). SSH keys: one authorized_keys line per row; Save replaces the managed list, Clear sends <code>[]</code>. SSH password: type a new password and Save (empty&nbsp;=&nbsp;keep), or Stop managing to stop pushing it.</p>
    <div class="scroll" tabindex="0" role="region" aria-label="Devices table — scroll for more columns">
      <table class="data-table" aria-label="Devices" id="devTable">
        <thead><tr><th>MAC</th><th>Name</th><th>Model</th><th>IP</th><th>State</th><th>Power</th><th>LED bar</th><th>Country</th><th>SSH keys</th><th>SSH password</th><th></th></tr></thead>
        <tbody id="devRows">
          <template v-if="c.devices.length">
            <DeviceRow v-for="row in c.devices" :key="row.mac" :row="row" />
          </template>
          <tr v-else><td colspan="11" class="empty">no devices registered</td></tr>
        </tbody>
      </table>
    </div>
    <span class="pill" id="devError" v-show="c.devError">{{ c.devError }}</span>
  </section>
</template>
