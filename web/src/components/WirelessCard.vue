<script setup lang="ts">
import WlanRow from "./WlanRow.vue";
import { useConsoleStore } from "../useConsole";

const c = useConsoleStore();
</script>

<template>
  <section class="card" id="wlSection">
    <h2>Wireless / VLAN config</h2>
    <p class="hint">
      Per device: choose a MAC, then <span class="mono">Save</span> PUTs all rows to
      <span class="mono">/api/v1/devices/{mac}/wireless</span>. Passphrase &ge; 8 chars for wpa-p,
      wpa3-p and wpa2-wpa3; optional for wpa-eap (&ge; 8 when set); empty for &ldquo;open&rdquo;; VLAN
      1&ndash;4094. wpa-eap needs a
      RADIUS profile: up to 4 auth servers (&ldquo;ip&rdquo; or &ldquo;ip:port&rdquo;), a shared secret,
      and a dynamic-VLAN mode.
    </p>
    <label class="rowform" for="wlDevice">Device MAC</label>
    <select id="wlDevice" aria-label="Device for wireless config" v-model="c.wlDevice" @change="c.onWlDeviceChange($event)">
      <option value="">— select device —</option>
      <option v-for="d in c.devices" :key="d.mac" :value="d.mac">{{ d.mac + (d.name ? " (" + d.name + ")" : "") }}</option>
    </select>
    <p class="hint" id="wlPickHint" v-show="!c.wlMac">Register or adopt a device above to edit WLANs.</p>
    <div class="scroll" tabindex="0" role="region" aria-label="Wireless table — scroll for more columns">
      <table class="data-table" aria-label="Wireless networks" id="wlTable">
        <thead><tr><th>SSID</th><th>Name</th><th>Security</th><th>Passphrase</th><th>VLAN</th><th>RADIUS</th><th>On</th><th></th></tr></thead>
        <tbody id="wlRows">
          <WlanRow v-for="(row, i) in c.wlans" :key="i" :row="row" :index="i" />
        </tbody>
        <tfoot><tr><td colspan="8"><button type="button" class="btn-ghost btn-small" id="wlAddRow" :disabled="!c.wlMac" @click="c.addWlanRow">+ Row</button>&nbsp; <button type="button" class="btn btn-small" id="wlSave" :disabled="!c.wlMac" @click="c.saveWlans">Save</button></td></tr></tfoot>
      </table>
    </div>
    <span class="pill" id="wlError" v-show="c.wlError">{{ c.wlError }}</span>
  </section>
</template>
