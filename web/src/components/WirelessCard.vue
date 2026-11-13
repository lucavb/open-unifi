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
      <option v-for="d in c.devices" :key="d.mac" :value="d.mac">{{ d.mac + (d.name ? " (" + d.name + ")" : "") + (c.wlUnavailable && c.wlMac === d.mac ? " (no longer managed)" : "") }}</option>
      <option v-for="mac in c.wlUnavailableDrafts" :key="'unavailable-' + mac" :value="mac">{{ mac }} (no longer managed)</option>
    </select>
    <p class="hint" id="wlPickHint" v-show="!c.wlMac">Register or adopt a device above to edit WLANs.</p>
    <div v-if="c.wlMac" class="wireless-status" aria-live="polite">
      <span v-if="c.wlUnavailable" class="sub">This device is no longer managed. Its draft is kept here, but it cannot be saved.</span>
      <span v-else-if="c.wlLoading" class="sub">Loading wireless settings…</span>
      <span v-else-if="c.wlSaving" class="sub">Saving wireless settings…</span>
      <span v-else-if="c.wlDirty" class="sub">Unsaved changes. Switching devices keeps this draft.</span>
      <span v-else-if="c.wlMac" class="sub">No unsaved changes.</span>
      <button v-if="c.wlDirty" id="wlDiscard" type="button" class="btn-ghost btn-small" :disabled="c.wlSaving" @click="c.discardWlanChanges">Discard changes</button>
    </div>
    <div v-if="c.wlConflict" class="wireless-conflict" role="alert">
      The server settings changed while you were editing. Your draft is safe. Reload the server version or explicitly save your draft over it.
      <div class="wireless-actions">
        <button type="button" class="btn-ghost btn-small" :disabled="c.wlSaving" @click="c.reloadWirelessVersion">Reload server version</button>
        <button id="wlSaveAnyway" type="button" class="btn btn-small" :disabled="!c.wlCanOverwrite" @click="() => c.saveWlans(true)">Save draft anyway</button>
      </div>
    </div>
    <div class="scroll" tabindex="0" role="region" aria-label="Wireless table — scroll for more columns">
      <table class="data-table" aria-label="Wireless networks" id="wlTable">
        <thead><tr><th scope="col">SSID</th><th scope="col">Name</th><th scope="col">Security</th><th scope="col">Passphrase</th><th scope="col">VLAN</th><th scope="col">RADIUS</th><th scope="col">On</th><th scope="col">Actions</th></tr></thead>
        <tbody id="wlRows">
          <WlanRow v-for="(row, i) in c.wlans" :key="row.clientId" :row="row" :index="i" />
        </tbody>
        <tfoot><tr><td colspan="8"><button type="button" class="btn-ghost btn-small" id="wlAddRow" :disabled="!c.wlMac || c.wlUnavailable" @click="c.addWlanRow">+ Row</button>&nbsp; <button type="button" class="btn btn-small" id="wlSave" :disabled="!c.wlCanSave" @click="() => c.saveWlans()">Save</button></td></tr></tfoot>
      </table>
    </div>
    <span class="pill" id="wlError" role="alert" v-show="c.wlError">{{ c.wlError }} <button v-if="c.wlLoadError && !c.wlUnavailable" type="button" class="btn-ghost btn-small" :disabled="c.wlLoading" @click="c.retryWirelessLoad">Try again</button></span>
  </section>
</template>
