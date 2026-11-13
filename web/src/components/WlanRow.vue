<script setup lang="ts">
import { useConsoleStore } from "../useConsole";
import type { WlanRowState } from "../types";

const c = useConsoleStore();
defineProps<{ row: WlanRowState; index: number }>();
</script>

<template>
  <tr>
    <td><input v-model="row.ssid" name="ssid" :aria-label="'SSID, row ' + (index + 1)" @input="c.markWlanDraftChanged"></td>
    <td><input v-model="row.name" name="name" :aria-label="'Name, row ' + (index + 1)" @input="c.markWlanDraftChanged"></td>
    <td>
      <select v-model="row.security" name="security" :aria-label="'Security, row ' + (index + 1)" @change="c.markWlanDraftChanged">
        <option v-for="s in c.securitys" :key="s" :value="s">{{ s }}</option>
      </select>
    </td>
    <td><input v-model="row.passphrase" name="passphrase" type="password" :aria-label="'Passphrase, row ' + (index + 1)" @input="c.markWlanDraftChanged"></td>
    <td><input v-model="row.vlan" name="vlan" class="num" type="number" min="1" max="4094" step="1" :aria-label="'VLAN, row ' + (index + 1)" @input="c.markWlanDraftChanged"></td>
    <td class="radius-cell">
      <input v-model="row.radiusServers" name="radius_servers" placeholder="10.0.0.5:1812, 10.0.0.6" :aria-label="'RADIUS servers, row ' + (index + 1)" :disabled="row.security !== 'wpa-eap'" @input="c.markWlanDraftChanged">
      <input v-model="row.radiusSecret" name="radius_secret" type="password" placeholder="shared secret" :aria-label="'RADIUS shared secret, row ' + (index + 1)" :disabled="row.security !== 'wpa-eap'" @input="c.markWlanDraftChanged">
      <select v-model="row.radiusVlanMode" name="radius_vlan_mode" :aria-label="'Dynamic VLAN mode, row ' + (index + 1)" :disabled="row.security !== 'wpa-eap'" @change="c.markWlanDraftChanged">
        <option v-for="m in c.radiusModes" :key="m" :value="m">{{ m === "" ? "dynamic vlan: off" : m }}</option>
      </select>
    </td>
    <td><input v-model="row.enabled" name="enabled" type="checkbox" :aria-label="'Enable WLAN, row ' + (index + 1)" @change="c.markWlanDraftChanged"></td>
    <td class="actions-cell"><button type="button" class="btn-ghost btn-small" :aria-label="'Remove WLAN row ' + (index + 1) + (row.ssid ? ': ' + row.ssid : '')" @click="c.removeWlan(index)">&times;</button></td>
  </tr>
</template>
