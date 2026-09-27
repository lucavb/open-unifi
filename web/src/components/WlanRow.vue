<script setup lang="ts">
import { useConsoleStore } from "../useConsole";
import type { WlanRowState } from "../types";

const c = useConsoleStore();
defineProps<{ row: WlanRowState; index: number }>();
</script>

<template>
  <tr>
    <td><input v-model="row.ssid" name="ssid"></td>
    <td><input v-model="row.name" name="name"></td>
    <td>
      <select v-model="row.security" name="security">
        <option v-for="s in c.securitys" :key="s" :value="s">{{ s }}</option>
      </select>
    </td>
    <td><input v-model="row.passphrase" name="passphrase" type="password"></td>
    <td><input v-model="row.vlan" name="vlan" class="num" type="number" min="1" max="4094"></td>
    <td class="radius-cell">
      <input v-model="row.radiusServers" name="radius_servers" placeholder="10.0.0.5:1812, 10.0.0.6" :disabled="row.security !== 'wpa-eap'">
      <input v-model="row.radiusSecret" name="radius_secret" type="password" placeholder="shared secret" :disabled="row.security !== 'wpa-eap'">
      <select v-model="row.radiusVlanMode" name="radius_vlan_mode" :disabled="row.security !== 'wpa-eap'">
        <option v-for="m in c.radiusModes" :key="m" :value="m">{{ m === "" ? "dynamic vlan: off" : m }}</option>
      </select>
    </td>
    <td><input v-model="row.enabled" name="enabled" type="checkbox"></td>
    <td class="actions-cell"><button type="button" class="btn-ghost btn-small" @click="c.removeWlan(index)">&times;</button></td>
  </tr>
</template>
