<script setup lang="ts">
import { computed } from "vue";
import ClientsPanel from "./ClientsPanel.vue";
import { useConsoleStore } from "../useConsole";
import type { DeviceRowState } from "../types";

const c = useConsoleStore();
const props = defineProps<{ row: DeviceRowState }>();

// The client expansion lives in a sibling row rendered as a second root of
// this fragment — open flag + fetched sessions come from the store, keyed
// by the device MAC.
const open = computed(() => c.openClients[props.row.mac]);
const clients = computed(() => c.clientData[props.row.mac]);
</script>

<template>
  <tr>
    <td class="mono">{{ row.mac }}</td>
    <td>{{ row.name }}</td>
    <td>{{ row.model }}</td>
    <td class="mono">{{ row.ip }}</td>
    <td><span class="badge" :class="row.stateClass">{{ row.stateLabel }}</span></td>
    <td v-if="row.adopted"><span class="badge live">live</span></td>
    <td v-else class="sub">&ndash;</td>
    <td v-if="row.adopted" class="led-cell">
      <input v-model="row.ledBright" name="led_bright" type="number" min="0" max="100" placeholder="100">
      <input v-model="row.ledColor" name="led_color" placeholder="#0000ff">
      <button type="button" class="btn-ghost btn-small" @click="c.saveLed(row)">Save</button>
    </td>
    <td v-else class="sub">&ndash;</td>
    <td v-if="row.adopted" class="country-cell">
      <input v-model="row.country" name="regulatory_country_code" type="number" min="0" max="999" class="num">
      <button type="button" class="btn-ghost btn-small" @click="c.saveCountry(row)">Save</button>
    </td>
    <td v-else class="sub">&ndash;</td>
    <td v-if="row.adopted" class="sshkeys-cell">
      <textarea v-model="row.keysText" name="ssh_public_keys" rows="3" placeholder="ssh-ed25519 AAAA… user@host"></textarea>
      <button type="button" class="btn-ghost btn-small" @click="c.saveKeys(row)">Save keys</button>
      <button type="button" class="btn-ghost btn-small" @click="c.clearKeys(row)">Clear keys</button>
    </td>
    <td v-else class="sub">&ndash;</td>
    <td v-if="row.adopted" class="ssh-cell">
      <span class="sub">{{ row.sshSet ? "password set" : "no password managed" }}</span>
      <input v-model="row.sshPwd" name="ssh_password" type="password" placeholder="new password" autocomplete="new-password">
      <button type="button" class="btn-ghost btn-small" @click="c.saveSsh(row)">Save</button>
      <button type="button" class="btn-ghost btn-small" @click="c.clearSsh(row)">Stop managing</button>
    </td>
    <td v-else class="sub">&ndash;</td>
    <td class="actions-cell">
      <button type="button" class="btn-ghost btn-small" @click="c.toggleClients(row)">{{ open ? "Hide clients" : "Clients" }}</button>&nbsp;
      <button type="button" class="btn-ghost btn-small" @click="c.forget(row)">Forget</button>
    </td>
  </tr>
  <ClientsPanel v-if="open && clients" :clients="clients" />
</template>
