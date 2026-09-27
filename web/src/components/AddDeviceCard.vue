<script setup lang="ts">
import { useConsoleStore } from "../useConsole";

const c = useConsoleStore();
</script>

<template>
  <section class="card" id="addSection">
    <h2>Add manually</h2>
    <p class="hint">Register a device MAC on the adopt whitelist (state: pending) even before it shows up on discovery.</p>
    <form class="rowform" id="addForm" @submit.prevent="c.addDevice">
      <input id="addMac" v-model="c.addMac" name="mac" placeholder="MAC, e.g. F0-9F-C2-84-8F-2A" required>
      <input id="addName" v-model="c.addName" name="name" placeholder="Optional name (e.g. office-ceiling)">
      <button type="submit" class="btn">Add device</button>
    </form>
    <span class="pill" id="addError" v-show="c.addError">{{ c.addError }}</span>
  </section>
</template>
