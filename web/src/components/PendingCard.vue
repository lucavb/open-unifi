<script setup lang="ts">
import { useConsoleStore } from "../useConsole";

const c = useConsoleStore();
</script>

<template>
  <section class="card" id="pendingSection">
    <h2>Adopt candidates</h2>
    <p class="hint">Devices heard on the discovery channel but not yet adopted.</p>
    <div id="pendingRows">
      <div v-if="!c.pending.length" class="empty">no candidates on the discovery channel</div>
      <table v-else>
        <tbody>
          <tr v-for="(p, i) in c.pending" :key="p.mac + ':' + i">
            <td class="mono">{{ p.mac }}</td>
            <td>{{ p.name || "" }}</td>
            <td>{{ p.source || "" }}</td>
            <td class="actions-cell"><button type="button" class="btn btn-small" @click="c.adopt(p)">Adopt</button></td>
          </tr>
        </tbody>
      </table>
    </div>
    <span class="pill" id="pendingError" v-show="c.pendingError">{{ c.pendingError }}</span>
  </section>
</template>
