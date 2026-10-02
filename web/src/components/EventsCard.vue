<script setup lang="ts">
import { EVENT_KINDS, dateTimeText, eventDescription, eventLabel } from "../clients";
import { useConsoleStore } from "../useConsole";

const c = useConsoleStore();
</script>

<template>
  <section class="card" id="eventsSection">
    <h2>Client events</h2>
    <p class="hint">
      WiFi client connects, disconnects and roams between APs, newest first &mdash; the same events as the official
      System Log. Client history is personal data, so it is opt-in.
    </p>
    <div v-if="c.eventsEnabled === false" class="empty" id="eventsOff">
      Client history is off. Start the controller with <code>--client-history</code> (or set
      <code>OPEN_UNIFI_CLIENT_HISTORY=true</code>; keep it for <code>--client-history-retention</code>, default 30d) to
      record and browse client events. Events are always written to the controller log.
    </div>
    <template v-else>
      <div class="filter-row">
        <input v-model="c.evSearch" type="search" placeholder="Search client, AP, SSID" aria-label="Search events" />
        <select v-model="c.evKey" aria-label="Event type" @change="c.onEventFilterChange()">
          <option value="">All client events</option>
          <option v-for="k in EVENT_KINDS" :key="k.key" :value="k.key">{{ k.label }}</option>
        </select>
        <select v-model="c.evRange" aria-label="Time range" @change="c.onEventFilterChange()">
          <option v-for="r in c.eventRanges" :key="r" :value="r">{{ r }}</option>
        </select>
      </div>
      <div class="scroll" tabindex="0" role="region" aria-label="Client events table">
        <table class="data-table" aria-label="Client events" id="eventRows">
          <thead><tr><th>Event</th><th>Description</th><th>Date/Time</th></tr></thead>
          <tbody>
            <template v-if="c.filteredEvents.length">
              <tr v-for="(ev, i) in c.filteredEvents" :key="ev.time + ':' + ev.client + ':' + ev.key + ':' + i">
                <td>{{ eventLabel(ev.key) }}</td>
                <td>{{ eventDescription(ev) }}</td>
                <td class="mono">{{ dateTimeText(ev.time) }}</td>
              </tr>
            </template>
            <tr v-else><td colspan="3" class="empty">no client events in this range</td></tr>
          </tbody>
        </table>
      </div>
    </template>
    <span class="pill" id="eventsError" v-show="c.eventsError">{{ c.eventsError }}</span>
  </section>
</template>
