// Console bootstrap: the global stylesheet (moved verbatim out of the old
// App.vue <style> block) is linked through this entry — Vite extracts it
// into the hashed /assets/*.css bundle. The 5s polling loop lives in the
// useConsole store (App's mounted hook), not here.
import "./styles.css";
import { createApp } from "vue";
import App from "./App.vue";

createApp(App).mount("#app");
