import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

// The console is embedded into the controller binary: build output
// lands in internal/adminapi/static/dist (never committed — built by
// the CI web job, the Docker console stage, or make update-frontend)
// and is go:embed'ed into the single-binary deploy.
// base "/" plus Vite's default assetsDir ("assets") emit /assets/<hashed>.js|css,
// matching the Go mux route (GET /assets/) that serves the bundles.
export default defineConfig({
  plugins: [vue()],
  base: "/",
  build: {
    outDir: "../internal/adminapi/static/dist",
    emptyOutDir: true,
    sourcemap: false
  }
});
