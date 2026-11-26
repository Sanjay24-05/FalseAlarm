import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

export default defineConfig(({ mode }) => {
  // FALSE_ALARM_API_TOKEN, when the API requires one, is added by the dev proxy and never reaches the browser.
  const token = loadEnv(mode, ".", "FALSE_ALARM_").FALSE_ALARM_API_TOKEN?.trim();
  return {
    plugins: [react(), tailwindcss()],
    server: {
      port: 5173,
      strictPort: true,
      proxy: {
        "/api": {
          target: "http://127.0.0.1:8000",
          changeOrigin: true,
          headers: token ? { Authorization: `Bearer ${token}` } : undefined,
        },
      },
    },
  };
});
