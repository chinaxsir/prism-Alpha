import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import path from "path";

export default defineConfig(({ command }) => ({
  plugins: [react()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "./src") },
  },
  clearScreen: false,
  // 生产包加固与极速冷启动：关闭 sourcemap、剥离 console/debugger/版权注释、
  // 纯哈希 chunk 命名（隐藏业务模块名）、按依赖拆包缩小首屏 JS 解析体积
  esbuild:
    command === "build"
      ? {
          drop: ["console", "debugger"],
          legalComments: "none",
        }
      : undefined,
  build: {
    target: "es2020",
    sourcemap: false,
    minify: "esbuild",
    cssCodeSplit: true,
    reportCompressedSize: false,
    rollupOptions: {
      output: {
        entryFileNames: "assets/[hash].js",
        chunkFileNames: "assets/[hash].js",
        assetFileNames: "assets/[hash][extname]",
        manualChunks: {
          v0: ["react", "react-dom", "react-router-dom"],
          v1: ["zustand", "lucide-react"],
        },
      },
    },
  },
  server: {
    port: 1420,
    strictPort: true,
    host: process.env.TAURI_DEV_HOST || false,
    hmr: process.env.TAURI_DEV_HOST
      ? { protocol: "ws", host: process.env.TAURI_DEV_HOST, port: 1421 }
      : undefined,
    watch: { ignored: ["**/src-tauri/**"] },
  },
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
    css: false,
  },
}));
