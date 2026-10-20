/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // 语义化表面色：随 [data-theme] 自适应（见 src/styles/globals.css）
        surface: {
          DEFAULT: "rgb(var(--surface) / <alpha-value>)",
          card: "rgb(var(--surface-card) / <alpha-value>)",
          hover: "rgb(var(--surface-hover) / <alpha-value>)",
        },
        accent: {
          DEFAULT: "rgb(var(--accent) / <alpha-value>)",
          hover: "rgb(var(--accent-hover) / <alpha-value>)",
        },
        // 自适应描边 / 玻璃层（浅色模式自动翻转为深色半透明）
        border: "rgb(var(--border) / 0.07)",
        "border-strong": "rgb(var(--border) / 0.14)",
        glass: "rgb(var(--glass) / 0.05)",
        "glass-strong": "rgb(var(--glass) / 0.10)",
        latency: {
          good: "#22c55e",
          medium: "#eab308",
          bad: "#ef4444",
        },
        ring: "#6366f1",
        // 灰阶文本随主题翻转：深色模式为浅灰，浅色模式为深板岩色
        gray: {
          100: "rgb(var(--gray-100) / <alpha-value>)",
          200: "rgb(var(--gray-200) / <alpha-value>)",
          300: "rgb(var(--gray-300) / <alpha-value>)",
          400: "rgb(var(--gray-400) / <alpha-value>)",
          500: "rgb(var(--gray-500) / <alpha-value>)",
          600: "rgb(var(--gray-600) / <alpha-value>)",
        },
      },
    },
  },
  plugins: [],
};
