import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        ink: "#111827",
        panel: "#f8fafc",
        line: "#d9e2ec",
        brand: "#0f766e",
        risk: {
          low: "#2563eb",
          medium: "#d97706",
          high: "#dc2626",
          critical: "#7f1d1d"
        }
      }
    }
  },
  plugins: []
};

export default config;


