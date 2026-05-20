import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        bg: {
          primary: "#0a0f1e",
          secondary: "#111827",
          tertiary: "#1e293b",
        },
        accent: {
          cyan: "#38bdf8",
          violet: "#a78bfa",
          emerald: "#34d399",
          rose: "#fb7185",
          amber: "#fbbf24",
        },
        text: {
          primary: "#f8fafc",
          secondary: "#94a3b8",
        },
        border: {
          subtle: "rgba(148,163,184,0.12)",
        },
      },
    },
  },
  plugins: [],
};
export default config;
