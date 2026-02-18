/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        stratus: {
          bg: '#0F172A',
          surface: '#1E293B',
          border: '#334155',
          text: '#E2E8F0',
          muted: '#94A3B8',
          accent: '#3B82F6',
          success: '#10B981',
          warning: '#F59E0B',
          danger: '#EF4444',
          purple: '#8B5CF6',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
    },
  },
  plugins: [],
}
