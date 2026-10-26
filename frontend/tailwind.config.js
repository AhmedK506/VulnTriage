/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        primary: {
          50:  '#eff6ff',
          100: '#dbeafe',
          500: '#3b82f6',
          600: '#2563eb',
          700: '#1d4ed8',
          900: '#1e3a8a',
        },
        severity: {
          critical: '#dc2626',
          high:     '#ea580c',
          medium:   '#d97706',
          low:      '#16a34a',
          info:     '#6b7280',
        },
        classification: {
          confirmed:  '#16a34a',
          manual:     '#d97706',
          notconf:    '#dc2626',
        },
      },
    },
  },
  plugins: [],
}
