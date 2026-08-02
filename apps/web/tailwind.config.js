/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Status colours are always paired with a text label in the UI.
        // §9.3 requires WCAG 2.1 AA and "no colour-only status encoding" —
        // these exist to reinforce a label, never to replace one.
        status: {
          active: '#16a34a',
          warned: '#ca8a04',
          restricted: '#ea580c',
          muted: '#dc2626',
          banned: '#b91c1c',
          deleted: '#57534e',
        },
      },
    },
  },
  plugins: [],
};
