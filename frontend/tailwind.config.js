/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        brand: {
          50: '#eef6ff',
          100: '#d9eaff',
          500: '#2f7af0',
          600: '#1e5fd1',
          700: '#174ba8',
        },
      },
    },
  },
  plugins: [],
}
