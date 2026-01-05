/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./templates/**/*.html",   // ✅ HTML 템플릿 폴더 전체
  ],
  theme: {
    extend: {
      zIndex: {
        100: "100",
        110: "110",
        119: "119",
        120: "120",
        130: "130",
      },
    },
  },
  plugins: [],
}
