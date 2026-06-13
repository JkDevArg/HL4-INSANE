import type { Config } from 'tailwindcss';

// Paleta hacker/HackTheBox: negro profundo + verde-neon + cian de acento.
const config: Config = {
  content: ['./src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: {
          DEFAULT: '#0a0f0d', // negro verdoso de fondo
          panel: '#0f1614', // paneles/cards
          elevated: '#131c18', // hover/elevados
        },
        neon: {
          DEFAULT: '#39ff14', // verde-neon principal
          dim: '#2bd40f',
          cyan: '#00e5ff', // cian de acento
        },
        line: '#1c2a24', // bordes sutiles
        muted: '#7a8c84', // texto secundario
        danger: '#ff3b3b',
        warn: '#ffb020',
      },
      fontFamily: {
        mono: ['var(--font-mono)', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
        sans: ['var(--font-sans)', 'ui-sans-serif', 'system-ui', 'sans-serif'],
      },
      boxShadow: {
        neon: '0 0 0 1px rgba(57,255,20,0.25), 0 0 18px rgba(57,255,20,0.10)',
        'neon-cyan': '0 0 0 1px rgba(0,229,255,0.25), 0 0 18px rgba(0,229,255,0.10)',
      },
      keyframes: {
        pulseNeon: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.55' },
        },
      },
      animation: {
        pulseNeon: 'pulseNeon 1.6s ease-in-out infinite',
      },
    },
  },
  plugins: [],
};

export default config;
