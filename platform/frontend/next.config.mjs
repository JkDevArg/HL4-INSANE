/** @type {import('next').NextConfig} */
const nextConfig = {
  // Salida standalone para una imagen Docker mas ligera (next start).
  output: 'standalone',
  reactStrictMode: true,
};

export default nextConfig;
