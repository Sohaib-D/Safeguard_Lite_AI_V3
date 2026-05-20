/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  eslint: {
    ignoreDuringBuilds: true,
  },
  typescript: {
    // Allow production builds even if there are type errors
    ignoreBuildErrors: true,
  },
};

export default nextConfig;
