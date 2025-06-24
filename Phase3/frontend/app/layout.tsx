import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'USAC AV',
  description: 'A simple AV system for USAC',
  generator: 'Next.js',
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
