import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  metadataBase: new URL((process.env.APP_URL ?? "http://localhost:3000").replace(/\/$/, "")),
  title: "Mission Control · Software Digital Twin",
  description: "A live, zoomable map of how your software is built, shipped and running.",
  applicationName: "Mission Control for Code",
  openGraph: { title: "Mission Control for Code", description: "A live, zoomable map of how your software is built, shipped and running.", type: "website" },
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
