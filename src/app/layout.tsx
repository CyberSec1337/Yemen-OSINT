import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Toaster } from "@/components/ui/toaster";
import { Toaster as SonnerToaster } from "@/components/ui/sonner";
import { ThemeProvider } from "@/components/theme-provider";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Yemen Cyber Intelligent | المنصة السيبرانية اليمنية",
  description: "منصة الاستخبارات السيبرانية المتقدمة للتحليل الأمني وجمع المعلومات",
  keywords: ["سيبرانية", "استخبارات", "أمن", "تحليل", "يمن", "OSINT", "Cybersecurity"],
  authors: [{ name: "Yemen Cyber Intelligent Team" }],
  icons: {
    icon: "https://z-cdn.chatglm.cn/z-ai/static/logo.svg",
  },
  openGraph: {
    title: "Yemen Cyber Intelligent",
    description: "منصة الاستخبارات السيبرانية المتقدمة للتحليل الأمني وجمع المعلومات",
    url: "https://chat.z.ai",
    siteName: "Yemen Cyber Intelligent",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "Yemen Cyber Intelligent",
    description: "منصة الاستخبارات السيبرانية المتقدمة للتحليل الأمني وجمع المعلومات",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-background text-foreground`}
      >
        <ThemeProvider
          attribute="class"
          defaultTheme="system"
          enableSystem
          disableTransitionOnChange
        >
          {children}
          <Toaster />
          <SonnerToaster />
        </ThemeProvider>
      </body>
    </html>
  );
}
