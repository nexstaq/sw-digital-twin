import type { Metadata } from "next";
import { SignInCard } from "@/components/site/SignInCard";
import { SiteFooter, SiteHeader } from "@/components/site/SiteChrome";

export const metadata: Metadata = { title: "Sign in with GitHub · Mission Control for Code", robots: { index: false, follow: true } };

export default function SignInPage() {
  return (
    <>
      <SiteHeader />
      <main className="flex flex-1 items-center px-6 py-10"><SignInCard /></main>
      <SiteFooter />
    </>
  );
}
