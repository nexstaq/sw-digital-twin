import { RepoPicker } from "@/components/twin/RepoPicker";
import { SiteFooter } from "@/components/site/SiteChrome";

export const metadata = { title: "Your repositories · Mission Control" };

export default function Page() {
  return (
    <>
      <RepoPicker />
      <SiteFooter />
    </>
  );
}
