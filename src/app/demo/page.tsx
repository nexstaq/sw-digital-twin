import { Canvas } from "@/components/twin/Canvas";
import { fixtureGraph } from "@/lib/graph/fixture";

export const metadata = { title: "Demo · Mission Control" };

export default function DemoPage() {
  return <Canvas graph={fixtureGraph} />;
}
