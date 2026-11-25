import { expect, test, type Page } from "@playwright/test";
import { mapRepo, tile, watchProblems } from "./helpers";

const simulateTab = (page: Page) => page.locator('[role=tab][title^="See how"]');
const panel = (page: Page) => page.getByRole("region", { name: "Simulation" });
const caption = (page: Page) => panel(page).locator("[aria-live=polite]");

async function openSimulate(page: Page, path = "/demo") {
  await page.goto(path);
  await expect(page.getByText("NO-GO").first()).toBeVisible();
  await simulateTab(page).click();
  await expect(panel(page)).toBeVisible();
}

test("explain a queue: watch a request reach it, step by step, in three voices", async ({ page }) => {
  const problems = watchProblems(page);
  await openSimulate(page);
  await expect(panel(page)).toContainText("Pick a part of the map");
  await panel(page).getByRole("button", { name: "Fulfilment Queue" }).click();

  await expect(panel(page)).toContainText("How Fulfilment Queue is used");
  await expect(panel(page)).toContainText("Step 1 of 3");
  await expect(caption(page)).toContainText("Orders Service");

  await page.keyboard.press("ArrowRight");
  await expect(panel(page)).toContainText("Step 2 of 3");
  await expect(caption(page)).toContainText("Fulfilment Queue");
  const plain = await caption(page).innerText();

  await panel(page).getByRole("radio", { name: "Engineer" }).click();
  await expect(caption(page)).not.toHaveText(plain);
  await expect(caption(page)).toContainText(/publishes a message to Fulfilment Queue/);
  await panel(page).getByRole("radio", { name: "Security" }).click();
  await expect(caption(page)).toContainText(/trusted by the part that picks it up/);

  await page.keyboard.press("ArrowRight");
  await expect(caption(page)).toContainText("Warehouse Sync");
  await expect(caption(page)).toContainText("services/orders/src/warehouse.ts"); // the code behind the step, from the map's own evidence
  await page.keyboard.press("ArrowLeft");
  await expect(panel(page)).toContainText("Step 2 of 3");

  // the three blocks of the flow are on the canvas, lit
  await expect(tile(page, "Warehouse Sync")).toBeVisible();
  expect(problems).toEqual([]);
});

test("auto-play walks through the steps and stops at the end", async ({ page }) => {
  await openSimulate(page);
  await panel(page).getByRole("button", { name: "Fulfilment Queue" }).click();
  await panel(page).getByRole("radio", { name: "4×" }).click();
  await panel(page).getByRole("button", { name: "Play" }).click();
  await expect(panel(page)).toContainText("Step 3 of 3", { timeout: 10_000 });
  await expect(panel(page).getByRole("button", { name: "Play" })).toBeVisible(); // not still "Pause"
});

test("break something: the health rules recolour the map, and Fix it puts it back", async ({ page }) => {
  await openSimulate(page);
  await panel(page).getByRole("button", { name: "Fulfilment Queue" }).click();

  await panel(page).locator("#sim-break-node").selectOption({ label: "Fulfilment Queue" });
  const outcome = panel(page).getByRole("status");
  await expect(outcome).toContainText("Fulfilment Queue stops working");
  await expect(outcome).toContainText("nominal → failing");
  await expect(outcome).toContainText("simulation"); // every reason says where it came from
  await expect(outcome).toContainText("Orders Service"); // what depends on it is dragged down too
  await expect(caption(page)).toContainText(/does not answer|failed/); // opens on the step that fails
  await expect(tile(page, "Fulfilment Queue")).toContainText("simulation"); // the tile on the canvas itself shows the simulated reason

  await panel(page).getByRole("button", { name: "Fix it" }).click();
  await expect(panel(page).locator("#sim-break-node")).toHaveValue("");
  await expect(panel(page).getByRole("status")).toHaveCount(0);
  await expect(caption(page)).not.toContainText("does not answer");
});

test("slowness is judged by the latency rule", async ({ page }) => {
  await openSimulate(page);
  await panel(page).getByRole("button", { name: "Fulfilment Queue" }).click();
  await panel(page).locator("#sim-break-node").selectOption({ label: "Fulfilment Queue" });
  await panel(page).locator("#sim-break-kind").selectOption({ label: "Gets very slow" });
  await expect(panel(page).getByRole("status")).toContainText(/p95 latency/);
});

test("a pipeline: a change goes through its jobs to a release", async ({ page }) => {
  await openSimulate(page);
  await panel(page).getByRole("button", { name: "CI Pipeline" }).click();
  await expect(panel(page)).toContainText("A change going through CI Pipeline");
  await panel(page).getByText(/All \d+ steps/).click();
  await expect(panel(page).getByRole("listitem").filter({ hasText: "Lint & Typecheck" })).toBeVisible();
  await panel(page).getByRole("listitem").filter({ hasText: "Build Image" }).getByRole("button").click();
  await expect(caption(page)).toContainText("Build Image");
});

test("breaking a pipeline job opens on the step that fails, and what needs it is skipped", async ({ page }) => {
  await openSimulate(page);
  await panel(page).getByRole("button", { name: "CI Pipeline" }).click();
  await expect(panel(page)).toContainText("Step 1 of");
  await panel(page).locator("#sim-break-node").selectOption({ label: "Unit Tests" });
  await expect(panel(page)).not.toContainText("Step 1 of"); // not the trigger: the first failing step
  await expect(caption(page)).toContainText("Unit Tests");
  await expect(caption(page)).toContainText(/failed/);
  await panel(page).getByText(/All \d+ steps/).click();
  await expect(panel(page).getByRole("listitem").filter({ hasText: "Build Image" }).getByLabel("failed")).toHaveCount(0); // skipped, not failed
  await page.keyboard.press("ArrowRight");
  await expect(caption(page)).toContainText("Build Image");
  await expect(caption(page)).toContainText(/did not run|skipped/);
});

test("the real verdict is never replaced by the simulation, and closing it restores the real colours", async ({ page }) => {
  await openSimulate(page);
  await expect(page.getByText("NO-GO").first()).toBeVisible();
  await panel(page).getByRole("button", { name: "Fulfilment Queue" }).click();
  await panel(page).locator("#sim-break-node").selectOption({ label: "Fulfilment Queue" });
  await expect(page.getByText("NO-GO").first()).toBeVisible(); // still the real "Payments failing" verdict
  await expect(page.getByText("Payments failing").first()).toBeVisible();

  await panel(page).getByRole("button", { name: "Close simulation" }).click();
  await expect(panel(page)).toHaveCount(0);
  await expect(page.getByText("Payments failing").first()).toBeVisible();
});

test("code structure says there is nothing to run, and offers somewhere to go", async ({ page }) => {
  await openSimulate(page);
  await tile(page, "Release & Deploy").click(); // a grouping block: simulates the most connected thing inside
  await expect(panel(page)).not.toContainText("Pick a part of the map");
  await expect(panel(page)).toContainText(/Release & Deploy/);
});

test("nothing is sent anywhere while simulating", async ({ page }) => {
  const sent: string[] = [];
  await openSimulate(page);
  page.on("request", (r) => { if (["fetch", "xhr", "websocket", "eventsource", "ping"].includes(r.resourceType())) sent.push(`${r.method()} ${r.url()}`); });
  await panel(page).getByRole("button", { name: "Fulfilment Queue" }).click();
  await panel(page).getByRole("radio", { name: "4×" }).click();
  await panel(page).getByRole("button", { name: "Play" }).click();
  await panel(page).locator("#sim-break-node").selectOption({ label: "Fulfilment Queue" });
  await panel(page).getByRole("button", { name: "Fix it" }).click();
  await page.waitForTimeout(800);
  expect(sent).toEqual([]);
});

test("reduced motion: nothing plays by itself, and stepping still works", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await openSimulate(page);
  await panel(page).getByRole("button", { name: "Fulfilment Queue" }).click();
  await expect(panel(page).getByRole("button", { name: "Play" })).toBeDisabled();
  await expect(panel(page)).toContainText("Reduced motion is on");
  await page.waitForTimeout(2500);
  await expect(panel(page)).toContainText("Step 1 of 3"); // did not advance on its own
  await panel(page).getByRole("button", { name: "Next step" }).click();
  await expect(panel(page)).toContainText("Step 2 of 3");
});

test("works on a phone: no sideways scroll, controls reachable", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await openSimulate(page);
  await panel(page).getByRole("button", { name: "Fulfilment Queue" }).click();
  await expect(panel(page).getByRole("button", { name: "Next step" })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  const box = await panel(page).boundingBox();
  expect(box!.width).toBeLessThanOrEqual(390);
  expect(box!.y + box!.height).toBeLessThanOrEqual(844);
});

test("a map built from a real scan works too: its pipeline runs and a failed job is judged by the engine", async ({ page }) => {
  await mapRepo(page, "acme/shop");
  await simulateTab(page).click();
  await tile(page, "CI/CD pipelines").click();
  await expect(panel(page)).toContainText(/pipeline|change going through/i);
  await expect(panel(page)).toContainText(/Step 1 of \d+/);
  // break any job the run went through: the map recolours and says why
  const options = panel(page).locator("#sim-break-node option:not([disabled])");
  expect(await options.count()).toBeGreaterThan(0);
  await panel(page).locator("#sim-break-node").selectOption({ index: 1 });
  await expect(panel(page).getByRole("status")).toContainText(/failing/);
});
