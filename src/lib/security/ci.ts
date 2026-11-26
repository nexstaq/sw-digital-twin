/** Pinned by digest, so the image that runs against your staging site cannot change underneath you. Bump deliberately. */
export const NUCLEI_IMAGE = "projectdiscovery/nuclei:v3.11.1@sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb";

/**
 * A GitHub Actions workflow that tests YOUR OWN staging site and sends the results here. It runs in your repository, on GitHub's
 * runners, against a target you name: this service never sends test traffic anywhere. Authentication is GitHub's own OIDC token
 * (no stored secret): it proves the run belongs to this repository, which is the only repository it can import into.
 *
 * Safe by default: manual or weekly only (never on pull requests), refuses to run until you name a target and confirm you are
 * authorised to test it, skips intrusive and denial-of-service templates, and is rate limited.
 */
export function ciWorkflow(o: { origin: string }): string {
  // https only. (http://localhost is accepted so the page can be developed locally; a GitHub runner could never reach it.)
  if (!/^(https:\/\/[\w.-]+|http:\/\/localhost|http:\/\/127\.0\.0\.1)(:\d+)?$/.test(o.origin)) throw new Error("origin must be an https origin");
  return `# Live security test, sent to Mission Control.
#
# BEFORE you enable this:
#   1. Settings > Secrets and variables > Actions > Variables: set SECURITY_TEST_TARGET to your STAGING site, e.g. https://staging.example.com
#   2. Set SECURITY_TEST_CONFIRM_OWNER to "yes" ONLY if you own that site or are authorised in writing to test it.
# Never point this at a system you do not own: unauthorised testing can be illegal.
name: Live security test

on:
  workflow_dispatch:
  schedule:
    - cron: "17 3 * * 1"   # Mondays 03:17 UTC

permissions:
  contents: read
  id-token: write   # lets this run prove to Mission Control which repository it belongs to; no secret is stored

jobs:
  nuclei:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    env:
      TARGET: \${{ vars.SECURITY_TEST_TARGET }}
      CONFIRMED: \${{ vars.SECURITY_TEST_CONFIRM_OWNER }}
      MC_ORIGIN: ${o.origin}
    steps:
      - name: Check a target is named and you are authorised to test it
        run: |
          case "$TARGET" in
            https://*) ;;
            *) echo "::error::Set the repository variable SECURITY_TEST_TARGET to your staging URL (https://...)."; exit 1 ;;
          esac
          if [ "$CONFIRMED" != "yes" ]; then
            echo "::error::Set SECURITY_TEST_CONFIRM_OWNER to yes, confirming you own or are authorised to test $TARGET."
            exit 1
          fi

      - name: Run the tests (gentle, rate limited, no intrusive or denial-of-service checks)
        run: |
          mkdir -p out
          docker run --rm -v "$PWD/out:/out" ${NUCLEI_IMAGE} \\
            -u "$TARGET" -severity low,medium,high,critical \\
            -etags dos,intrusive,fuzz,bruteforce \\
            -rate-limit 20 -c 10 -timeout 10 -ni -silent \\
            -sarif-export /out/nuclei.sarif
          # a clean run writes no file: send an empty report so earlier findings are cleared
          [ -s out/nuclei.sarif ] || echo '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Nuclei"}},"results":[]}]}' > out/nuclei.sarif

      - name: Send the results to Mission Control
        run: |
          set -euo pipefail
          TOKEN=$(curl -fsS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=$MC_ORIGIN" | jq -r .value)
          echo "::add-mask::$TOKEN"
          curl -fsS --fail-with-body -X POST \\
            -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\
            --data-binary @out/nuclei.sarif \\
            "$MC_ORIGIN/api/security/import?repo=$GITHUB_REPOSITORY"
`.replace("${NUCLEI_IMAGE}", NUCLEI_IMAGE);
}

/**
 * A GitHub Actions workflow that runs an authorised, non-intrusive simulation check (X9: the red-team or gray-box
 * agent's own reachability questions, extended to a real site) against YOUR OWN staging site, from YOUR OWN runner.
 * Two round trips to Mission Control, never more: first it asks exactly which GET requests it may make (the plan),
 * then it makes only those, gently, and reports what it saw. This service never sends a request to your site itself.
 *
 * Safe by default, the same way the live security test above is: manual or weekly only, never on pull requests,
 * refuses to run until you name a target and confirm you are authorised to test it, and is rate limited. No container
 * image is needed at all: every request is a plain `curl` the workflow's own text shows in full, nothing hidden in an
 * image this service chose for you.
 */
export function simulationWorkflow(o: { origin: string }): string {
  if (!/^(https:\/\/[\w.-]+|http:\/\/localhost|http:\/\/127\.0\.0\.1)(:\d+)?$/.test(o.origin)) throw new Error("origin must be an https origin");
  return `# Authorised simulation test, run from YOUR OWN runner against YOUR OWN staging site. Mission Control only ever
# decides which requests are allowed and reads back what you saw: it never sends a request to your site itself.
#
# BEFORE you enable this:
#   1. Settings > Secrets and variables > Actions > Variables: set SECURITY_TEST_TARGET to your STAGING site, e.g. https://staging.example.com
#   2. Set SECURITY_TEST_CONFIRM_OWNER to "yes" ONLY if you own that site or are authorised in writing to test it.
#   3. Optionally set SECURITY_TEST_PROFILE to "access" (the default: do routes meant for signed-in users answer anonymously?)
#      or "reachability" (which routes on the map are actually live).
# Never point this at a system you do not own: unauthorised testing can be illegal.
name: Authorised simulation test

on:
  workflow_dispatch:
  schedule:
    - cron: "41 4 * * 1"   # Mondays 04:41 UTC: a different time than the live security test, so they never collide

permissions:
  contents: read
  id-token: write   # lets this run prove to Mission Control which repository it belongs to; no secret is stored

jobs:
  simulate:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    env:
      TARGET: \${{ vars.SECURITY_TEST_TARGET }}
      CONFIRMED: \${{ vars.SECURITY_TEST_CONFIRM_OWNER }}
      PROFILE: \${{ vars.SECURITY_TEST_PROFILE || 'access' }}
      MC_ORIGIN: ${o.origin}
    steps:
      - name: Check a target is named and you are authorised to test it
        run: |
          case "$TARGET" in
            https://*) ;;
            *) echo "::error::Set the repository variable SECURITY_TEST_TARGET to your staging URL (https://...)."; exit 1 ;;
          esac
          if [ "$CONFIRMED" != "yes" ]; then
            echo "::error::Set SECURITY_TEST_CONFIRM_OWNER to yes, confirming you own or are authorised to test $TARGET."
            exit 1
          fi

      - name: Ask Mission Control which requests this run may make (it sends nothing itself)
        run: |
          set -euo pipefail
          TOKEN=$(curl -fsS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=$MC_ORIGIN" | jq -r .value)
          echo "::add-mask::$TOKEN"
          curl -fsS --fail-with-body -X POST \\
            -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\
            --data "{\\"url\\":\\"$TARGET\\",\\"profile\\":\\"$PROFILE\\",\\"confirmed\\":true}" \\
            "$MC_ORIGIN/api/security/simulate/ci-plan?repo=$GITHUB_REPOSITORY" > plan.json

      - name: Make exactly the authorised requests, gently, nothing else (GET only, a pause between each, a 4 KB cap)
        run: |
          set -euo pipefail
          CONTROL=$(jq -r .controlPath plan.json)
          probe() { curl -sS -o /dev/null -w '%{http_code} %{size_download}' --max-time 10 -r 0-4095 "$TARGET$1" 2>/dev/null || echo "0 0"; }
          read -r CONTROL_STATUS CONTROL_BYTES <<< "$(probe "$CONTROL")"
          OBS="[]"
          while IFS= read -r path; do
            [ -z "$path" ] && continue
            sleep 0.3
            read -r STATUS BYTES <<< "$(probe "$path")"
            OBS=$(echo "$OBS" | jq --arg p "$path" --argjson s "$STATUS" --argjson b "$BYTES" '. + [{path:$p,status:$s,bytes:$b}]')
          done < <(jq -r '.routes[]' plan.json)
          jq -n --argjson obs "$OBS" --argjson cs "$CONTROL_STATUS" --argjson cb "$CONTROL_BYTES" --arg t "$(jq -r .token plan.json)" \\
            '{token:$t, controlStatus:$cs, controlBytes:$cb, observations:$obs}' > report.json

      - name: Send what was seen back to Mission Control
        run: |
          set -euo pipefail
          TOKEN=$(curl -fsS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=$MC_ORIGIN" | jq -r .value)
          echo "::add-mask::$TOKEN"
          curl -fsS --fail-with-body -X POST \\
            -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\
            --data-binary @report.json \\
            "$MC_ORIGIN/api/security/simulate/ci-report?repo=$GITHUB_REPOSITORY"

      - name: Print a redacted transcript to this run's own log (the token is a one-time, 35-minute credential; stripped anyway)
        if: always()
        run: |
          echo "--- plan ---"; jq 'del(.token)' plan.json 2>/dev/null || true
          echo "--- report ---"; cat report.json 2>/dev/null || true
`;
}
