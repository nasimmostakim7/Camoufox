# Auditing your own WAF and bot defenses

This guide covers the audit tool added in this fork. It is for testing a site you
own or have written permission to test, to find out which of your defenses are
actually doing work and which are not.

**Read this first.** Running this tool sends real traffic to a real site. It has
safety ceilings and an authorization gate built in, but the responsibility for
having permission is yours. Do not point it at a site you do not control.

## What it answers

Most defenses are tested with a single pass/fail: either the bot got in or it did
not. That result is not actionable. It tells you to turn everything up, which is
how a site ends up with a WAF that blocks real customers.

This tool instead runs an ordered ladder of client postures and reports **which
rung your defenses first stop**, and **which rungs sail through**. Each finding
points at one control, so you know what to fix.

## The evasion ladder

Each rung adds exactly one capability over the one below it, so a change in
outcome between two rungs isolates the defense responsible.

| Level | Posture | What a stop here tells you |
|-------|---------|----------------------------|
| 0 | Plain HTTP, default library User-Agent | Your defenses stop trivial scrapers. This is the floor, not an achievement. |
| 1 | Real Camoufox browser, headless, default fingerprint | You are catching headless/automation tells, not fingerprint spoofing. |
| 2 | Headful browser, coherent navigation headers | You key on missing or contradictory headers. |
| 3 | Consistent fingerprint (screen, locale, timezone, WebGL) | You key on fingerprint inconsistency. |
| 4 | Proxy rotation, one exit IP per visit | Your IP-based reputation or rate limiting is the control doing the work. |
| 5 | Human-like behavior (dwell, mouse, referers) | Your behavioral analysis is the control doing the work. |
| 6 | Persistent identity across visits | You are correlating identity over time. |

Run `camoufox audit levels` to see the current ladder.

## Command line

The fastest path is the CLI.

```bash
# See what the ladder tests
camoufox audit levels

# A first look: 100 visitors over one hour, levels 0-3
camoufox audit run \
    --target https://staging.example.com/ \
    --i-am-authorized

# The full 24-hour picture: 1000 visitors spread across a day
camoufox audit run \
    --target https://example.com/ \
    --i-am-authorized \
    --visitors 1000 --hours 24

# Climb further, with proxy rotation
camoufox audit run \
    --target https://example.com/ \
    --i-am-authorized \
    --max-level 5 \
    --proxy-file proxies.txt \
    --out ./audit-2026-09-15
```

`--i-am-authorized` is required. Without it the tool refuses to start.

Useful flags:

| Flag | Meaning |
|------|---------|
| `--visitors N` | How many visitors to schedule. |
| `--hours H` | Window to spread them across. |
| `--pattern` | `human_diurnal` (default), `constant`, `ramp`, `spike`, `sustained`. |
| `--max-level N` | Highest rung to climb, 0-6. |
| `--level N` | Run exactly these rungs (repeatable). |
| `--single-level N` | Run only rung N, skipping L0 up to it. Pins `--visitors` to 100. |
| `--proxy-file` | Text file of proxies, one per line, rotated one per visit. |
| `--proxy-gateway` | Rotating gateway URL; `{session}` is substituted per visit. |
| `--max-requests`, `--max-rps`, `--max-concurrency`, `--max-per-minute` | Safety ceilings. |
| `--seed N` | Makes the schedule and behavior reproducible. |
| `--out DIR` | Write JSON, CSV, HTML and text reports. |

### Why 1000 visitors over 24 hours does not arrive at once

This matters, so it is worth being explicit. The tool does **not** fire N requests
simultaneously, and it does not use a fixed interval either. Both of those patterns
are trivially detectable.

Instead it samples arrival times from a distribution. With the default
`human_diurnal` pattern, arrivals follow a day curve — quiet overnight, busier in
the evening — with random jitter on each one. A 1000-visitor/24-hour run produces
inter-arrival gaps ranging from about 1 second to over 20 minutes, with hundreds of
distinct values. The GUI shows a preview of this before you start, so the shape is
visible rather than assumed.

The `--max-per-minute` ceiling bounds the worst burst, so a random draw cannot
accidentally turn into a flood.

### Running one rung on its own

By default the audit climbs the ladder from L0 up to `--max-level`, because the
finding that matters is *which* rung the defenses stop at. That attribution only
exists relative to the rungs below it: "the defenses first hold at L3" means L3
was stopped and L0-L2 were not.

`--single-level N` runs only rung N, skipping L0 up to it. Use it when you already
know which posture you care about and want to repeat one measurement — a specific
page behind a proxy pool, a change to a WAF rule, the same rung at two points in
time. The visitor count is pinned to 100 in this mode, not taken from `--visitors`,
so two single-rung runs are directly comparable.

A single rung has nothing below it to compare against, so the report says so
rather than printing the usual "first holding rung" line:

```
camoufox audit run \
    --target https://example.com/ \
    --i-am-authorized \
    --single-level 5 --proxy-file proxies.txt
```

```
Single-rung run: only L5 - Human behavior was tested, so this measures one
posture and cannot attribute a defense. Run the ladder from L0 to find which
control is doing the work.
```

`--single-level` cannot be combined with `--level`; both name the rungs to run,
and passing both is refused rather than silently resolved.

## The GUI

Launch it with:

```bash
camoufox gui
```

The **Audit** tab has three parts.

**Left column — configuration.**

- Target URL and authorized hosts. The scope defaults to the target's host, and
  subdomains are opt-in: a bare domain does not authorize `*.domain.com`.
- The authorization checkbox and an optional ticket reference. The Start button
  stays disabled until this is checked.
- Traffic plan: visitor count, window in hours, arrival pattern, and the maximum
  evasion level. Tick **Single-level mode** to run one rung on its own instead of
  the ladder, and pick which one; the visitor count is pinned to 100 and the
  input is disabled, so repeat runs at that rung are comparable.
- An arrival preview chart showing how the visitors are distributed across the
  window, with the busiest and quietest periods called out.
- Proxy settings: no proxy, a list file, or a rotating gateway, with a per-proxy
  ceiling and a **Check** button that parses the file and reports what was usable.
- Safety ceilings: requests, requests per second, concurrency, arrivals per
  minute, and where to write reports.

**Right side — run and results.**

- Start, Stop and Clear. Stop takes effect between visits and lets in-flight
  requests finish, so a run does not end mid-navigation.
- A live table of every visit with its level, verdict, HTTP status and reason.
- The findings list, which is the part to read.
- A running log.

### Proxies

Proxy passwords are never displayed. The Check button shows redacted endpoints
(`http://user:***@1.2.3.4:8080`) so a screenshot of the app does not leak your
pool's credentials.

A malformed line is reported as an error rather than silently skipped. That is
deliberate: a silently dropped proxy means a visit goes out from your own IP under
a foreign fingerprint, which contaminates the audit and can burn the identity.

## Reading the results

The report leads with findings, not totals. A few examples of what they mean:

**"The defenses first hold at L2 - Consistent headers (94% of visits stopped
there)."** Your header validation is doing the work. The fingerprint and IP
layers below it are not being reached. Start by checking that the fingerprints
are actually being applied.

**"L0 and L1 were fully defeated and are doing no work against this client."**
You are spending effort on a layer that this class of bot walks through.

**"L4 reached the site cleanly on 97% of visits."** Proxy rotation defeats your
current control. If that is a surprise, your IP reputation feed is probably not
connected to the edge that serves this route.

**"No known WAF or bot-defense product signature appeared in any response."**
Either the responses carry no identifying headers, or your traffic never reached
a product that would recognize it. Confirm which before trusting an "allowed".

**"340 of 500 visits ended in a transport error."** Connectivity or proxy trouble,
not a defense verdict. Detection rates from that run are not meaningful.

### Verdicts

| Verdict | Meaning |
|---------|---------|
| `allowed` | The request reached the site. This is a bypass. |
| `challenged` | A challenge or interstitial was served. The request did not reach the site. |
| `rate_limited` | Refused with a retry horizon (429/503, usually with `Retry-After`). |
| `blocked` | Refused outright (403, or a WAF block page). |
| `error` | Transport or server failure. Not a verdict about the client. |

`challenged` and `blocked` are deliberately distinct. A block means the request
never had a chance; a challenge means the defense is willing to be convinced. They
call for opposite responses, so the tool does not merge them.

## Reports

`--out DIR` (or the report directory in the GUI) writes four files:

- `audit.json` — everything, including per-visit detail.
- `audit.csv` — one row per visit, for a spreadsheet.
- `audit.html` — a self-contained report with no external assets, safe to hand to
  someone who does not have this package installed.
- `audit.txt` — the plain-text summary.

Re-render a saved run with:

```bash
camoufox audit report audit.json
```

## Safety ceilings

The ceilings are not advisory. When one is reached the run stops and the report
records why, rather than continuing quietly.

| Ceiling | Stops the run at |
|---------|------------------|
| `max_requests` | Total requests sent. |
| `max_rps` | Requests per second. |
| `max_concurrency` | Visitors in flight at once. |
| `max_arrivals_per_minute` | Worst-case burst. |
| `max_per_proxy` | Requests through one exit IP. |
| consecutive errors | 15 errors in a row, which usually means the target is down. |

An aborted run is marked as such in the report. Partial levels are labeled, so you
do not mistake a cut-off run for a clean result.

## What this tool will not do

It does not solve CAPTCHAs, exploit vulnerabilities, or replay stolen credentials.
Detecting that a challenge was issued *is* the finding. Solving it would defeat the
defense you are trying to measure, and you would learn nothing about your own site.

## Scope and authorization

- A target must be named in the scope **and** acknowledged. There is no bypass flag.
- Scope matching is exact host plus explicitly listed subdomains. `example.com`
  does not authorize `api.example.com`, and `evil-example.com` is never matched.
- Every navigation passes the scope check, so a redirect or an off-site link cannot
  pull the audit somewhere it was not authorized to go.
- Only `http` and `https` targets are accepted.

## Troubleshooting

**"Refusing to run: pass --i-am-authorized"** — this is the gate working. Confirm
you have permission and pass the flag.

**Browser levels report `CamoufoxNotInstalled`** — the browser binary has not been
fetched yet. Run `camoufox fetch`, or use the Browsers tab in the GUI.

**Headed levels (L2 and above) report an error about `no DISPLAY`** — this should not
happen on its own. The runner detects a host with no X server and points those rungs
at Camoufox's built-in virtual display, announcing it with a notice in the log. If you
see a raw `no DISPLAY environment variable specified` in a visit reason instead, the
virtual display could not start: check that `Xvfb` is installed (`apt install xvfb`),
or run under `xvfb-run`.

Note that a virtual display is not a desktop. Headed levels under it still look like
a real headed browser to JavaScript, but there is no window manager and no real screen
hardware, so a defense that inspects those may behave differently than on a laptop.
Treat an L2+ result from a headless server as strong evidence, not as identical to a
run on a real desktop.

**Headed levels fail with `CannotFindXvfb`** — the fallback above needs `Xvfb` to be
present. `apt install xvfb` (or run the whole audit under `xvfb-run -a`) and the rung
will launch.

**Fingerprint levels (L3 and above) run without geolocation** — the `geoip` extra is
not installed, so `geoip2` is missing and those rungs would otherwise fail to launch.
The runner clears the flag on its own so the rung still runs and reports a verdict,
and logs a notice. The mask is weaker: the spoofed fingerprint is not aligned to the
request's IP location or timezone, which a defense comparing the two can detect.
Install it with `pip install camoufox[geoip]` for the full mask.

Both fallbacks are decisions the runner makes per rung, and both are asserted in
`pythonlib/tests/test_audit.py` against the assembled launch options rather than
against a live visit. That suite runs in CI's browser-free `pythonlib` tier, which
fetches no browser, so a version of these tests that launched one would report
`CamoufoxNotInstalled` as if it were an audit finding.

**Every level reports the same verdict** — check that the target is actually being
reached. A `403` at L0 and a `403` at L6 with an identical body often means the
scope is wrong or the host is refusing all traffic.

**Detection rates look implausible** — check the error count in the findings. A run
where most visits errored is measuring your connectivity, not your defenses.
