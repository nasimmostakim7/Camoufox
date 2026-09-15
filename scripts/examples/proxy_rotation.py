"""
Rotate exit IPs with Camoufox.

Two rotation points, and picking the right one is the whole decision:

* `AsyncCamoufox(proxy_rotator=...)` / `Camoufox(proxy_rotator=...)` assigns one
  exit IP per *browser*. The proxy is fixed for the browser's lifetime and every
  context inside it shares it. Use this when one browser is one session.

* `AsyncNewContext(proxy_rotator=...)` / `NewContext(proxy_rotator=...)` assigns
  one exit IP per *context*. Use this for "a new IP per visit": keep one browser
  and open a fresh context per visit, which is also where the fingerprint is
  regenerated. Creating a browser per visit costs ~1-2s and is usually waste.

Both are shown below.

Notes that matter in production:

* A rotating proxy makes the geoip warning *more* important, not less. Keep
  `geoip=True` so the timezone, locale and WebRTC IP describe the exit IP. When
  the proxy was verified, Camoufox reuses that verified IP instead of probing
  again, so a gateway cannot race you onto a different exit than the one you
  fingerprint for.
* Proxies are checked for repeated exit IPs. A gateway under load hands back a
  sticky IP, and two pool entries can exit from the same address; without this
  check the "new IP" guarantee is silently false.
* If no proxy is available, Camoufox raises rather than connecting directly.
  Launching on your own IP while the fingerprint claims to be elsewhere is a
  detection vector, not a graceful fallback. Pass `allow_direct_fallback=True`
  to override.

Inspect a pool before trusting it:

    camoufox proxy check proxies.txt --verify
    camoufox proxy status --file proxies.txt
    camoufox proxy reset  --file proxies.txt
"""

import asyncio

from camoufox.async_api import AsyncCamoufox, AsyncNewContext

GATEWAY = "http://user-session-{session}:password@gateway.example.com:8000"

# A gateway rotates server-side; `{session}` makes each session land on a
# different exit. Camoufox substitutes a fresh token per session.
GATEWAY_CONFIG = {
    "mode": "gateway",
    "gateway": GATEWAY,
    # Optional: some providers rotate on demand rather than per session.
    # "rotate_url": "http://gateway.example.com/rotate?session={session}",
}

# A list of proxies. One is picked per session, in order, skipping any that are
# cooling down; the cursor lives in a state file, so a restart resumes rather
# than replaying the head of the list.
POOL_CONFIG = {
    "mode": "file",
    "file": "proxies.txt",  # one per line: host:port:user:pass, or user:pass@host:port
    "policy": "round_robin",  # or "least_used", or "random"
    # Ask each proxy for its exit IP and reject repeats. Opt-in here because it
    # costs one request per proxy; gateways default to on.
    "verify_ip": True,
    "failure_threshold": 3,
    "cooldown_seconds": 300,
}


async def one_ip_per_browser() -> None:
    """Each browser gets its own exit IP for its whole lifetime."""
    async with AsyncCamoufox(proxy_rotator=GATEWAY_CONFIG, geoip=True) as browser:
        page = await browser.new_page()
        await page.goto("https://example.com")
        print(await page.title())


async def one_ip_per_visit() -> None:
    """
    One browser, a new exit IP and a new fingerprint for every visit.

    This is the shape most scraping jobs want: the browser launch is the slow
    part, and a context is cheap.
    """
    async with AsyncCamoufox(geoip=True) as browser:
        for visit in range(3):
            context = await AsyncNewContext(browser, proxy_rotator=POOL_CONFIG, os="windows")
            page = await context.new_page()
            await page.goto("https://httpbin.org/ip")
            print(f"visit {visit}: {(await page.text_content('body')).strip()}")
            await context.close()


async def main() -> None:
    await one_ip_per_browser()
    await one_ip_per_visit()


if __name__ == "__main__":
    asyncio.run(main())
