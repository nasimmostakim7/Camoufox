"""
Human-like visitor journeys.

A visitor is not a single request. It is an arrival, a period of attention, some
interaction, and a departure. Behavioral defenses score exactly that shape: a
client that requests one page and vanishes is not behaving like a reader, and a
client that requests every page in a fixed order and fixed interval is behaving
like a crawler.

Everything here is randomized on purpose, and drawn from distributions that
resemble real attention rather than a uniform range. Uniform dwell time is the
tell: real reading time is right-skewed, with most visits short and a long tail.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse

__all__ = [
    "ArrivalSource",
    "JourneyConfig",
    "VisitPlan",
    "plan_visit",
    "build_arrival_referer",
]

#: Real search engines and a couple of common referral hosts. A visitor that
#: claims a search-engine referer on every visit is itself a pattern, so the
#: mix matters as much as the individual values.
SEARCH_ENGINES = {
    "google": "https://www.google.com/",
    "bing": "https://www.bing.com/",
    "duckduckgo": "https://duckduckgo.com/",
    "yahoo": "https://search.yahoo.com/",
    "ecosia": "https://www.ecosia.org/",
}

SOCIAL_REFERRERS = [
    "https://www.facebook.com/",
    "https://t.co/",
    "https://www.linkedin.com/",
    "https://www.reddit.com/",
    "https://www.instagram.com/",
]


class ArrivalSource:
    """How a visitor found the site."""

    DIRECT = "direct"
    SEARCH = "search"
    REFERRAL = "referral"
    INTERNAL = "internal"

    ALL = (DIRECT, SEARCH, REFERRAL, INTERNAL)


def build_arrival_referer(source: str, target_url: str, rng: random.Random) -> Optional[str]:
    """
    A plausible Referer for an arrival, or None for a direct visit.

    Direct traffic sends no Referer at all. An audit that always sends one is
    trivially separable from real traffic, which is mostly direct.
    """
    if source == ArrivalSource.DIRECT or source == ArrivalSource.INTERNAL:
        return None
    if source == ArrivalSource.SEARCH:
        engine = rng.choice(list(SEARCH_ENGINES.values()))
        query = rng.choice(
            ["", "?q=" + rng.choice(["site", "login", "pricing", "docs", "contact", "reviews"]),
             "?q=" + urlparse(target_url).netloc]
        )
        return engine + query
    if source == ArrivalSource.REFERRAL:
        return rng.choice(SOCIAL_REFERRERS)
    return None


@dataclass
class JourneyConfig:
    """Tunables for one visitor's behavior, all randomized within these bounds."""

    #: Fraction of visitors arriving by each channel. Direct-heavy by default,
    #: because that is the common shape of real traffic.
    source_weights: dict = field(
        default_factory=lambda: {
            ArrivalSource.DIRECT: 0.45,
            ArrivalSource.SEARCH: 0.35,
            ArrivalSource.REFERRAL: 0.20,
        }
    )
    #: How long the visitor stays, in seconds. Log-normal mimics real attention:
    #: mostly short visits with a long tail, unlike a uniform draw.
    dwell_median_s: float = 75.0
    dwell_sigma: float = 0.9
    dwell_min_s: float = 8.0
    dwell_max_s: float = 900.0
    #: Pages viewed in one session.
    pages_min: int = 1
    pages_max: int = 6
    #: Whether to scroll, and roughly how far down the page.
    scroll_probability: float = 0.85
    scroll_steps_min: int = 2
    scroll_steps_max: int = 10
    #: Whether to type into a form/search box when one is available.
    type_probability: float = 0.15
    #: Probability the visitor leaves immediately (bounce).
    bounce_probability: float = 0.35
    #: Follow in-site links found on a page vs. request known paths directly.
    follow_links_probability: float = 0.6
    #: Ceiling on pages requested from any single path, to avoid hammering one URL.
    max_requests_per_visitor: int = 12


@dataclass
class VisitPlan:
    """One visitor's scripted session, decided up front."""

    source: str
    referer: Optional[str]
    dwell_s: float
    page_count: int
    scroll_steps: int
    will_type: bool
    is_bounce: bool
    follow_links: bool
    inter_page_delay_s: List[float] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "referer": self.referer,
            "dwell_s": round(self.dwell_s, 2),
            "page_count": self.page_count,
            "scroll_steps": self.scroll_steps,
            "will_type": self.will_type,
            "is_bounce": self.is_bounce,
            "follow_links": self.follow_links,
            "inter_page_delay_s": [round(d, 2) for d in self.inter_page_delay_s],
        }


def _lognormal(median: float, sigma: float, low: float, high: float, rng: random.Random) -> float:
    """Sample a right-skewed dwell time, clamped to a sane range."""
    import math

    value = rng.lognormvariate(math.log(max(median, 1e-6)), sigma)
    return float(min(max(value, low), high))


def plan_visit(
    config: JourneyConfig,
    rng: random.Random,
    *,
    behavior: bool = True,
) -> VisitPlan:
    """
    Decide what one visitor does, before touching the network.

    Planning first keeps the behavior coherent: the referer, the page count and
    the cadence are chosen together rather than drifting independently, which is
    what makes a session look scripted.

    `behavior` gates the *human cadence* axes -- dwell, goto-scrolling, typing,
    multi-page journeys and the arrival source. When False the visit is a single
    direct request, which is what the rungs below the behavioral one have to send
    to stay honest: a rung whose job is to test header consistency cannot also be
    silently humanized, or its verdict would credit the wrong control. Camoufox's
    own cursor humanization is a separate axis, enabled by the rung's launch
    options.
    """
    if not behavior:
        # A single, direct, immediate request: no referer, no scroll, no typing,
        # no follow-up pages. The shape is what distinguishes this from the
        # behavioral rungs, not the dwell value.
        return VisitPlan(
            source=ArrivalSource.DIRECT,
            referer=None,
            dwell_s=0.0,
            page_count=1,
            scroll_steps=0,
            will_type=False,
            is_bounce=True,
            follow_links=False,
            inter_page_delay_s=[],
        )

    sources = list(config.source_weights.keys())
    weights = list(config.source_weights.values())
    source = rng.choices(sources, weights=weights, k=1)[0]

    is_bounce = rng.random() < config.bounce_probability
    if is_bounce:
        # A bounce is a short visit that requests one page and leaves.
        dwell = _lognormal(
            med := config.dwell_median_s * 0.25,
            config.dwell_sigma * 0.7,
            config.dwell_min_s,
            min(config.dwell_max_s, 60.0),
            rng,
        )
        return VisitPlan(
            source=source,
            referer=None,
            dwell_s=dwell,
            page_count=1,
            scroll_steps=0 if rng.random() < 0.7 else rng.randint(1, 3),
            will_type=False,
            is_bounce=True,
            follow_links=False,
            inter_page_delay_s=[],
        )

    pages = rng.randint(config.pages_min, config.pages_max)
    dwell = _lognormal(
        config.dwell_median_s, config.dwell_sigma, config.dwell_min_s, config.dwell_max_s, rng
    )

    scroll_steps = (
        rng.randint(config.scroll_steps_min, config.scroll_steps_max)
        if rng.random() < config.scroll_probability
        else 0
    )

    # Split the dwell across the session as reading pauses between pages, rather
    # than sleeping the whole time on the last page.
    delays: List[float] = []
    if pages > 1:
        pools = [rng.random() for _ in range(pages - 1)]
        total = sum(pools) or 1.0
        for pool in pools:
            delays.append(dwell * (pool / total))

    return VisitPlan(
        source=source,
        referer=None,  # filled in by the caller, which knows the target URL
        dwell_s=dwell,
        page_count=pages,
        scroll_steps=scroll_steps,
        will_type=rng.random() < config.type_probability,
        is_bounce=False,
        follow_links=rng.random() < config.follow_links_probability,
        inter_page_delay_s=delays,
    )