"""
config.py — Centralised configuration with file/env loading and validation.
"""

import os
import json
from dataclasses import dataclass, field


@dataclass
class Config:
    # Thread-pool sizes
    max_workers: int = 100
    max_dns_workers: int = 50
    max_http_workers: int = 50
    enrich_threads: int = 50

    # Rate-limit & timeouts
    dns_rate: float = 0.05           # seconds between DNS queries (token bucket)
    dns_burst: int = 20              # token bucket burst capacity
    wayback_delay: float = 1.0       # polite pause before Wayback requests
    http_timeout: float = 8.0        # seconds per HTTP request
    retry_backoff: list[int] = field(default_factory=lambda: [1, 2, 4])

    # Limits
    max_permutations: int = 10_000
    max_wayback: int = 50_000        # CDX limit per request

    # Feature toggles
    enable_wayback: bool = True
    enable_permutations: bool = True
    enable_tech_fingerprint: bool = True
    enable_nmap: bool = True
    nmap_top_ports: int = 20

    # Shodan
    shodan_key: str = ""

    # User-agent
    user_agent: str = "SubDomainScout/2.0"

    # Permutation tuning
    high_value_suffixes: list[str] = field(
        default_factory=lambda: ["dev", "prod", "test", "staging", "internal", "api", "admin"]
    )
    low_value_suffixes: list[str] = field(
        default_factory=lambda: ["1", "2", "3", "old", "new"]
    )
    permutation_separators: list[str] = field(
        default_factory=lambda: ["-", ""]
    )

    @classmethod
    def load(cls, path: str | None = None) -> "Config":
        """Load from JSON file, then apply environment variable overrides."""
        cfg = cls()
        if path and os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as fp:
                data = json.load(fp)
                for k, v in data.items():
                    if hasattr(cfg, k):
                        setattr(cfg, k, v)

        # Env overrides — e.g. MAX_WORKERS=64, SHODAN_KEY=abc
        for field_name in cfg.__dataclass_fields__:
            env_val = os.getenv(field_name.upper())
            if env_val is not None:
                typ = type(getattr(cfg, field_name))
                if typ is bool:
                    setattr(cfg, field_name, env_val.lower() in ("1", "true", "yes"))
                elif typ is list:
                    setattr(cfg, field_name, env_val.split(","))
                else:
                    setattr(cfg, field_name, typ(env_val))

        # Legacy env var support
        if not cfg.shodan_key:
            cfg.shodan_key = os.getenv("SHODAN_API_KEY", "")

        return cfg

    def validate(self) -> list[str]:
        """Return a list of validation warnings (empty = OK)."""
        errors = []
        if self.max_dns_workers > 200:
            errors.append("max_dns_workers too high (>200), risk of DNS flooding")
        if self.max_permutations < 100:
            errors.append("max_permutations too low (<100)")
        if self.dns_rate < 0:
            errors.append("dns_rate must be non-negative")
        if self.http_timeout <= 0:
            errors.append("http_timeout must be positive")
        return errors
