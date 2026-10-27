"""
Centralized configuration for 3nricher.

Loads .env from the project root (regardless of the current working directory),
exposes typed configuration values, and validates required keys at startup.

Usage:
    from config import Config

    api_key = Config.VT_API_KEY
    timeout = Config.HTTP_TIMEOUT

    warnings = Config.validate()
"""
import os
from pathlib import Path

from dotenv import load_dotenv


# ---------------------------------------------------------------
# Load .env from project root — regardless of CWD
# ---------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent
ENV_PATH = PROJECT_ROOT / ".env"

load_dotenv(ENV_PATH)


# ---------------------------------------------------------------
# Configuration class
# ---------------------------------------------------------------
class Config:
    """
    Runtime configuration.

    Values are read once at import time. To pick up changes to .env,
    restart the process.
    """

    # ---- API keys (None if not set) ----
    VT_API_KEY: str | None = os.getenv("VT_API_KEY")
    ABUSE_API_KEY: str | None = os.getenv("ABUSE_API_KEY")
    ABUSE_CH_API_KEY: str | None = os.getenv("ABUSE_CH_API_KEY")
    OTX_API_KEY: str | None = os.getenv("OTX_API_KEY")
    GREYNOISE_API_KEY: str | None = os.getenv("GREYNOISE_API_KEY")
    IPINFO_API_KEY: str | None = os.getenv("IPINFO_API_KEY")
    # ---- Behavior ----
    VT_SLEEP_SECONDS: int = int(os.getenv("VT_SLEEP_SECONDS", "16"))
    HTTP_TIMEOUT: int = int(os.getenv("HTTP_TIMEOUT", "15"))
    DEFAULT_WORKERS: int = int(os.getenv("DEFAULT_WORKERS", "10"))
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()
    
        # ---- Scoring weights ----
    # VirusTotal
    SCORE_VT_PER_MALICIOUS: int = 5
    SCORE_VT_PER_SUSPICIOUS: int = 2
    SCORE_VT_MAX: int = 50

    # AbuseIPDB
    SCORE_ABUSE_MULTIPLIER: float = 0.25
    SCORE_ABUSE_MAX: int = 25

    # MalwareBazaar — flat score for confirmed malware
    SCORE_MB_HIT: int = 40

    # URLhaus
    SCORE_URLHAUS_PER_URL: int = 5
    SCORE_URLHAUS_MAX: int = 25

    # Thresholds
    THRESHOLD_CRITICAL: int = 70
    THRESHOLD_HIGH: int = 45
    THRESHOLD_MEDIUM: int = 20

    # Floors — minimum label if specific sources hit
    FLOOR_MB_LABEL: str = "High"        # confirmed malware → at least High
    FLOOR_ABUSE_100_LABEL: str = "High" # abuse_score 100 → at least High

    # Allowlist — IOCs that should always score Low
    ALLOWLIST_IPS: tuple[str, ...] = (
        "8.8.8.8", "8.8.4.4",                    # Google DNS
        "1.1.1.1", "1.0.0.1",                    # Cloudflare DNS
        "9.9.9.9",                                # Quad9
        "208.67.222.222", "208.67.220.220",      # OpenDNS
    )
    ALLOWLIST_DOMAINS: tuple[str, ...] = (
        "google.com", "microsoft.com", "cloudflare.com",
        "amazon.com", "apple.com", "github.com",
    )

    # ---- Paths ----
    PROJECT_ROOT: Path = PROJECT_ROOT
    ENV_PATH: Path = ENV_PATH

    @classmethod
    def validate(cls) -> list[str]:
        """
        Check that required keys are set.

        Returns:
            A list of human-readable warnings. Empty list if all good.
        """
        warnings: list[str] = []

        if not cls.VT_API_KEY:
            warnings.append(
                "VT_API_KEY not set — VirusTotal enrichment disabled"
            )
        if not cls.ABUSE_API_KEY:
            warnings.append(
                "ABUSE_API_KEY not set — AbuseIPDB enrichment disabled"
            )
        if not cls.ABUSE_CH_API_KEY:
            warnings.append(
                "ABUSE_CH_API_KEY not set — MalwareBazaar + URLhaus disabled"
            )
        if not cls.OTX_API_KEY:
            warnings.append(
                "OTX_API_KEY not set — AlienVault OTX enrichment disabled"
            )
        if not cls.GREYNOISE_API_KEY:
            warnings.append(
                "GREYNOISE_API_KEY not set — GreyNoise enrichment disabled"
            )

        return warnings

    @classmethod
    def redacted_summary(cls) -> dict:
        """
        Return a dict safe for logging — API keys are redacted.

        Useful for DEBUG logs to confirm which keys are loaded
        without leaking the actual values.
        """
        def redact(key: str | None) -> str:
            if not key:
                return "<not set>"
            if len(key) < 8:
                return "<short>"
            return f"{key[:4]}...{key[-4:]}"

        return {
            "VT_API_KEY": redact(cls.VT_API_KEY),
            "ABUSE_API_KEY": redact(cls.ABUSE_API_KEY),
            "ABUSE_CH_API_KEY": redact(cls.ABUSE_CH_API_KEY),
            "OTX_API_KEY": redact(cls.OTX_API_KEY),
            "GREYNOISE_API_KEY": redact(cls.GREYNOISE_API_KEY),
            "VT_SLEEP_SECONDS": cls.VT_SLEEP_SECONDS,
            "HTTP_TIMEOUT": cls.HTTP_TIMEOUT,
            "LOG_LEVEL": cls.LOG_LEVEL,
            "PROJECT_ROOT": str(cls.PROJECT_ROOT),
        }
