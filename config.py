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

    # ---- Behavior ----
    VT_SLEEP_SECONDS: int = int(os.getenv("VT_SLEEP_SECONDS", "16"))
    HTTP_TIMEOUT: int = int(os.getenv("HTTP_TIMEOUT", "15"))
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()

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
            "VT_SLEEP_SECONDS": cls.VT_SLEEP_SECONDS,
            "HTTP_TIMEOUT": cls.HTTP_TIMEOUT,
            "LOG_LEVEL": cls.LOG_LEVEL,
            "PROJECT_ROOT": str(cls.PROJECT_ROOT),
        }
