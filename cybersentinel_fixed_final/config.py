"""CyberSentinel — Configuration v3"""
import os
from pathlib import Path
from dotenv import load_dotenv

_BASE_DIR = Path(__file__).parent

def _read_env(key: str, default: str = "") -> str:
    val = os.getenv(key, default)
    return val.strip('"').strip("'").strip()

class Settings:
    def __init__(self):
        load_dotenv(_BASE_DIR / ".env")
        self._load()

    def _load(self):
        self.GROQ_API_KEY: str = _read_env("GROQ_API_KEY")
        self.GROQ_MODEL: str   = _read_env("GROQ_MODEL", "llama-3.3-70b-versatile")
        self.GROQ_API_URL: str = "https://api.groq.com/openai/v1/chat/completions"
        self.APP_ENV:   str    = _read_env("APP_ENV", "production")
        self.LOG_LEVEL: str    = _read_env("LOG_LEVEL", "INFO")
        self.VERSION:   str    = "3.0.0"
        self.TITLE:     str    = "CyberSentinel Forensic Scanner"
        self.HOST: str         = _read_env("HOST", "0.0.0.0")
        self.PORT: int         = int(_read_env("PORT", "8000"))
        # CORS_ORIGINS: comma-separated list of allowed frontend origins.
        # On Render, set this env var to your Vercel URL, e.g.:
        #   CORS_ORIGINS=https://cybersentinel.vercel.app,http://localhost:8000
        cors_raw = _read_env("CORS_ORIGINS", "http://localhost:8000,http://localhost:3000")
        self.CORS_ORIGINS: list[str] = [o.strip() for o in cors_raw.split(",") if o.strip()]
        self.MAX_WS_CONNECTIONS: int = int(_read_env("MAX_WS_CONNECTIONS", "10"))
        self.RATE_LIMIT: int         = int(_read_env("RATE_LIMIT", "30"))
        self.SCAN_TIMEOUT: int       = int(_read_env("SCAN_TIMEOUT", "60"))
        self.VIRUSTOTAL_API_KEY: str = _read_env("VIRUSTOTAL_API_KEY", "")
        self.ENABLE_HEURISTICS: bool = _read_env("ENABLE_HEURISTICS", "true").lower() == "true"

    def reload(self):
        load_dotenv(_BASE_DIR / ".env", override=True)
        self._load()

    @property
    def is_production(self) -> bool:
        return self.APP_ENV == "production"

    @property
    def groq_configured(self) -> bool:
        return bool(self.GROQ_API_KEY) and not self.GROQ_API_KEY.startswith("gsk_your_")

    @property
    def vt_configured(self) -> bool:
        return bool(self.VIRUSTOTAL_API_KEY) and len(self.VIRUSTOTAL_API_KEY) > 10

settings = Settings()