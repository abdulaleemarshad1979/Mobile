"""
CyberSentinel — Production Groq AI Engine
Improvements over v1:
  • Retry with exponential back-off (3 attempts)
  • Response validated against Pydantic AiReport model
  • Config sourced from settings singleton (no key leaks)
  • Chat history capped to prevent context bloat
  • Type-annotated throughout
"""

from __future__ import annotations

import asyncio
import json
from typing import Optional

import httpx

from config import settings
from logger import get_logger
from models import AiReport, DeviceInfo, Finding, FirmwareReport, NetworkReport, ScanMetrics

log = get_logger("ai_engine")

_MAX_RETRIES = 3
_RETRY_DELAYS = (1.0, 2.0, 4.0)   # seconds
_CHAT_HISTORY_LIMIT = 20            # keep last N messages to avoid token bloat


class GroqAIEngine:

    def __init__(self):
        self._key: str = settings.GROQ_API_KEY
        self._model: str = settings.GROQ_MODEL

    def set_key(self, key: str):
        self._key = key.strip('"').strip("'").strip()

    @property
    def is_configured(self) -> bool:
        return bool(self._key) and not self._key.startswith("gsk_your_")

    # ── Key validation ────────────────────────────────────────────────────

    async def validate_key(self, key: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(
                    settings.GROQ_API_URL,
                    headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                    json={"model": self._model, "max_tokens": 5, "messages": [{"role": "user", "content": "hi"}]},
                )
                return r.status_code == 200
        except Exception as exc:
            log.warning('"Key validation error: %s"', exc)
            return False

    # ── Core Groq caller with retry ───────────────────────────────────────

    async def _call(
        self,
        messages: list[dict],
        max_tokens: int = 800,
        temperature: float = 0.3,
    ) -> str:
        if not self.is_configured:
            raise ValueError("Groq API key not configured")

        last_exc: Optional[Exception] = None
        for attempt in range(_MAX_RETRIES):
            try:
                async with httpx.AsyncClient(timeout=30) as client:
                    resp = await client.post(
                        settings.GROQ_API_URL,
                        headers={
                            "Authorization": f"Bearer {self._key}",
                            "Content-Type": "application/json",
                        },
                        json={
                            "model": self._model,
                            "max_tokens": max_tokens,
                            "temperature": temperature,
                            "messages": messages,
                        },
                    )
                    if resp.status_code == 429:
                        # Rate limited — back off
                        delay = _RETRY_DELAYS[min(attempt, len(_RETRY_DELAYS) - 1)]
                        log.warning('"Groq rate-limited, waiting %.1fs (attempt %d)"', delay, attempt + 1)
                        await asyncio.sleep(delay)
                        continue
                    if resp.status_code != 200:
                        raise Exception(f"Groq API {resp.status_code}: {resp.text[:300]}")
                    data = resp.json()
                    return data["choices"][0]["message"]["content"]
            except Exception as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES - 1:
                    delay = _RETRY_DELAYS[attempt]
                    log.warning('"Groq call failed (attempt %d): %s — retrying in %.1fs"', attempt + 1, exc, delay)
                    await asyncio.sleep(delay)
        raise RuntimeError(f"Groq call failed after {_MAX_RETRIES} attempts: {last_exc}")

    # ── Scan analysis ─────────────────────────────────────────────────────

    async def analyze_scan(
        self,
        device: DeviceInfo,
        findings: list[Finding],
        metrics: ScanMetrics,
        firmware: FirmwareReport,
        network: NetworkReport,
    ) -> AiReport:
        """Generate AI forensic report from scan results. Returns validated AiReport."""

        findings_text = "\n".join(
            f"- [{f.severity.upper()}] {f.title}: {f.description}"
            for f in findings
        ) or "No threats detected."

        net_suspicious = [
            f"{c.ip}:{c.port}"
            for c in network.connections
            if any(s.description and str(c.ip) in s.description for s in network.suspicious)
        ] or ["None"]

        prompt = f"""You are CyberSentinel AI, a senior mobile forensics and threat intelligence analyst assigned to a government cybercrime unit.

A real scan of an Android device has just completed. Analyze the results and produce an expert forensic report.

DEVICE PROFILE:
- Model: {device.model} ({device.brand})
- Android: {device.android_version} (SDK {device.sdk_version})
- Build Fingerprint: {(device.build_fingerprint or "N/A")[:80]}
- Rooted: {device.rooted}
- USB Mode: {device.usb_mode}

FIRMWARE ANALYSIS:
- Tampered: {firmware.tampered}
- Reason: {firmware.reason or "N/A"}
- Build Type: {firmware.build_type or "N/A"}
- Signing Keys: {firmware.signing_keys or "N/A"}

SCAN METRICS:
- Packages Scanned: {metrics.files_scanned}
- Threats Found: {metrics.threats}
- Risk Score: {metrics.risk_score}/100
- Scan Duration: {metrics.scan_time}s

THREAT FINDINGS:
{findings_text}

NETWORK ANALYSIS:
- Suspicious Connections: {len(network.suspicious)}
- Details: {', '.join(net_suspicious)}

Respond ONLY with a JSON object with exactly these fields (no markdown, no extra text):
{{
  "verdict": "CRITICAL_THREAT" | "HIGH_RISK" | "MEDIUM_RISK" | "LOW_RISK" | "CLEAN",
  "summary": "2-3 sentence expert summary",
  "immediate_actions": ["action 1", "action 2", "action 3"],
  "threat_breakdown": "1-2 sentences on the most dangerous finding",
  "chain_of_custody": "Brief forensic handling recommendation",
  "confidence": 85
}}"""

        raw = await self._call(
            messages=[
                {"role": "system", "content": "You are a forensic cybersecurity AI. Always respond with valid JSON only."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=700,
        )

        return self._parse_ai_report(raw, findings)

    def _parse_ai_report(self, raw: str, findings: list[Finding]) -> AiReport:
        """Parse and validate AI JSON response, with graceful fallback."""
        try:
            clean = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
            data = json.loads(clean)
            return AiReport(**data)
        except Exception as exc:
            log.warning('"AI report parse error: %s — using fallback"', exc)
            has_critical = any(f.severity == "critical" for f in findings)
            has_threats = bool(findings)
            return AiReport(
                verdict="CRITICAL_THREAT" if has_critical else ("HIGH_RISK" if has_threats else "CLEAN"),
                summary=raw[:300] if raw else f"Scan complete. {len(findings)} threats found.",
                immediate_actions=[
                    "Isolate device immediately" if has_threats else "Device appears clean",
                    "Place in RF-shielding bag",
                    "Generate forensic image with write-blocker",
                ],
                threat_breakdown="Review individual threat findings in the dashboard." if has_threats else "No active firmware or package anomalies.",
                chain_of_custody="Store evidence device in static-shielded environment. Document chain of custody.",
                confidence=70,
            )

    # ── AI Chat ───────────────────────────────────────────────────────────

    async def chat(
        self,
        history: list[dict],
        scan_context: dict,
    ) -> str:
        """
        Context-aware forensic chat.
        history: list of {role, content} dicts
        scan_context: {device, findings, metrics, ...}
        """
        device = scan_context.get("device", {})
        findings = scan_context.get("findings", [])
        metrics = scan_context.get("metrics", {})

        system_prompt = f"""You are CyberSentinel AI — an expert mobile forensics and cybersecurity analyst embedded in a government forensic team.

Current scan context:
- Device: {device.get('model', 'Unknown')} running Android {device.get('android_version', '?')}
- Threats found: {metrics.get('threats', 0)}
- Risk score: {metrics.get('risk_score', 0)}/100
- Key findings: {', '.join(f['title'] for f in findings[:5]) if findings else 'None detected'}

Answer the investigator's questions accurately and concisely. Be technical but clear. Limit responses to 150 words unless the question requires more detail."""

        # Cap history to avoid token bloat
        trimmed = history[-_CHAT_HISTORY_LIMIT:] if len(history) > _CHAT_HISTORY_LIMIT else history
        messages = [{"role": "system", "content": system_prompt}] + trimmed

        return await self._call(messages, max_tokens=300, temperature=0.4)
