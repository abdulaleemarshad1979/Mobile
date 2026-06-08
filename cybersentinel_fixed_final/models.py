"""CyberSentinel — Data Models v3"""
from __future__ import annotations
from typing import Literal, Optional
from pydantic import BaseModel, Field

class WsStartScan(BaseModel):
    action: Literal["start_scan"]
    device_serial: str = Field(..., min_length=1, max_length=64)

class WsChatMessage(BaseModel):
    action: Literal["chat"]
    message: str = Field(..., min_length=1, max_length=2000)

class WsConfigUpdate(BaseModel):
    action: Literal["update_config"]
    groq_api_key: str = Field(..., min_length=10)

class DeviceInfo(BaseModel):
    model: str = "Unknown"
    brand: str = "Unknown"
    manufacturer: str = "Unknown"
    android_version: str = "?"
    sdk_version: str = "?"
    build_fingerprint: str = "N/A"
    build_type: str = "unknown"
    build_tags: str = "unknown"
    serial_number: str = "N/A"
    imei: str = "N/A"
    usb_mode: str = "Unknown"
    battery: str = "N/A"
    cpu_arch: str = "Unknown"
    rooted: bool = False
    build_tampered: bool = False
    connection: str = "USB"
    device_serial: str = ""
    scan_timestamp: str = ""

class Finding(BaseModel):
    title: str
    description: str
    severity: Literal["critical", "high", "medium", "low"]
    category: str
    signature: str
    package: Optional[str] = None
    mitre_id: Optional[str] = None
    source: str = "CyberSentinel"
    cls: str = "high"
    badge: str = "HIGH"
    icon: str = "shield-alert"

class NetworkConnection(BaseModel):
    ip: str
    port: int
    raw: str = ""

class NetworkReport(BaseModel):
    connections: list[NetworkConnection] = []
    suspicious: list[Finding] = []
    error: Optional[str] = None

class FirmwareReport(BaseModel):
    tampered: bool = False
    reason: Optional[str] = None
    fingerprint: Optional[str] = None
    fingerprint_hash: Optional[str] = None
    build_type: Optional[str] = None
    signing_keys: Optional[str] = None

class UsbReport(BaseModel):
    mode: str = "Unknown"
    usb_config: str = ""
    hid_detected: bool = False
    mass_storage: bool = False
    adb_interface: bool = False
    dual_hid_storage: bool = False
    suspicious: bool = False

class ScanMetrics(BaseModel):
    files_scanned: int = 0
    packages_total: int = 0
    threats: int = 0
    risk_score: int = 0
    scan_time: float = 0.0

class AiReport(BaseModel):
    verdict: Literal["CRITICAL_THREAT", "HIGH_RISK", "MEDIUM_RISK", "LOW_RISK", "CLEAN"]
    summary: str
    immediate_actions: list[str]
    threat_breakdown: str
    chain_of_custody: str
    confidence: int = Field(ge=0, le=100)

class DeviceListResponse(BaseModel):
    devices: list[dict]
    adb_available: bool
    count: int

class HealthResponse(BaseModel):
    status: str
    version: str
    groq_configured: bool
    adb_available: bool
    vt_configured: bool = False
    active_ws_connections: int

class ScanReport(BaseModel):
    device: DeviceInfo
    usb: UsbReport
    firmware: FirmwareReport
    network: NetworkReport
    findings: list[Finding]
    metrics: ScanMetrics
    ai_report: Optional[AiReport] = None
