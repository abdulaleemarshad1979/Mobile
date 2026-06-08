"""CyberSentinel — Production FastAPI v3"""
from __future__ import annotations
import asyncio, json
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from ai_engine import GroqAIEngine
from config import settings
from logger import get_logger
from models import AiReport, DeviceListResponse, Finding, FirmwareReport, HealthResponse, NetworkReport, ScanMetrics, ScanReport, UsbReport
from scanner import DeviceScanner
from ws_manager import manager

log = get_logger("main")
HTML_PATH = Path(__file__).parent / "cybersentinel_v3.html"
if not HTML_PATH.exists():
    HTML_PATH = Path(__file__).parent / "cybersentinel_v2.html"

_last_reports: dict[str, ScanReport] = {}

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info('"CyberSentinel %s starting — env=%s groq=%s vt=%s adb=%s"', settings.VERSION, settings.APP_ENV, settings.groq_configured, settings.vt_configured, scanner.adb_available)
    yield
    log.info('"CyberSentinel shutting down"')

app = FastAPI(title=settings.TITLE, version=settings.VERSION, docs_url="/docs" if not settings.is_production else None, redoc_url=None, lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=settings.CORS_ORIGINS, allow_credentials=True, allow_methods=["GET","POST"], allow_headers=["*"])
scanner = DeviceScanner()
ai_engine = GroqAIEngine()

@app.get("/", include_in_schema=False)
async def serve_dashboard():
    if HTML_PATH.exists(): return FileResponse(HTML_PATH)
    return JSONResponse({"error": "Dashboard HTML not found"}, status_code=404)

@app.get("/health", response_model=HealthResponse)
async def health():
    return HealthResponse(status="ok", version=settings.VERSION, groq_configured=settings.groq_configured, adb_available=scanner.adb_available, vt_configured=settings.vt_configured, active_ws_connections=manager.count)

@app.get("/api/devices", response_model=DeviceListResponse)
async def get_devices():
    devices = await asyncio.to_thread(scanner.get_connected_devices)
    return DeviceListResponse(devices=devices, adb_available=scanner.adb_available, count=len(devices))

@app.get("/api/export/{fmt}")
async def export_report(fmt: str, serial: str = ""):
    if not serial or serial=="DEMO-0047" or serial.startswith("demo"):
        return JSONResponse({"error": "No real device serial provided."}, status_code=400)
    report = _last_reports.get(serial)
    if not report: return JSONResponse({"error": "No scan report found."}, status_code=404)
    if fmt == "json": return JSONResponse(report.model_dump(mode="json"))
    elif fmt == "txt":
        lines = [f"CyberSentinel Forensic Report v{settings.VERSION}", f"Device: {report.device.model} ({report.device.brand}) — Android {report.device.android_version}", f"Serial: {report.device.device_serial}", f"Risk score: {report.metrics.risk_score}/100  |  Threats: {report.metrics.threats}  |  Scan time: {report.metrics.scan_time}s", "", "── FIRMWARE ──", f"Tampered: {report.firmware.tampered}", f"Reason: {report.firmware.reason or 'N/A'}", "", "── FINDINGS ──"]
        for f in report.findings:
            lines.append(f"[{f.severity.upper()}] {f.title}"); lines.append(f"  {f.description}")
            if f.signature: lines.append(f"  Signature: {f.signature}")
            if f.mitre_id: lines.append(f"  MITRE: {f.mitre_id}")
            lines.append("")
        if report.ai_report:
            lines += ["── AI ANALYSIS ──", f"Verdict: {report.ai_report.verdict}", f"Summary: {report.ai_report.summary}", "Immediate Actions:", *[f"  • {a}" for a in report.ai_report.immediate_actions], f"Chain of Custody: {report.ai_report.chain_of_custody}"]
        return PlainTextResponse("\n".join(lines))
    return JSONResponse({"error": "Use json or txt"}, status_code=400)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    log.error('"Unhandled exception on %s: %s"', request.url.path, exc)
    return JSONResponse({"error":"Internal server error","detail":str(exc) if not settings.is_production else ""}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    if not await manager.connect(ws): return
    settings.reload(); ai_engine.set_key(settings.GROQ_API_KEY)
    await manager.send_json(ws, {"type":"init","adb_available":scanner.adb_available,"groq_configured":ai_engine.is_configured,"vt_configured":settings.vt_configured,"version":settings.VERSION})
    scan_context: dict = {}; chat_history: list[dict] = []; active_scan_task: asyncio.Task|None = None

    async def poll_devices():
        last=None
        while True:
            try:
                devices=await asyncio.to_thread(scanner.get_connected_devices)
                if devices!=last:
                    await manager.send_json(ws,{"type":"devices_list","devices":devices})
                    last=devices
                    # Log unauthorized devices to help user
                    for d in devices:
                        if d.get("needs_auth") or d.get("status")=="unauthorized":
                            await manager.send_json(ws,{"type":"log","level":"warn","tag":"[USB]","message":f"Device {d['serial']} connected but UNAUTHORIZED — tap Allow on phone screen!","threat":False})
                await asyncio.sleep(2)
            except asyncio.CancelledError: return
            except Exception as e: log.warning('"Poll error: %s"',e); await asyncio.sleep(5)

    poller=asyncio.create_task(poll_devices())
    try:
        while True:
            raw=await ws.receive_text()
            try: msg=json.loads(raw)
            except json.JSONDecodeError: await manager.send_json(ws,{"type":"error","message":"Invalid JSON"}); continue
            action=msg.get("action")
            if action=="start_scan":
                serial=(msg.get("device_serial") or "").strip()
                if not serial or len(serial)>64: await manager.send_json(ws,{"type":"error","message":"Invalid device_serial"}); continue
                if serial=="DEMO-0047" or serial.startswith("demo"): await manager.send_json(ws,{"type":"error","message":"Demo devices are disabled. Connect a real Android device."}); continue
                if active_scan_task and not active_scan_task.done(): active_scan_task.cancel()
                active_scan_task=asyncio.create_task(_run_full_scan(ws,serial,scan_context,chat_history))
            elif action=="chat":
                user_msg=(msg.get("message") or "").strip()
                if not user_msg: continue
                if len(user_msg)>2000: await manager.send_json(ws,{"type":"error","message":"Message too long"}); continue
                asyncio.create_task(_handle_chat(ws,user_msg,chat_history,scan_context))
            elif action=="update_config":
                new_key=(msg.get("groq_api_key") or "").strip()
                if new_key and len(new_key)>10:
                    ai_engine.set_key(new_key); valid=await ai_engine.validate_key(new_key)
                    await manager.send_json(ws,{"type":"config_updated","groq_configured":valid,"message":"API key accepted." if valid else "API key validation failed."})
            else: await manager.send_json(ws,{"type":"error","message":f"Unknown action: {action}"})
    except WebSocketDisconnect: log.info('"WS client disconnected"')
    except Exception as e: log.error('"WS handler error: %s"',e)
    finally:
        poller.cancel()
        if active_scan_task and not active_scan_task.done(): active_scan_task.cancel()
        await manager.disconnect(ws)

async def _run_full_scan(ws,serial,scan_context,chat_history):
    loop_start=asyncio.get_event_loop().time(); findings=[]
    async def send(p): await manager.send_json(ws,p)
    async def log_msg(phase,msg,level="info",tag="[SYS]",threat=False):
        await send({"type":"status","phase":phase,"log":msg}); await send({"type":"log","level":level,"tag":tag,"message":msg,"threat":threat})
    try:
        await log_msg("Detecting device...","Enumerating USB connection...",tag="[USB]")
        usb=await asyncio.wait_for(asyncio.to_thread(scanner.analyze_usb_descriptors,serial),timeout=settings.SCAN_TIMEOUT)
        if usb.suspicious:
            findings.append(_fd("Suspicious USB Enumeration",f"Dual HID + Mass Storage (config: {usb.usb_config}). Possible BadUSB.","critical","badusb","USB-DUAL-HID-001"))
            await send({"type":"log","level":"danger","tag":"[USB]","message":"Dual HID + Mass Storage — possible BadUSB!","threat":True})
        else: await send({"type":"log","level":"info","tag":"[USB]","message":f"USB mode: {usb.mode}"})
        await log_msg("Reading device profile...","Extracting ADB properties...",tag="[DEV]")
        device_info=await asyncio.wait_for(asyncio.to_thread(scanner.get_device_info,serial),timeout=settings.SCAN_TIMEOUT)
        await send({"type":"device_info","data":{"model":device_info.model,"os":f"Android {device_info.android_version} (SDK {device_info.sdk_version})","serial":device_info.device_serial or serial,"imei":device_info.imei,"conn":f"{device_info.connection} · {device_info.usb_mode}","fw":"TAMPERED" if (device_info.build_tampered or device_info.rooted) else "VERIFIED","risk":"HIGH" if (device_info.rooted or device_info.build_tampered) else "UNKNOWN","battery":device_info.battery,"cpu":device_info.cpu_arch}})
        await send({"type":"log","level":"info","tag":"[DEV]","message":f"{device_info.manufacturer} {device_info.model} · Android {device_info.android_version} · {device_info.cpu_arch}"})
        if device_info.rooted:
            findings.append(_fd("Root Access Enabled","Active root privileges (su binary) detected — Android sandbox bypassed.","high","root","ROOT-SU-001"))
            await send({"type":"log","level":"danger","tag":"[WARN]","message":"Device is ROOTED — su binary active!","threat":True})
        await log_msg("Verifying firmware...","Verifying boot signature hashes...",tag="[FW]")
        fw=await asyncio.wait_for(asyncio.to_thread(scanner.check_firmware_integrity,serial),timeout=settings.SCAN_TIMEOUT)
        if fw.tampered:
            findings.append(_fd("Firmware Tampering Detected",fw.reason or "Signature mismatch","critical","firmware","FW-TAMPER-001"))
            await send({"type":"log","level":"danger","tag":"[FW]","message":f"Firmware tampered: {fw.reason}","threat":True})
        else: await send({"type":"log","level":"info","tag":"[FW]","message":"Firmware fingerprint verified — no tampering detected."})
        await log_msg("Checking network beacons...","Analyzing active sockets...",tag="[NET]")
        network=await asyncio.wait_for(asyncio.to_thread(scanner.check_network_beacons,serial),timeout=settings.SCAN_TIMEOUT)
        if network.error: await send({"type":"log","level":"warn","tag":"[NET]","message":f"Network check limited: {network.error}"})
        else:
            await send({"type":"log","level":"info","tag":"[NET]","message":f"Inspected {len(network.connections)} active socket(s)."})
            for sus in network.suspicious: findings.append(sus.model_dump()); await send({"type":"log","level":"danger","tag":"[NET]","message":f"C2 beacon: {sus.description}","threat":True})
        await log_msg("Scanning applications...","Extracting package manifests...",tag="[APK]")
        files_scanned=0
        async for progress in scanner.scan_apks_stream(serial):
            files_scanned=progress.get("count",0)
            for f in progress.get("findings",[]):
                findings.append(f); await send({"type":"log","level":"danger","tag":"[MAL]","message":f"Threat: {f.get('title')} ({f.get('package','?')})","threat":True})
            pkg=progress.get("package")
            if pkg: await send({"type":"apk_scan_progress","current":files_scanned,"total":progress.get("total",0),"package":pkg})
        await log_msg("AI threat analysis...","Sending forensic data to Groq...",tag="[AI]")
        scan_time=round(asyncio.get_event_loop().time()-loop_start,1)
        risk_score=DeviceScanner.calculate_risk_score(findings)
        metrics=ScanMetrics(files_scanned=files_scanned,threats=len(findings),risk_score=risk_score,scan_time=scan_time)
        ai_report=None
        if ai_engine.is_configured:
            try:
                typed=[Finding(**f) if isinstance(f,dict) else f for f in findings]
                ai_report=await ai_engine.analyze_scan(device_info,typed,metrics,fw,network)
            except Exception as e: log.error('"AI failed: %s"',e)
        if not ai_report:
            has_threats=bool(findings)
            ai_report=AiReport(verdict="CRITICAL_THREAT" if risk_score>90 else ("HIGH_RISK" if has_threats else "CLEAN"),summary=f"Scan complete. {len(findings)} threat(s) across {files_scanned} packages.",immediate_actions=["Isolate device immediately" if has_threats else "Device appears clean","Place in RF-shielding bag","Generate forensic image with write-blocker"],threat_breakdown="Review threat findings below." if has_threats else "No anomalies detected.",chain_of_custody="Store evidence device in static-shielded environment.",confidence=75)
        scan_context.clear()
        scan_context.update({"device":device_info.model_dump(),"findings":findings,"metrics":metrics.model_dump(),"firmware":fw.model_dump(),"network":network.model_dump(mode="json")})
        chat_history.clear()
        _last_reports[serial]=ScanReport(device=device_info,usb=usb,firmware=fw,network=network,findings=[Finding(**f) if isinstance(f,dict) else f for f in findings],metrics=metrics,ai_report=ai_report)
        await send({"type":"scan_complete","metrics":metrics.model_dump(),"findings":findings,"ai_report":ai_report.model_dump()})
        done_msg="DEVICE IS CLEAN — safe for forensic analysis." if not findings else f"{len(findings)} THREAT(S) DETECTED — DEVICE QUARANTINED. DO NOT CONNECT."
        await send({"type":"log","level":"ok" if not findings else "danger","tag":"[DONE]","message":done_msg,"clean":not findings,"threat":bool(findings)})
    except asyncio.CancelledError: await send({"type":"error","message":"Scan cancelled."})
    except asyncio.TimeoutError: await send({"type":"error","message":"Scan phase timed out — check ADB connection."})
    except Exception as e: log.error('"Scan failed: %s"',e); await send({"type":"error","message":f"Scan failed: {e}"})

async def _handle_chat(ws,user_msg,history,scan_context):
    await manager.send_json(ws,{"type":"chat_status","status":"thinking"})
    try:
        history.append({"role":"user","content":user_msg})
        reply=await ai_engine.chat(history,scan_context) if ai_engine.is_configured else "Groq API key not configured. Add GROQ_API_KEY to .env to enable AI chat."
        history.append({"role":"assistant","content":reply})
        await manager.send_json(ws,{"type":"chat_reply","message":reply})
    except Exception as e: log.error('"Chat error: %s"',e); await manager.send_json(ws,{"type":"chat_reply","message":f"AI error: {e}"})

_ICON_MAP={"critical":"shield-bolt","high":"shield-alert","medium":"alert-triangle","low":"info"}
_CLS_MAP={"critical":"crit","high":"high","medium":"med","low":"low"}
def _fd(title,description,severity,category,signature,package=None) -> dict:
    return dict(title=title,description=description,severity=severity,category=category,signature=signature,package=package,cls=_CLS_MAP.get(severity,"high"),badge=severity.upper(),icon=_ICON_MAP.get(severity,"shield-alert"),source="CyberSentinel")
