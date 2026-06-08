"""
CyberSentinel — ADB Scanner v3
New: Heuristic scoring, VirusTotal hash check, demo mode with IOC hits, MITRE-mapped findings
"""
from __future__ import annotations
import asyncio, hashlib, re, shutil, subprocess, time
from pathlib import Path
from typing import AsyncGenerator, Optional
import httpx
from config import settings
from logger import get_logger
from models import DeviceInfo, Finding, FirmwareReport, NetworkReport, NetworkConnection, UsbReport, ScanMetrics
from threat_db import (
    MALWARE_PACKAGES, DANGEROUS_PERMISSIONS, SPYWARE_COMBOS,
    KNOWN_C2_IPS, SUSPICIOUS_PORTS, TRUSTED_SYSTEM_PREFIXES, SUSPICIOUS_KEYWORDS,
)

log = get_logger("scanner")
_SEV_MAP = {"critical":("crit","CRITICAL","shield-bolt"),"high":("high","HIGH","shield-alert"),"medium":("med","MEDIUM","alert-triangle"),"low":("low","LOW","info")}
_VT_FILE_REPORT = "https://www.virustotal.com/api/v3/files/{}"

def _make_finding(title,description,severity,category,signature,package=None,mitre_id=None,source="CyberSentinel") -> Finding:
    cls,badge,icon = _SEV_MAP.get(severity,("high","HIGH","shield-alert"))
    return Finding(title=title,description=description,severity=severity,category=category,signature=signature,package=package,cls=cls,badge=badge,icon=icon,mitre_id=mitre_id,source=source)

# ── Demo data ──────────────────────────────────────────────────────────────
_DEMO_PACKAGES = [
    {"path":"/data/app/com.android.chrome-1.apk","name":"com.android.chrome"},
    {"path":"/data/app/com.google.android.gms-1.apk","name":"com.google.android.gms"},
    {"path":"/data/app/com.instagram.android-1.apk","name":"com.instagram.android"},
    {"path":"/data/app/com.spotify.music-1.apk","name":"com.spotify.music"},
    {"path":"/data/app/com.netflix.mediaclient-1.apk","name":"com.netflix.mediaclient"},
    {"path":"/data/app/com.amazon.mShop.android-1.apk","name":"com.amazon.mShop.android"},
    {"path":"/data/app/com.snapchat.android-1.apk","name":"com.snapchat.android"},
    {"path":"/data/app/com.thetruth-1.apk","name":"com.thetruth"},
    {"path":"/data/app/com.spynote.v6-1.apk","name":"com.spynote.v6"},
    {"path":"/data/app/com.cerberus.android-1.apk","name":"com.cerberus.android"},
    {"path":"/data/app/com.android.system.logger-1.apk","name":"com.android.system.logger"},
    {"path":"/data/app/com.util.background.service-1.apk","name":"com.util.background.service"},
    {"path":"/data/app/com.duolingo.app-1.apk","name":"com.duolingo.app"},
    {"path":"/data/app/com.ubercab-1.apk","name":"com.ubercab"},
    {"path":"/data/app/com.canva.editor-1.apk","name":"com.canva.editor"},
]
_DEMO_PERMS: dict[str,list[str]] = {
    "com.thetruth":["android.permission.RECORD_AUDIO","android.permission.ACCESS_FINE_LOCATION","android.permission.ACCESS_BACKGROUND_LOCATION","android.permission.READ_CONTACTS","android.permission.READ_SMS","android.permission.RECEIVE_SMS","android.permission.READ_CALL_LOG","android.permission.CAMERA","android.permission.RECEIVE_BOOT_COMPLETED","android.permission.BIND_DEVICE_ADMIN"],
    "com.spynote.v6":["android.permission.RECORD_AUDIO","android.permission.ACCESS_FINE_LOCATION","android.permission.READ_SMS","android.permission.CAMERA","android.permission.BIND_DEVICE_ADMIN","android.permission.INSTALL_PACKAGES"],
    "com.cerberus.android":["android.permission.BIND_ACCESSIBILITY_SERVICE","android.permission.READ_SMS","android.permission.RECEIVE_SMS","android.permission.BIND_NOTIFICATION_LISTENER","android.permission.SYSTEM_ALERT_WINDOW","android.permission.RECEIVE_BOOT_COMPLETED"],
    "com.android.system.logger":["android.permission.RECORD_AUDIO","android.permission.ACCESS_FINE_LOCATION","android.permission.RECEIVE_BOOT_COMPLETED","android.permission.SYSTEM_ALERT_WINDOW","android.permission.READ_SMS"],
    "com.util.background.service":["android.permission.BIND_ACCESSIBILITY_SERVICE","android.permission.SYSTEM_ALERT_WINDOW","android.permission.RECEIVE_BOOT_COMPLETED","android.permission.BIND_DEVICE_ADMIN"],
}
_DEMO_DEVICE = DeviceInfo(model="Pixel 6",brand="Google",manufacturer="Google",android_version="13",sdk_version="33",build_fingerprint="google/raven/raven:13/TQ3A.230805.001/test-keys",serial_number="DEMO-0047",cpu_arch="arm64-v8a",build_type="userdebug",build_tags="test-keys",imei="DEMO — root required",usb_mode="adb",battery="78%",rooted=True,build_tampered=True,connection="USB",device_serial="DEMO-0047",scan_timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"))
_DEMO_USB = UsbReport(mode="adb",usb_config="adb",hid_detected=False,mass_storage=False,adb_interface=True,dual_hid_storage=False,suspicious=False)
_DEMO_FW = FirmwareReport(tampered=True,reason="Build signed with test-keys · userdebug build type",fingerprint="google/raven/raven:13/TQ3A.230805.001/test-keys",fingerprint_hash="3f2d1a7b",build_type="userdebug",signing_keys="test-keys")
_DEMO_NET_CONNS = [NetworkConnection(ip="69.64.74.239",port=4444,raw="tcp ESTABLISHED 10.0.2.15:50234 69.64.74.239:4444"),NetworkConnection(ip="8.8.8.8",port=443,raw="tcp ESTABLISHED 10.0.2.15:51200 8.8.8.8:443")]


class DeviceScanner:
    def __init__(self):
        self.adb_path: Optional[str] = self._find_adb()
        if not self.adb_path:
            log.info("ADB not found in standard paths. Attempting to download Google ADB Platform Tools...")
            self.adb_path = self._download_adb()
            
        self.adb_available: bool = self.adb_path is not None
        if self.adb_available:
            log.info("ADB found/installed at %s", self.adb_path)
        else:
            log.warning("ADB not found — demo mode active")

    def _download_adb(self) -> Optional[str]:
        import urllib.request
        import zipfile
        import sys
        import os
        
        is_wsl = self._is_wsl()
        
        # In WSL we MUST download the Windows version because the Linux
        # adb binary cannot access USB devices on the Windows host.
        if is_wsl:
            url = "https://dl.google.com/android/repository/platform-tools-latest-windows.zip"
            adb_name = "adb.exe"
        elif sys.platform == "win32":
            url = "https://dl.google.com/android/repository/platform-tools-latest-windows.zip"
            adb_name = "adb.exe"
        elif sys.platform == "darwin":
            url = "https://dl.google.com/android/repository/platform-tools-latest-darwin.zip"
            adb_name = "adb"
        elif sys.platform.startswith("linux"):
            url = "https://dl.google.com/android/repository/platform-tools-latest-linux.zip"
            adb_name = "adb"
        else:
            log.warning("Automated ADB download is not supported on platform: %s", sys.platform)
            return None
            
        bin_dir = Path(__file__).parent / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        
        # Check if already downloaded
        extracted_adb = bin_dir / "platform-tools" / adb_name
        if extracted_adb.exists():
            log.info("ADB already downloaded at %s", extracted_adb)
            return str(extracted_adb)
        
        zip_path = bin_dir / "platform-tools.zip"
        
        log.info("Downloading official Google platform-tools from %s...", url)
        try:
            urllib.request.urlretrieve(url, zip_path)
            log.info("Download completed successfully. Extracting zip archive...")
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(bin_dir)
                
            zip_path.unlink()
            log.info("Extraction complete. Cleaning up zip archive.")
            
            if extracted_adb.exists():
                if not is_wsl and sys.platform != "win32":
                    extracted_adb.chmod(0o755)
                return str(extracted_adb)
            else:
                log.error("ADB executable not found in extracted directory structure!")
        except Exception as e:
            log.error("Failed to automatically download and extract ADB: %s", e)
            
        return None

    def _find_adb(self) -> Optional[str]:
        import os
        is_wsl = self._is_wsl()

        # When running in WSL, we MUST use the Windows adb.exe because
        # Linux adb inside WSL cannot access USB devices attached to the
        # Windows host.  We search for the Windows binary first.
        if is_wsl:
            log.info("WSL detected — searching for Windows adb.exe (Linux adb cannot access host USB)")
            win_adb = self._find_windows_adb_from_wsl()
            if win_adb:
                return win_adb
            # If no Windows adb.exe found, fall through to auto-download
            # (which will download the Linux version — not ideal in WSL,
            # but the download path also checks for the .exe variant).
            return None

        # --- Native Windows or native Linux/macOS ---
        p = shutil.which("adb")
        if p: return p
        # Check local download directory (both variants)
        for name in ("adb.exe", "adb"):
            local_adb = Path(__file__).parent / "bin" / "platform-tools" / name
            if local_adb.exists(): return str(local_adb)
        # Check ANDROID_HOME / ANDROID_SDK_ROOT env vars
        for env_var in ("ANDROID_HOME", "ANDROID_SDK_ROOT", "ANDROID_SDK"):
            sdk = os.environ.get(env_var)
            if sdk:
                candidate = Path(sdk) / "platform-tools" / ("adb.exe" if os.name == "nt" else "adb")
                if candidate.exists(): return str(candidate)
        # Check %LOCALAPPDATA%\Android\Sdk
        local_app = os.environ.get("LOCALAPPDATA", "")
        if local_app:
            p2 = Path(local_app) / "Android" / "Sdk" / "platform-tools" / "adb.exe"
            if p2.exists(): return str(p2)
        # Fixed candidates (expanded)
        candidates = [
            r"C:\platform-tools\adb.exe",
            r"C:\Android\platform-tools\adb.exe",
            r"C:\Program Files\Android\platform-tools\adb.exe",
        ]
        for c in candidates:
            if Path(os.path.expandvars(c)).exists(): return os.path.expandvars(c)
        return None

    @staticmethod
    def _is_wsl() -> bool:
        """Detect if we are running inside Windows Subsystem for Linux."""
        try:
            with open("/proc/version", "r") as f:
                return "microsoft" in f.read().lower()
        except Exception:
            return False

    def _find_windows_adb_from_wsl(self) -> Optional[str]:
        """Find Windows adb.exe accessible from WSL via /mnt/c paths."""
        import os
        candidates = [
            # Our own downloaded copy (Windows version)
            Path(__file__).parent / "bin" / "platform-tools" / "adb.exe",
            # Common Windows install locations via WSL mount
            Path("/mnt/c/platform-tools/adb.exe"),
            Path("/mnt/c/Android/platform-tools/adb.exe"),
            Path("/mnt/c/Program Files/Android/platform-tools/adb.exe"),
        ]
        # Check LOCALAPPDATA via WSL
        username = os.environ.get("USER", "")
        if username:
            candidates.append(Path(f"/mnt/c/Users/{username}/AppData/Local/Android/Sdk/platform-tools/adb.exe"))
        # Also try to find it via `which adb.exe`
        p = shutil.which("adb.exe")
        if p: return p
        for c in candidates:
            if c.exists():
                return str(c)
        return None

    def _run_adb(self,*args,serial=None,timeout=30):
        if not self.adb_path: return -1,"","ADB not available"
        cmd=[self.adb_path]
        if serial: cmd+=["-s",serial]
        cmd+=list(args)
        try:
            r=subprocess.run(cmd,capture_output=True,text=True,timeout=timeout,encoding="utf-8",errors="replace")
            return r.returncode,r.stdout.strip(),r.stderr.strip()
        except subprocess.TimeoutExpired:
            return -1,"",f"Timed out after {timeout}s"
        except Exception as e:
            return -1,"",str(e)

    def get_connected_devices(self) -> list[dict]:
        if not self.adb_path:
            return []  # No ADB — return empty list, no fake demo devices
        # Always restart ADB server to re-detect freshly connected devices
        self._run_adb("start-server", timeout=8)
        rc,out,_=self._run_adb("devices","-l",timeout=10)
        if rc!=0: return []
        devices=[]
        for line in out.splitlines()[1:]:
            line=line.strip()
            if not line: continue
            parts=line.split()
            if len(parts)<2: continue
            serial=parts[0]
            status=parts[1]
            if status=="unauthorized":
                # Device connected but waiting for USB debugging authorization tap
                devices.append({"serial":serial,"status":"unauthorized","model":"Tap ALLOW on phone","transport":"USB","needs_auth":True})
                continue
            if status=="offline":
                # Device detected but offline — could be reconnecting
                devices.append({"serial":serial,"status":"offline","model":"Device offline — reconnect USB","transport":"USB","needs_auth":False})
                continue
            if status not in ("device","recovery"):
                continue
            info={"serial":serial,"status":status,"model":"Android Device","transport":"USB","needs_auth":False}
            for p in parts[2:]:
                if p.startswith("model:"): info["model"]=p.split(":",1)[1].replace("_"," ")
            devices.append(info)
        return devices

    def get_device_info(self,serial:str) -> DeviceInfo:
        if serial=="DEMO-0047": return _DEMO_DEVICE
        prop_map={"ro.product.model":"model","ro.product.brand":"brand","ro.product.manufacturer":"manufacturer","ro.build.version.release":"android_version","ro.build.version.sdk":"sdk_version","ro.build.fingerprint":"build_fingerprint","ro.serialno":"serial_number","ro.product.cpu.abi":"cpu_arch","ro.build.type":"build_type","ro.build.tags":"build_tags"}
        raw={}
        for prop,key in prop_map.items():
            rc,out,_=self._run_adb("shell","getprop",prop,serial=serial,timeout=5)
            if rc==0 and out: raw[key]=out.strip()
        rc,out,_=self._run_adb("shell","getprop","sys.usb.config",serial=serial,timeout=5)
        raw["usb_mode"]=out.strip() if rc==0 else "Unknown"
        rc,out,_=self._run_adb("shell","dumpsys","battery",serial=serial,timeout=8)
        m=re.search(r"level:\s*(\d+)",out)
        raw["battery"]=f"{m.group(1)}%" if m else "N/A"
        rc,out,_=self._run_adb("shell","which","su",serial=serial,timeout=5)
        raw["rooted"]=rc==0 and bool(out)
        tags=raw.get("build_tags","")
        raw["build_tampered"]="test-keys" in tags or "dev-keys" in tags
        raw["connection"]="WiFi/Network" if (serial.startswith("192.")|serial.startswith("10.")) else "USB"
        raw["device_serial"]=serial
        raw["scan_timestamp"]=time.strftime("%Y-%m-%dT%H:%M:%S")
        raw["imei"]="N/A"
        return DeviceInfo(**{k:v for k,v in raw.items() if k in DeviceInfo.model_fields})

    def analyze_usb_descriptors(self,serial:str) -> UsbReport:
        if serial=="DEMO-0047": return _DEMO_USB
        rc,state,_=self._run_adb("shell","getprop","sys.usb.state",serial=serial,timeout=5)
        rc2,config,_=self._run_adb("shell","getprop","sys.usb.config",serial=serial,timeout=5)
        state=state.lower() if rc==0 else ""
        hid="hid" in state; ms="mass_storage" in state; adb_if="adb" in state; dual=hid and ms
        return UsbReport(mode=state or "Unknown",usb_config=config.strip() if rc2==0 else "",hid_detected=hid,mass_storage=ms,adb_interface=adb_if,dual_hid_storage=dual,suspicious=dual or (hid and not adb_if))

    def check_firmware_integrity(self,serial:str) -> FirmwareReport:
        if serial=="DEMO-0047": return _DEMO_FW
        props={}
        for prop,key in [("ro.build.fingerprint","fingerprint"),("ro.build.type","build_type"),("ro.build.tags","build_tags"),("ro.secure","secure"),("ro.debuggable","debuggable")]:
            rc,out,_=self._run_adb("shell","getprop",prop,serial=serial,timeout=5)
            if rc==0 and out: props[key]=out.strip()
        fp=props.get("fingerprint",""); bt=props.get("build_type",""); tags=props.get("build_tags","")
        reasons=[]
        if "test-keys" in tags: reasons.append("Signed with test-keys")
        if "dev-keys" in tags: reasons.append("Signed with dev-keys")
        if "userdebug" in bt: reasons.append("Debug build type (userdebug)")
        if props.get("secure")=="0": reasons.append("ro.secure=0 — insecure system partition")
        for binary in ("/system/xbin/su","/sbin/su"):
            rc,_,_=self._run_adb("shell","ls",binary,serial=serial,timeout=5)
            if rc==0: reasons.append(f"Suspicious binary: {binary}")
        return FirmwareReport(tampered=bool(reasons),reason=" · ".join(reasons) if reasons else "No tampering detected",fingerprint=fp or None,fingerprint_hash=hashlib.sha256(fp.encode()).hexdigest()[:16] if fp else None,build_type=bt or None,signing_keys=tags or None)

    def check_network_beacons(self,serial:str) -> NetworkReport:
        if serial=="DEMO-0047":
            suspicious=[]
            for conn in _DEMO_NET_CONNS:
                if conn.ip in KNOWN_C2_IPS:
                    suspicious.append(_make_finding("C2 Beacon Detected",f"Active connection to {conn.ip}:{conn.port} — known TheTruthSpy stalkerware C2 infrastructure.","critical","c2_beacon","NET-C2-BEACON"))
                elif conn.port in SUSPICIOUS_PORTS:
                    suspicious.append(_make_finding("Suspicious Port Connection",f"Active connection to {conn.ip}:{conn.port} — port {conn.port} is a common RAT/C2 port.","high","c2_beacon","NET-SUSP-PORT"))
            return NetworkReport(connections=_DEMO_NET_CONNS,suspicious=suspicious)
        rc,out,_=self._run_adb("shell","netstat","-tn",serial=serial,timeout=15)
        if rc!=0: rc,out,_=self._run_adb("shell","ss","-tn",serial=serial,timeout=15)
        if rc!=0: return NetworkReport(error="Cannot read network connections")
        connections=[]; suspicious=[]
        for line in out.splitlines():
            parts=line.split(); remote=""
            for part in parts:
                if re.match(r"\d+\.\d+\.\d+\.\d+:\d+",part) and not part.startswith(("0.0.0.0","127.")): remote=part; break
            if not remote: continue
            ip,port_str=remote.rsplit(":",1)
            try: port=int(port_str)
            except ValueError: continue
            connections.append(NetworkConnection(ip=ip,port=port,raw=line.strip()))
            if ip in KNOWN_C2_IPS:
                suspicious.append(_make_finding("C2 Beacon Detected",f"Connection to {ip}:{port} — known malware C2 IP.","critical","c2_beacon","NET-C2-BEACON"))
            elif port in SUSPICIOUS_PORTS:
                suspicious.append(_make_finding("Suspicious Network Connection",f"Connection to {ip}:{port} — suspicious port.","high","c2_beacon","NET-SUSP-PORT"))
        return NetworkReport(connections=connections,suspicious=suspicious)

    async def virustotal_check(self,apk_path:str,serial:str) -> Optional[dict]:
        if not settings.vt_configured: return None
        local=f"/tmp/cs_apk_{hashlib.md5(apk_path.encode()).hexdigest()[:8]}.apk"
        rc,_,_=await asyncio.to_thread(self._run_adb,"pull",apk_path,local,serial=serial,timeout=30)
        if rc!=0: return None
        try:
            sha256=hashlib.sha256(open(local,"rb").read()).hexdigest()
            async with httpx.AsyncClient(timeout=15) as c:
                r=await c.get(_VT_FILE_REPORT.format(sha256),headers={"x-apikey":settings.VIRUSTOTAL_API_KEY})
                if r.status_code==200:
                    stats=r.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
                    mal=stats.get("malicious",0); total=sum(stats.values()) or 1
                    return {"sha256":sha256,"malicious":mal,"total":total,"ratio":f"{mal}/{total}"}
                elif r.status_code==404: return {"sha256":sha256,"malicious":0,"total":0,"ratio":"Unknown (new file)"}
        except Exception as e: log.warning("VT check failed: %s",e)
        finally: Path(local).unlink(missing_ok=True)
        return None

    def heuristic_score(self,pkg_name:str,pkg_path:str,perms:list[str]) -> Optional[Finding]:
        if not settings.ENABLE_HEURISTICS: return None
        # Skip trusted/core system packages entirely — they legitimately hold broad permissions
        if any(pkg_name.startswith(p) for p in TRUSTED_SYSTEM_PREFIXES): return None
        score=0; reasons=[]
        perm_set=set(perms)
        dangerous=[p for p in perm_set if p in DANGEROUS_PERMISSIONS]
        critical=[p for p in perm_set if any(k in p for k in ("BIND_DEVICE_ADMIN","BIND_ACCESSIBILITY_SERVICE","INSTALL_PACKAGES"))]
        if len(dangerous)>=15: score+=30; reasons.append(f"Excessive permissions ({len(dangerous)})")
        elif len(dangerous)>=10: score+=15; reasons.append(f"High permission count ({len(dangerous)})")
        if len(critical)>=3: score+=40; reasons.append(f"Multiple critical permissions ({len(critical)})")
        elif len(critical)>=2: score+=20; reasons.append(f"Critical permission pair ({len(critical)})")
        # Only flag namespace masquerade for user-installed apps (in /data/app/)
        if pkg_name.startswith("com.android.") and "/data/app/" in pkg_path:
            score+=20; reasons.append("Impersonates com.android.* namespace")
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in pkg_name.lower(): score+=30; reasons.append(f"Suspicious keyword: '{kw}'"); break
        if any("BIND_ACCESSIBILITY_SERVICE" in p for p in perms) and not any(pkg_name.startswith(p) for p in TRUSTED_SYSTEM_PREFIXES):
            score+=30; reasons.append("Requests Accessibility Service (banking trojan vector)")
        if any("BIND_DEVICE_ADMIN" in p for p in perms) and len(dangerous)>5:
            score+=25; reasons.append("Requests Device Admin — possible ransomware")
        if score<40: return None
        severity="critical" if score>=80 else ("high" if score>=60 else "medium")
        return _make_finding(title=f"Suspicious App (Heuristic Score: {score}/100)",description=f"{pkg_name} — {'; '.join(reasons)}.",severity=severity,category="heuristic",signature=f"HEUR-{score:03d}",package=pkg_name)

    def _get_package_perms(self,serial:str,package:str) -> list[str]:
        rc,out,_=self._run_adb("shell","dumpsys","package",package,serial=serial,timeout=10)
        if rc!=0: return []
        perms=[]; in_perms=False
        for line in out.splitlines():
            if "requested permissions:" in line.lower(): in_perms=True; continue
            if in_perms:
                s=line.strip()
                if s.startswith(("android.permission.","com.android.")): perms.append(s.split(":")[0].strip())
                elif s and not s.startswith(("android"," ")): in_perms=False
        return perms

    def _analyze_perms(self,pkg_name:str,perms:list[str]) -> list[Finding]:
        # Skip permission combo analysis for trusted/core system packages
        # These packages legitimately hold broad permissions as part of the OS
        if any(pkg_name.startswith(p) for p in TRUSTED_SYSTEM_PREFIXES):
            return []
        findings=[]; perm_set=set(perms)
        for combo in SPYWARE_COMBOS:
            if all(any(kw in p for p in perm_set) for kw in combo["perms"]):
                findings.append(_make_finding(combo["name"],f"{pkg_name}: {combo['description']} MITRE {combo.get('mitre','N/A')}",combo["severity"],"suspicious_permissions",combo["sig"],pkg_name,combo.get("mitre")))
        return findings

    async def scan_apks_stream(self,serial:str) -> AsyncGenerator[dict,None]:
        is_demo=serial=="DEMO-0047"
        if is_demo:
            packages=_DEMO_PACKAGES
        else:
            rc,out,_=await asyncio.to_thread(self._run_adb,"shell","pm","list","packages","-f",serial=serial,timeout=settings.SCAN_TIMEOUT)
            if rc!=0: yield {"count":0,"total":0,"package":"","findings":[]}; return
            packages=[{"path":m.group(1),"name":m.group(2)} for line in out.splitlines() if (m:=re.search(r"package:(.+?)=(.+)$",line))]
        total=len(packages)
        for i,pkg in enumerate(packages):
            pkg_name=pkg["name"]; pkg_path=pkg.get("path",""); pkg_findings=[]
            if pkg_name in MALWARE_PACKAGES:
                e=MALWARE_PACKAGES[pkg_name]
                pkg_findings.append(_make_finding(e.title,f"Known malware: {pkg_name} — {e.family} ({e.category.upper()}). Source: {e.source}",e.severity,e.category,e.sig,pkg_name,source=e.source))
            is_trusted=any(pkg_name.startswith(p) for p in TRUSTED_SYSTEM_PREFIXES)
            if pkg_name.startswith("com.android.") and not is_trusted and "/data/app/" in pkg_path:
                pkg_findings.append(_make_finding("System Namespace Masquerade",f"{pkg_name} uses com.android.* namespace but is user-installed. MITRE T1036.","medium","masquerade","MASQ-SYSAPP-013",pkg_name,"T1036"))
            perms=_DEMO_PERMS.get(pkg_name,[]) if is_demo else await asyncio.to_thread(self._get_package_perms,serial,pkg_name)
            pkg_findings.extend(self._analyze_perms(pkg_name,perms))
            if not pkg_findings and pkg_name not in MALWARE_PACKAGES:
                h=self.heuristic_score(pkg_name=pkg_name,pkg_path=pkg_path,perms=perms)
                if h: pkg_findings.append(h)
            if pkg_findings and not is_demo and settings.vt_configured and pkg_path:
                vt=await self.virustotal_check(pkg_path,serial)
                if vt and vt.get("malicious",0)>0:
                    pkg_findings.append(_make_finding(f"VirusTotal: {vt['ratio']} engines detect malware",f"{pkg_name} SHA256: {vt['sha256'][:16]}... detected by {vt['malicious']} AV engines.","critical","virustotal",f"VT-{vt['sha256'][:8].upper()}",pkg_name,source="VirusTotal"))
            if i%5==0 or pkg_findings:
                yield {"count":i+1,"total":total,"package":pkg_name,"findings":[f.model_dump() for f in pkg_findings]}
                await asyncio.sleep(0.01)
        yield {"count":total,"total":total,"package":"","findings":[]}

    @staticmethod
    def calculate_risk_score(findings:list) -> int:
        if not findings: return 3
        severities=[f.get("severity","medium") if isinstance(f,dict) else f.severity for f in findings]
        if "critical" in severities: return min(99,95+severities.count("critical"))
        if "high" in severities: return min(89,60+5*severities.count("high"))
        if "medium" in severities: return min(59,30+3*severities.count("medium"))
        return 15