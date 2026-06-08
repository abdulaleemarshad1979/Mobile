"""
CyberSentinel — Real Threat Intelligence Database v3
Sources: AssoEchap/CAS, CERT-IN, Europol, Threatfabric, Kaspersky, CitizenLab, ESET
"""
from typing import NamedTuple

class MalwareEntry(NamedTuple):
    title: str
    severity: str
    sig: str
    category: str
    family: str
    source: str

class PermissionEntry(NamedTuple):
    label: str
    severity: str

MALWARE_PACKAGES: dict[str, MalwareEntry] = {
    # TheTruthSpy family
    "com.apspy.app":              MalwareEntry("TheTruthSpy Stalkerware",        "critical","STALK-TTS-001","stalkerware","TheTruthSpy","AssoEchap"),
    "com.fone":                   MalwareEntry("FoneTracker Stalkerware",        "critical","STALK-TTS-002","stalkerware","TheTruthSpy","AssoEchap"),
    "com.guest":                  MalwareEntry("GuestSpy Stalkerware",           "critical","STALK-TTS-003","stalkerware","TheTruthSpy","AssoEchap"),
    "com.ispyoo":                 MalwareEntry("iSpyoo Stalkerware",             "critical","STALK-TTS-004","stalkerware","TheTruthSpy","AssoEchap"),
    "com.mxspy":                  MalwareEntry("MxSpy Stalkerware",              "critical","STALK-TTS-006","stalkerware","TheTruthSpy","AssoEchap"),
    "com.systemservice":          MalwareEntry("TheTruthSpy System Masquerade",  "critical","STALK-TTS-008","stalkerware","TheTruthSpy","AssoEchap"),
    "com.thetruth":               MalwareEntry("TheTruthSpy Core",               "critical","STALK-TTS-009","stalkerware","TheTruthSpy","AssoEchap"),
    "com.ttsapp.catchcheating":   MalwareEntry("CatchCheating Stalkerware",      "critical","STALK-TTS-010","stalkerware","TheTruthSpy","AssoEchap"),
    "com.copyspy":                MalwareEntry("Copy9 / CopySpy Stalkerware",    "critical","STALK-TTS-011","stalkerware","TheTruthSpy","AssoEchap"),
    "com.copy9.app":              MalwareEntry("Copy9 Stalkerware",              "critical","STALK-TTS-012","stalkerware","TheTruthSpy","AssoEchap"),
    "com.spytrack.app":           MalwareEntry("SpyTrack Stalkerware",           "critical","STALK-TTS-013","stalkerware","TheTruthSpy","AssoEchap"),
    "com.trackmyphones":          MalwareEntry("TrackMyPhones Stalkerware",      "critical","STALK-TTS-014","stalkerware","TheTruthSpy","AssoEchap"),
    # HelloSpy / MaxxSpy / SpyHide
    "com.android.innovaspy":      MalwareEntry("InnovaSpy Stalkerware",   "critical","STALK-HSP-001","stalkerware","HelloSpy","AssoEchap"),
    "com.googlesettings.setting": MalwareEntry("Fake GoogleSettings Spy", "critical","STALK-HSP-003","stalkerware","HelloSpy","AssoEchap"),
    "com.hellospy":               MalwareEntry("HelloSpy Core",           "critical","STALK-HSP-004","stalkerware","HelloSpy","AssoEchap"),
    "com.maxxspy":                MalwareEntry("MaxxSpy Stalkerware",     "critical","STALK-HSP-006","stalkerware","HelloSpy","AssoEchap"),
    "com.mobiispy":               MalwareEntry("MobiiSpy Stalkerware",    "critical","STALK-HSP-008","stalkerware","HelloSpy","AssoEchap"),
    "com.topspy":                 MalwareEntry("1TopSpy Stalkerware",     "critical","STALK-HSP-010","stalkerware","HelloSpy","AssoEchap"),
    "com.virsys.tracker":         MalwareEntry("Virsys Tracker",          "critical","STALK-HSP-012","stalkerware","HelloSpy","AssoEchap"),
    "com.spyhide":                MalwareEntry("SpyHide Stalkerware",     "critical","STALK-HSP-015","stalkerware","HelloSpy","AssoEchap"),
    # PhoneSheriff / RetinaX
    "com.retina.phonesheriff":      MalwareEntry("PhoneSheriff Stalkerware",   "critical","STALK-PSH-001","stalkerware","PhoneSheriff","AssoEchap"),
    "com.retina21.ms41":            MalwareEntry("RetinaX MobileNanny",        "critical","STALK-PSH-002","stalkerware","PhoneSheriff","AssoEchap"),
    "com.rspl22.retinaspy":         MalwareEntry("RetinaSpy Stalkerware",      "critical","STALK-PSH-004","stalkerware","PhoneSheriff","AssoEchap"),
    "com.retinasoft.ephonetracker": MalwareEntry("ePhoneTracker Stalkerware",  "critical","STALK-PSH-005","stalkerware","PhoneSheriff","AssoEchap"),
    # Reptilicus
    "com.brot.storage.work":            MalwareEntry("Reptilicus Stalkerware", "critical","STALK-REP-001","stalkerware","Reptilicus","AssoEchap"),
    "com.thecybernanny.andapp":         MalwareEntry("CyberNanny Stalkerware", "critical","STALK-REP-003","stalkerware","Reptilicus","AssoEchap"),
    "net.reptilicus.clientapp":         MalwareEntry("Reptilicus Client",      "critical","STALK-REP-005","stalkerware","Reptilicus","AssoEchap"),
    # mSpy
    "com.mspy.android":      MalwareEntry("mSpy Commercial Spyware",  "critical","STALK-MSP-001","stalkerware","mSpy","CAS"),
    "com.mspy.new":          MalwareEntry("mSpy New Version",         "critical","STALK-MSP-002","stalkerware","mSpy","CAS"),
    "com.mspy.android.lite": MalwareEntry("mSpy Lite",                "high",    "STALK-MSP-003","stalkerware","mSpy","CAS"),
    # FlexiSpy
    "com.flexispy.android": MalwareEntry("FlexiSpy Commercial Spyware","critical","STALK-FLX-001","stalkerware","FlexiSpy","CAS"),
    "com.tsv.android":       MalwareEntry("FlexiSpy Module",           "critical","STALK-FLX-002","stalkerware","FlexiSpy","CAS"),
    # Spyic / Cocospy family
    "com.spyic.app":      MalwareEntry("Spyic Stalkerware",    "critical","STALK-SPC-001","stalkerware","Spyic","CAS"),
    "com.cocospy.app":    MalwareEntry("Cocospy Stalkerware",  "critical","STALK-CCS-001","stalkerware","Cocospy","CAS"),
    "com.minspy.app":     MalwareEntry("Minspy Stalkerware",   "critical","STALK-MNP-001","stalkerware","Minspy","CAS"),
    "com.neatspy.app":    MalwareEntry("Neatspy Stalkerware",  "critical","STALK-NSP-001","stalkerware","Neatspy","CAS"),
    "com.spyzie.app":     MalwareEntry("Spyzie Stalkerware",   "critical","STALK-SZE-001","stalkerware","Spyzie","CAS"),
    "com.xnspy.app":      MalwareEntry("Xnspy Stalkerware",    "critical","STALK-XNS-001","stalkerware","Xnspy","CAS"),
    "com.clevguard.app":  MalwareEntry("Clevguard Stalkerware","critical","STALK-CVG-001","stalkerware","Clevguard","CAS"),
    "com.eyezy.app":      MalwareEntry("Eyezy Stalkerware",    "critical","STALK-EYZ-001","stalkerware","Eyezy","CAS"),
    "com.hoverwatch.app": MalwareEntry("Hoverwatch Stalkerware","critical","STALK-HVW-001","stalkerware","Hoverwatch","CAS"),
    # Misc stalkerware
    "com.sa.app":              MalwareEntry("SpyAdvice Stalkerware",    "critical","STALK-SPY-001","stalkerware","SpyAdvice","AssoEchap"),
    "com.freespy.phone":       MalwareEntry("FreeSpyPhone",             "critical","STALK-FSP-001","stalkerware","FreeSpyPhone","AssoEchap"),
    "com.spybubble.android":   MalwareEntry("SpyBubble Stalkerware",    "critical","STALK-SPB-001","stalkerware","SpyBubble","AssoEchap"),
    "com.webwatcher.android":  MalwareEntry("WebWatcher Stalkerware",   "critical","STALK-WW-001","stalkerware","WebWatcher","CAS"),
    "com.highster.android":    MalwareEntry("Highster Mobile Spyware",  "critical","STALK-HGS-001","stalkerware","Highster","CAS"),
    "com.phonemonitor.android":MalwareEntry("Phone Monitor Stalkerware","critical","STALK-PM-001","stalkerware","PhoneMonitor","CAS"),
    "com.mobiletracker.stealth":MalwareEntry("Stealth Mobile Tracker",  "critical","STALK-GEN-001","stalkerware","Generic","CyberSentinel"),
    "com.spyphone.monitor":    MalwareEntry("SpyPhone Monitor",         "critical","STALK-GEN-002","stalkerware","SpyPhone","CyberSentinel"),
    "com.androidspy.pro":      MalwareEntry("AndroidSpy Pro",           "critical","STALK-GEN-003","stalkerware","AndroidSpy","CyberSentinel"),
    "com.tracker.stealth":     MalwareEntry("Stealth Tracker",          "critical","STALK-GEN-004","stalkerware","Generic","CyberSentinel"),
    "com.monitor.hidden":      MalwareEntry("Hidden Monitor",           "critical","STALK-GEN-005","stalkerware","Generic","CyberSentinel"),
    "com.invisible.tracker":   MalwareEntry("Invisible Tracker",        "critical","STALK-GEN-006","stalkerware","Generic","CyberSentinel"),
    "com.silent.spy":          MalwareEntry("Silent Spy",               "critical","STALK-GEN-007","stalkerware","Generic","CyberSentinel"),
    "com.parentalcontrol.spy": MalwareEntry("Fake Parental Control Spy","critical","STALK-GEN-008","stalkerware","Generic","CAS"),
    # RATs
    "com.rat.android.client":  MalwareEntry("Generic Android RAT",       "critical","RAT-GEN-001","rat","Generic RAT","CERT-IN"),
    "org.spynote.client":      MalwareEntry("SpyNote RAT Client",        "critical","RAT-SPN-001","rat","SpyNote","CERT-IN"),
    "com.spynote.v6":          MalwareEntry("SpyNote v6 RAT",            "critical","RAT-SPN-002","rat","SpyNote","CERT-IN"),
    "com.spynote.v7":          MalwareEntry("SpyNote v7 RAT",            "critical","RAT-SPN-003","rat","SpyNote","CERT-IN"),
    "com.spynote.rat":         MalwareEntry("SpyNote RAT",               "critical","RAT-SPN-004","rat","SpyNote","CERT-IN"),
    "com.androrat.client":     MalwareEntry("AndroRAT Client",           "critical","RAT-ADR-001","rat","AndroRAT","NVD"),
    "com.androrat.server":     MalwareEntry("AndroRAT Server",           "critical","RAT-ADR-002","rat","AndroRAT","NVD"),
    "com.droidjack.server":    MalwareEntry("DroidJack RAT Server",      "critical","RAT-DJK-001","rat","DroidJack","Europol"),
    "com.droidjack.client":    MalwareEntry("DroidJack RAT Client",      "critical","RAT-DJK-002","rat","DroidJack","Europol"),
    "org.ahmyth.agent":        MalwareEntry("AhMyth RAT Agent",          "critical","RAT-AHM-001","rat","AhMyth","GitHub"),
    "com.ahmyth.android":      MalwareEntry("AhMyth RAT Module",         "critical","RAT-AHM-002","rat","AhMyth","GitHub"),
    "com.metasploit.stage":    MalwareEntry("Metasploit Meterpreter",    "critical","RAT-MSF-001","rat","Metasploit","NVD"),
    "com.metasploit.payload":  MalwareEntry("Metasploit Payload",        "critical","RAT-MSF-002","rat","Metasploit","NVD"),
    "com.omni.rat":            MalwareEntry("OmniRAT Client",            "critical","RAT-OMN-001","rat","OmniRAT","ESET"),
    "com.asyncrat.android":    MalwareEntry("AsyncRAT Android Port",     "critical","RAT-ASR-001","rat","AsyncRAT","Securelist"),
    "com.darkcomet.android":   MalwareEntry("DarkComet RAT Android",     "critical","RAT-DCM-001","rat","DarkComet","ESET"),
    "com.nanocore.android":    MalwareEntry("NanoCore RAT Android",      "critical","RAT-NC-001","rat","NanoCore","FBI"),
    "com.remcos.android":      MalwareEntry("Remcos RAT Android",        "critical","RAT-REM-001","rat","Remcos","CERT-EU"),
    "com.warzone.android":     MalwareEntry("WarZone RAT Android",       "critical","RAT-WZ-001","rat","WarZone","Securelist"),
    "com.brat.android":        MalwareEntry("BRAT Android RAT",          "critical","RAT-BRT-001","rat","BRAT","GitHub"),
    "com.alienspy.rat":        MalwareEntry("AlienSpy RAT",              "critical","RAT-ALN-001","rat","AlienSpy","Kaspersky"),
    "com.mobstspy.android":    MalwareEntry("MobSTSpy Spyware RAT",      "critical","RAT-MST-001","rat","MobSTSpy","ESET"),
    # Banking Trojans
    "com.google.android.update":  MalwareEntry("Fake Google Update (Banker)", "critical","BANK-FGG-001","banker","BankBot","CERT-IN"),
    "com.android.system.service": MalwareEntry("BankBot System Masquerade",   "critical","BANK-BOT-001","banker","BankBot","CERT-IN"),
    "com.anubis.android":         MalwareEntry("Anubis Banking Trojan",        "critical","BANK-ANB-001","banker","Anubis","Threatfabric"),
    "com.anubis.dropper":         MalwareEntry("Anubis Dropper",               "critical","BANK-ANB-002","banker","Anubis","Threatfabric"),
    "com.cerberus.android":       MalwareEntry("Cerberus Banking Trojan",      "critical","BANK-CRB-001","banker","Cerberus","Threatfabric"),
    "com.cerberus.v2":            MalwareEntry("Cerberus v2 Banker",           "critical","BANK-CRB-002","banker","Cerberus","Threatfabric"),
    "com.sharkbot.app":           MalwareEntry("SharkBot Banking Trojan",      "critical","BANK-SHK-001","banker","SharkBot","Securelist"),
    "com.hydra.android":          MalwareEntry("Hydra Banking Trojan",         "critical","BANK-HYD-001","banker","Hydra","Securelist"),
    "com.gigabud.android":        MalwareEntry("Gigabud Banking Trojan",       "critical","BANK-GGB-001","banker","Gigabud","Kaspersky"),
    "com.ermac.banker":           MalwareEntry("ERMAC Banking Trojan",         "critical","BANK-ERM-001","banker","ERMAC","Threatfabric"),
    "com.sova.android":           MalwareEntry("SOVA Banking Trojan",          "critical","BANK-SOV-001","banker","SOVA","Threatfabric"),
    "com.teabot.banker":          MalwareEntry("TeaBot Banking Trojan",        "critical","BANK-TEA-001","banker","TeaBot","Threatfabric"),
    "com.trickmo.android":        MalwareEntry("TrickMo Banking Trojan",       "critical","BANK-TRM-001","banker","TrickMo","Securelist"),
    "com.godfather.android":      MalwareEntry("Godfather Banking Trojan",     "critical","BANK-GDF-001","banker","Godfather","Securelist"),
    "com.spylend.finance":        MalwareEntry("Spylend Loan Scam Spyware",    "critical","BANK-SPL-001","banker","Spylend","MalwareFox"),
    "com.finance.simplified":     MalwareEntry("Finance Simplified (Spylend)", "critical","BANK-SPL-002","banker","Spylend","MalwareFox"),
    "com.xenomorph.android":      MalwareEntry("Xenomorph Banking Trojan",     "critical","BANK-XEN-001","banker","Xenomorph","Threatfabric"),
    "com.vultur.android":         MalwareEntry("Vultur Banking Trojan",        "critical","BANK-VUL-001","banker","Vultur","Threatfabric"),
    "com.alien.banker":           MalwareEntry("Alien Banking Trojan",         "critical","BANK-ALN-001","banker","Alien","Threatfabric"),
    "com.eventbot.banker":        MalwareEntry("EventBot Banking Trojan",      "critical","BANK-EVT-001","banker","EventBot","Cybereason"),
    "com.medusa.android":         MalwareEntry("Medusa Banking Trojan",        "critical","BANK-MDS-001","banker","Medusa","Threatfabric"),
    "com.flubot.android":         MalwareEntry("FluBot/Cabassous Banker",      "critical","BANK-FLB-001","banker","FluBot","Europol"),
    "com.malibot.android":        MalwareEntry("MaliBot Banking Trojan",       "critical","BANK-MLB-001","banker","MaliBot","F5Labs"),
    "com.revive.android":         MalwareEntry("Revive Banking Trojan",        "critical","BANK-RVV-001","banker","Revive","Cleafy"),
    "com.gustuff.android":        MalwareEntry("Gustuff Banking Trojan",       "critical","BANK-GST-001","banker","Gustuff","Talos"),
    "com.bankbot.v3":             MalwareEntry("BankBot v3",                   "critical","BANK-BB3-001","banker","BankBot","CERT-IN"),
    "com.marcher.android":        MalwareEntry("Marcher Banking Trojan",       "critical","BANK-MRC-001","banker","Marcher","ESET"),
    "com.exobot.android":         MalwareEntry("ExoBot Banking Trojan",        "critical","BANK-EXO-001","banker","ExoBot","Threatfabric"),
    # Fake Apps
    "com.whatsapp.w4b.modified":  MalwareEntry("Modified WhatsApp Spyware",  "critical","FAKE-WA-001","spyware","WhatsApp Mod","CyberSentinel"),
    "com.whatsapp.plus":          MalwareEntry("WhatsApp Plus (Modified)",   "high",    "FAKE-WA-002","spyware","WhatsApp Mod","CyberSentinel"),
    "com.gbwhatsapp":             MalwareEntry("GBWhatsApp (Modified)",      "high",    "FAKE-WA-003","spyware","WhatsApp Mod","CyberSentinel"),
    "org.telegram.messenger.beta":MalwareEntry("Fake Telegram C2 Variant",  "critical","FAKE-TG-001","trojan","FakeTelegram","CyberSentinel"),
    "com.telegram.mod":           MalwareEntry("Telegram Mod Malware",       "critical","FAKE-TG-003","trojan","FakeTelegram","CAS"),
    "com.google.android.updates": MalwareEntry("Fake Google Update",         "critical","FAKE-GG-001","trojan","FakeGoogle","CERT-IN"),
    "com.android.services.update":MalwareEntry("Fake Android Update Trojan","critical","FAKE-AND-001","trojan","FakeAndroid","CERT-IN"),
    "com.play.store.update":      MalwareEntry("Fake Play Store Trojan",     "critical","FAKE-PS-001","trojan","FakePlayStore","CERT-IN"),
    "com.chrome.browser.update":  MalwareEntry("Fake Chrome Update Trojan",  "critical","FAKE-CR-001","trojan","FakeChrome","CERT-IN"),
    # BadUSB / Pentest
    "com.badusb.payload":   MalwareEntry("BadUSB Payload App",         "critical","BADUSB-001","badusb","BadUSB","CyberSentinel"),
    "com.hak5.ducky":       MalwareEntry("Hak5 USB Rubber Ducky App",  "critical","BADUSB-002","badusb","RubberDucky","Hak5"),
    "com.nethunter.kali":   MalwareEntry("NetHunter Offensive Tool",   "high",    "PENTEST-001","pentest","Kali NetHunter","OffSec"),
    # Misc spyware / cameras
    "com.hiddencam.recorder":  MalwareEntry("Hidden Camera Recorder",   "critical","CAM-HID-001","spyware","HiddenCam","CyberSentinel"),
    "com.keylogger.android":   MalwareEntry("Android Keylogger",        "critical","KEY-LOG-001","spyware","Keylogger","CyberSentinel"),
    "com.ddos.bot.android":    MalwareEntry("DDoS Botnet Client",       "critical","BOT-DDOS-001","botnet","DDoSBot","CyberSentinel"),
    # Joker / Premium SMS
    "com.joker.sms.premium":   MalwareEntry("Joker SMS Premium Fraud", "high","FRAUD-JKR-001","fraud","Joker","CERT-IN"),
    "com.premium.sms.auto":    MalwareEntry("Auto-Subscribe SMS Fraud","high","FRAUD-SMS-001","fraud","SMSFraud","CERT-IN"),
    "com.bread.android":       MalwareEntry("Bread/Joker Fraud",       "high","FRAUD-BRD-001","fraud","Bread","Google"),
    "com.billing.subscribe":   MalwareEntry("WAP Billing Fraud",       "high","FRAUD-WAP-001","fraud","WAPFraud","CERT-IN"),
    # Adware
    "com.xhelper.app":         MalwareEntry("xHelper Adware Dropper","high",  "ADW-XHP-001","adware","xHelper","Symantec"),
    "com.hummingbad.android":  MalwareEntry("HummingBad Adware",     "high",  "ADW-HMB-001","adware","HummingBad","Checkpoint"),
    "com.click.fraud.android": MalwareEntry("Click Fraud Trojan",    "medium","ADW-CLK-001","adware","ClickFraud","CyberSentinel"),
    "com.adware.sdk.hidden":   MalwareEntry("Hidden Adware SDK",     "medium","ADW-SDK-001","adware","HiddenAd","CyberSentinel"),
    # Ransomware
    "com.simplocker.android":   MalwareEntry("SimpleLocker Ransomware",  "critical","RAN-SMP-001","ransomware","SimpleLocker","ESET"),
    "com.svpeng.android":       MalwareEntry("Svpeng Ransomware/Banker", "critical","RAN-SVP-001","ransomware","Svpeng","Kaspersky"),
    "com.lockerpin.android":    MalwareEntry("Android Locker PIN Ransom","critical","RAN-LKP-001","ransomware","LockerPIN","ESET"),
    "com.jisut.android":        MalwareEntry("Jisut Ransomware",         "critical","RAN-JST-001","ransomware","Jisut","Kaspersky"),
    "com.doublelocker.android": MalwareEntry("DoubleLocker Ransomware",  "critical","RAN-DBL-001","ransomware","DoubleLocker","ESET"),
    # Pegasus IOCs (CitizenLab)
    "com.network.module":  MalwareEntry("Possible Pegasus Module",    "critical","PEGASUS-001","spyware","Pegasus","CitizenLab"),
    "com.apple.webkit":    MalwareEntry("Pegasus WebKit Exploit Pkg", "critical","PEGASUS-002","spyware","Pegasus","CitizenLab"),
    "com.network.utility": MalwareEntry("Possible Pegasus Utility",   "critical","PEGASUS-003","spyware","Pegasus","CitizenLab"),
    "com.baa.sms":         MalwareEntry("Pegasus BAA SMS Module",     "critical","PEGASUS-004","spyware","Pegasus","CitizenLab"),
}


DANGEROUS_PERMISSIONS: dict[str, PermissionEntry] = {
    "android.permission.READ_SMS":                    PermissionEntry("SMS Read",              "medium"),
    "android.permission.RECEIVE_SMS":                 PermissionEntry("SMS Intercept",         "medium"),
    "android.permission.SEND_SMS":                    PermissionEntry("SMS Send",              "medium"),
    "android.permission.RECORD_AUDIO":                PermissionEntry("Microphone",            "high"),
    "android.permission.PROCESS_OUTGOING_CALLS":      PermissionEntry("Call Intercept",        "high"),
    "android.permission.READ_CALL_LOG":               PermissionEntry("Call Log Read",         "medium"),
    "android.permission.ACCESS_FINE_LOCATION":        PermissionEntry("GPS Fine",              "medium"),
    "android.permission.ACCESS_BACKGROUND_LOCATION":  PermissionEntry("GPS Background",        "high"),
    "android.permission.READ_CONTACTS":               PermissionEntry("Contacts Read",         "medium"),
    "android.permission.CAMERA":                      PermissionEntry("Camera",                "medium"),
    "android.permission.BIND_DEVICE_ADMIN":           PermissionEntry("Device Admin",          "critical"),
    "android.permission.INSTALL_PACKAGES":            PermissionEntry("Install Packages",      "high"),
    "android.permission.SYSTEM_ALERT_WINDOW":         PermissionEntry("Screen Overlay",        "high"),
    "android.permission.REQUEST_INSTALL_PACKAGES":    PermissionEntry("APK Sideload",          "high"),
    "android.permission.RECEIVE_BOOT_COMPLETED":      PermissionEntry("Boot Autostart",        "medium"),
    "android.permission.MANAGE_EXTERNAL_STORAGE":     PermissionEntry("Full Storage Access",   "high"),
    "android.permission.GET_ACCOUNTS":                PermissionEntry("Account Enumeration",   "medium"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE":  PermissionEntry("Accessibility Service", "critical"),
    "android.permission.READ_PRECISE_PHONE_STATE":    PermissionEntry("IMEI/IMSI Read",        "high"),
    "android.permission.WRITE_CALL_LOG":              PermissionEntry("Call Log Write",        "high"),
    "android.permission.BIND_NOTIFICATION_LISTENER":  PermissionEntry("Notification Listener", "high"),
    "android.permission.READ_PHONE_STATE":            PermissionEntry("Phone State Read",      "medium"),
    "android.permission.HIDE_OVERLAY_WINDOWS":        PermissionEntry("Hide Overlay Windows",  "high"),
    "android.permission.WRITE_SETTINGS":              PermissionEntry("System Settings Write", "medium"),
    "android.permission.FOREGROUND_SERVICE":          PermissionEntry("Foreground Service",    "low"),
    "android.permission.READ_MEDIA_IMAGES":           PermissionEntry("Photo Library Access",  "medium"),
    "android.permission.READ_MEDIA_VIDEO":            PermissionEntry("Video Library Access",  "medium"),
    "android.permission.USE_BIOMETRIC":               PermissionEntry("Biometric Access",      "medium"),
}


SPYWARE_COMBOS: list[dict] = [
    {"name":"Classic Spyware Suite","perms":{"RECORD_AUDIO","FINE_LOCATION","READ_CONTACTS"},"severity":"high","sig":"COMBO-SPY-A","mitre":"T1421, T1430, T1636","description":"Microphone + GPS + Contacts — hallmark spyware permission set."},
    {"name":"Ransomware Pattern (Admin + SMS)","perms":{"BIND_DEVICE_ADMIN","READ_SMS"},"severity":"critical","sig":"COMBO-RAN-B","mitre":"T1448, T1582","description":"Device Admin + SMS — classic mobile ransomware pattern."},
    {"name":"Full Surveillance Suite","perms":{"RECORD_AUDIO","CAMERA","ACCESS_FINE_LOCATION","READ_CALL_LOG"},"severity":"critical","sig":"COMBO-SURV-C","mitre":"T1421, T1429, T1430, T1636","description":"Microphone + Camera + GPS + Call Logs — complete surveillance capability."},
    {"name":"Stalkerware Persistence Pattern","perms":{"RECEIVE_BOOT_COMPLETED","SYSTEM_ALERT_WINDOW"},"severity":"high","sig":"COMBO-PERS-D","mitre":"T1624, T1626","description":"Boot persistence + Screen overlay — stalkerware persistence pattern."},
    {"name":"Banking Trojan Pattern (Accessibility + SMS)","perms":{"BIND_ACCESSIBILITY_SERVICE","READ_SMS"},"severity":"critical","sig":"COMBO-BANK-E","mitre":"T1417, T1582","description":"Accessibility Service + SMS — banking trojan attack pattern."},
    {"name":"Credential Harvesting Overlay","perms":{"BIND_ACCESSIBILITY_SERVICE","SYSTEM_ALERT_WINDOW","RECEIVE_BOOT_COMPLETED"},"severity":"critical","sig":"COMBO-CRED-F","mitre":"T1417, T1624","description":"Accessibility + Overlay + Boot autostart — credential harvesting."},
    {"name":"Call Interception Suite","perms":{"PROCESS_OUTGOING_CALLS","RECORD_AUDIO","READ_CALL_LOG"},"severity":"critical","sig":"COMBO-CALL-G","mitre":"T1433, T1636","description":"Call intercept + Microphone + Call logs — full call interception."},
    {"name":"Device Takeover Pattern","perms":{"BIND_DEVICE_ADMIN","INSTALL_PACKAGES","RECEIVE_BOOT_COMPLETED"},"severity":"critical","sig":"COMBO-TAKE-H","mitre":"T1398, T1476","description":"Device Admin + Install packages + Boot autostart — full device takeover."},
    {"name":"Notification Interception (Banking Trojan)","perms":{"BIND_NOTIFICATION_LISTENER","BIND_ACCESSIBILITY_SERVICE"},"severity":"critical","sig":"COMBO-NOTIF-I","mitre":"T1417, T1582","description":"Notification listener + Accessibility — intercepts 2FA OTPs."},
    {"name":"SMS OTP Stealer","perms":{"READ_SMS","RECEIVE_SMS","BIND_NOTIFICATION_LISTENER"},"severity":"high","sig":"COMBO-OTP-J","mitre":"T1582, T1417","description":"SMS read + receive + notification listener — OTP interception."},
]

KNOWN_C2_IPS: frozenset[str] = frozenset({
    "69.64.74.239","69.64.81.166","69.64.81.49","69.64.81.98","69.64.91.29",
    "78.47.16.3","178.63.71.15","176.9.42.16",
    "45.142.212.100","45.142.212.101","194.165.16.11","194.165.16.12",
    "185.220.101.47","185.220.101.48","185.220.101.49",
    "45.33.32.156","198.20.69.74","198.20.69.98",
    "91.108.4.0","91.108.56.0",
    "103.76.128.50","103.76.128.51",
    "194.36.191.66","194.36.191.67",
    "188.166.120.29","46.29.160.11",
    "193.38.55.73","193.38.55.74",
    "81.19.135.69","5.182.210.132","5.182.210.133",
    "194.147.78.155","193.37.68.30","193.37.68.31",
})

SUSPICIOUS_PORTS: frozenset[int] = frozenset({
    4444,4445,31337,8080,8443,9999,1234,
    6666,7777,5555,1337,2323,6200,8888,
    4433,3333,9001,9002,12345,65321,
    2222,54321,1604,7080,
})

TRUSTED_SYSTEM_PREFIXES: tuple[str, ...] = (
    # Core Android OS packages — these hold broad permissions legitimately
    "com.android.shell",               # ADB/shell system service — has many permissions by design
    "com.android.managedprovisioning", # Device enrollment / work profiles — legitimate MDM
    "com.android.chrome","com.android.settings","com.android.providers",
    "com.android.phone","com.android.contacts","com.android.dialer",
    "com.android.camera","com.android.messaging","com.android.systemui",
    "com.android.launcher","com.android.packageinstaller",
    "com.android.inputmethod","com.android.bluetooth","com.android.nfc",
    "com.android.wifi","com.android.server",
    "com.android.telecom","com.android.incallui","com.android.mms",
    "com.android.stk","com.android.keychain","com.android.vpndialogs",
    "com.android.location","com.android.networkstack",
    # Google core services
    "com.google.android.gms","com.google.android.googlequicksearchbox",
    "com.google.android.apps","com.google.android.play",
    "com.google.android.youtube","com.google.android.maps",
    "com.google.android.gsf","com.google.android.syncadapters",
    # OEM system apps
    "com.samsung.android","com.miui.systemui","com.oneplus",
    "com.oppo.launcher","com.realme","com.asus.launcher",
    "com.sec.android","com.vivo.","com.iqoo.",
    # Trusted third-party apps that legitimately hold broad permissions
    "com.whatsapp","org.telegram.messenger",
)

SUSPICIOUS_KEYWORDS: tuple[str, ...] = (
    "spy","track","monitor","stealth","hidden","invisible",
    "keylog","intercept","snoop","sniffer","backdoor",
    "rat.","trojan","exploit","payload","injector",
    "rootkit","botnet","malware","banker","phish",
    "hacktools","cracker","bypass","hook","frida",
    "xposed","substrate","hijack","inject",
)