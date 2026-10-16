# Mass-scan dashboard

- **Generated:** 2026-09-30T21:05:12Z
- **Source:** scan-only
- **Apps:** 150 scanned · 0 failed · 150 requested
- **Total scan time:** 4195.0s · **Total IPA size:** 36.86 GB

## Summary

| Metric | Value |
|---|---:|
| Apps scanned | 150 |
| Total findings | 10338 |
| Unique trackers | 56 |
| Apps w/ ATS arbitrary loads | 42 |
| Apps w/ potential secrets | 12 |

## Findings by severity

| Severity | Count |
|---|---:|
| info | 9631 |
| low | 0 |
| medium | 707 |
| high | 0 |
| critical | 0 |

## Top trackers (by app count)

| Tracker | Apps | Detail |
|---|---:|---|
| Meta / Facebook | 60 | Meta · US · advertising |
| Google Ads | 47 | Google · US · advertising |
| AppsFlyer | 44 | AppsFlyer · IL · attribution |
| Firebase Analytics | 32 | Google · US · analytics |
| AppLovin / MAX | 21 | AppLovin · US · advertising |
| Branch | 19 | Branch · US · attribution |
| Audience Network | 18 | Meta · US · advertising |
| InMobi | 16 | InMobi · IN · advertising |
| Adjust | 15 | Adjust · DE · attribution |
| Braze (Appboy) | 14 | Braze · US · push |
| Moloco | 14 | Moloco · US · advertising |
| ThreatMetrix | 11 | LexisNexis · US · antifraud |
| Amazon Ads (APS) | 9 | Amazon · US · advertising |
| Vungle / Liftoff | 9 | Liftoff · US · advertising |
| PubMatic | 8 | PubMatic · US · advertising |
| Amplitude | 7 | Amplitude · US · analytics |
| Verve Group | 7 | Verve · DE · advertising |
| Forter | 6 | Forter · US · antifraud |
| mParticle | 6 | mParticle · US · analytics |
| FullStory | 5 | FullStory · US · session-replay |

## Top endpoint owners

| Owner | Apps | Detail |
|---|---:|---|
| Apple | 150 | US |
| Google | 83 | US |
| Meta | 58 | US |
| AppsFlyer | 42 | IL |
| Amazon | 30 | US |
| PayPal | 25 | US |
| Stripe | 21 | US |
| X Corp | 15 | US |
| Adjust | 14 | DE |
| Branch | 12 | US |
| Microsoft | 11 | US |
| ByteDance | 9 | CN |
| PubMatic | 8 | US |
| Verve | 7 | DE |
| Braze | 5 | US |
| FullStory | 5 | US |
| Arkose Labs | 4 | US |
| Kakao | 4 | KR |
| Klarna | 4 | SE |
| LY Corp | 4 | JP |

## Top endpoint countries

| Country | Apps | Detail |
|---|---:|---|
| US | 150 |  |
| IL | 42 |  |
| DE | 20 |  |
| CN | 11 |  |
| SE | 8 |  |
| JP | 4 |  |
| KR | 4 |  |
| AE | 2 |  |
| GB | 2 |  |
| IN | 2 |  |
| RU | 2 |  |
| FR | 1 |  |

## Top requested permissions

| Permission key | Apps | Detail |
|---|---:|---|
| NSCameraUsageDescription | 144 | Camera access |
| NSPhotoLibraryUsageDescription | 128 | Photo library read |
| NSMicrophoneUsageDescription | 124 | Microphone access (eavesdropping risk) |
| NSLocationWhenInUseUsageDescription | 118 | Location access while the app is in use |
| NSContactsUsageDescription | 93 | Address book / contacts access |
| NSPhotoLibraryAddUsageDescription | 92 | Photo library write |
| NSUserTrackingUsageDescription | 84 | App Tracking Transparency / IDFA collection |
| NSFaceIDUsageDescription | 76 | Face ID biometric authentication |
| NSCalendarsUsageDescription | 70 | Calendar events access |
| NSLocationAlwaysAndWhenInUseUsageDescription | 68 | Persistent location access, including while backgrounded |
| NSBluetoothAlwaysUsageDescription | 53 | Persistent Bluetooth access (beacons, fingerprinting) |
| NSSpeechRecognitionUsageDescription | 45 | Speech recognition |
| NSLocationAlwaysUsageDescription | 44 | Persistent location access (deprecated key) |
| NSBluetoothPeripheralUsageDescription | 42 | Bluetooth peripheral access |
| NSMotionUsageDescription | 37 | Accelerometer / motion sensors (CoreMotion) |
| NSLocalNetworkUsageDescription | 35 | Local network scanning (routers, smart devices) |
| NSAppleMusicUsageDescription | 32 | Apple Music library access |
| NSSiriUsageDescription | 24 | Sends user speech and app content to Siri |
| NSCalendarsFullAccessUsageDescription | 23 | Full calendar read/write access |
| NSLocationUsageDescription | 18 |  |

## Most common vectors

| Vector | Apps | Detail |
|---|---:|---|
| TRK-01, Analytics / attribution / anti-fraud SDKs | 112 | MASVS-PRIVACY |
| SECH-01, Transport security (ATS / TLS / pinning) | 101 | MASVS-NETWORK |
| DCS-02, Location tracking | 68 | MASVS-PRIVACY |
| SECH-05, Hardcoded secrets & credentials | 12 | MASVS-STORAGE |
| DCS-06, Installed-app enumeration | 4 | MASVS-PRIVACY |
| DCS-07, Proximity & cross-device sensing | 2 | MASVS-PRIVACY |
| PLAT-03, App extensions & custom keyboards | 1 | MASVS-PLATFORM |

## MASVS group frequency

| Group | Apps | Detail |
|---|---:|---|
| MASVS-PRIVACY · Privacy | 126 |  |
| MASVS-NETWORK · Network | 101 |  |
| MASVS-STORAGE · Storage | 12 |  |

## Cluster frequency

| Cluster | Apps | Detail |
|---|---:|---|
| MASVS-PRIVACY · Privacy | 126 |  |
| MASVS-NETWORK · Network | 101 |  |
| MASVS-STORAGE · Storage | 12 |  |
| INDICATORS · Indicators outside MASVS | 4 |  |

## MASWE weakness classes

| Weakness | Apps | Detail |
|---|---:|---|
| MASWE-0068 | 359 | Incorrect Use of Identifiers for User Tracking |
| MASWE-0066 | 162 | Inadequate Permission Management |
| MASWE-0026 | 121 | Network Traffic Not Encrypted |
| MASWE-0004 | 61 | Sensitive Data Hardcoded in the App Package |

## Cluster profiles

Apps per finding. Counted rows are offensive at low or above, the cluster reach test; a family of per-value rules is one row, its members in brackets.

### MASVS-PRIVACY · Privacy

Data collection, tracking, fingerprinting and exfiltration. **126 of 150 apps.**

MASWE-0066 Inadequate Permission Management (109) · MASWE-0068 Incorrect Use of Identifiers for User Tracking (107)

| Finding | Apps | Worst severity |
|---|---:|---|
| Tracker SDK (Meta / Facebook (advertising) 60, Google Ads (advertising) 47, AppsFlyer (attribution) 44, AppLovin / MAX (advertising) 21, Branch (attribution) 19, Audience Network (advertising) 18, InMobi (advertising) 16, Adjust (attribution) 15, Moloco (advertising) 14, ThreatMetrix (antifraud) 11, Amazon Ads (APS) (advertising) 9, Vungle / Liftoff (advertising) 9, PubMatic (advertising) 8, Verve Group (advertising) 7, Forter (antifraud) 6, FullStory (session-replay) 5, Kochava (attribution) 5, Sardine (antifraud) 4, Smaato (advertising) 4, Arkose Labs (antifraud) 3, Google reCAPTCHA (antifraud) 3, LogRocket (session-replay) 3, Ogury (advertising) 3, Singular (attribution) 3, Unity Ads / Analytics (advertising) 3, Quantum Metric (session-replay) 2, ironSource (advertising) 2, Chartboost (advertising) 1, Criteo (advertising) 1, Fyber / Digital Turbine (advertising) 1, Outbrain (advertising) 1, Pangle (advertising) 1, Smartlook (session-replay) 1, Taboola (advertising) 1) | 106 | medium |
| Requests permission (App Tracking Transparency / IDFA collection 84, Persistent location access, including while backgrounded 53) | 104 | medium |
| Always-on (background) location authorization | 10 | medium |
| Geofence region monitoring | 7 | medium |
| Probes for remote-control apps (AnyDesk / TeamViewer) | 4 | medium |
| Visit monitoring (CLVisit) | 4 | medium |
| Significant-location-change monitoring (background) | 3 | medium |
| AppsFlyer attribution SDK | 2 | medium |
| Retail proximity / beacon SDK | 2 | medium |
| Custom keyboard with full network access | 1 | medium |

Not counted: APS push environment (148) · Imports sysctlbyname() (148) · Cellular operator information (CTCarrier) (145) · Associated domains / universal links (144) · File creation date / disk size as fingerprint signal (143) · Camera capture API (142) · Probes installed apps via LSApplicationQueriesSchemes (140) · Privacy manifest declares accessed API (139) · CoreLocation use (134) · App Groups entitlement (cross-app data sharing) (131) · Boot time fingerprint (PrivacyAccessedAPICategorySystemBootTime) (131) · CoreMotion accelerometer / gyroscope (129) · Photo library (PHPhotoLibrary) (127) · IDFA / IDFV / ASIdentifierManager (115) · Requests permission (114) · Keychain access group (cross-app credential share) (102) · Contacts (ABAddressBook / CNContactStore) (89) · Checks for specific messenger, social or banking apps (87) · Wi-Fi network / BSSID inspection (87) · Privacy manifest declares tracking domains (79) · Microphone recording API (AVAudioRecorder) (72) · Calendar / Reminders access (EventKit) (71) · canOpenURL / LSApplicationQueriesSchemes runtime probe (71) · Tracker SDK (59) · Local network scanning (44) · Firebase Analytics (41) · Bluetooth LE peripheral scanning (33) · Access Wi-Fi Information entitlement (30) · NFC tag-reader entitlement (15) · Battery / uptime / SIM-location telemetry (14) · Touch coordinate / force / radius capture (13) · HealthKit entitlement (12) · Multicast networking entitlement (9) · sysctl reads hardware/kernel identity (7) · iBeacon ranging (Bluetooth micro-location) (6) · HealthKit Capabilities entitlement (5) · HealthKit background-delivery entitlement (5) · Location Push Service Extension entitlement (5) · Geofence region monitoring (4) · AutoFill credential-provider entitlement (3) · NetworkExtension provider entitlement (3) · Significant-location-change monitoring (background) (2) · Visit monitoring (CLVisit) (2) · Always-on (background) location authorization (1) · Contact-notes entitlement (1) · HomeKit entitlement (1) · Notification-filtering entitlement (1) · Retail proximity / beacon SDK (1) · TouchData serialized struct (x/y/pressure/size/timestamp) (1) · Ultra-wideband ranging (NearbyInteraction) (1) · Yandex AppMetrica SDK (1)

### MASVS-NETWORK · Network

Transport security and server communication. **101 of 150 apps.**

MASWE-0026 Network Traffic Not Encrypted (101)

| Finding | Apps | Worst severity |
|---|---:|---|
| ATS relaxed for web, media or local-network content | 45 | medium |
| App Transport Security globally disabled (NSAllowsArbitraryLoads) | 42 | medium |
| ATS exception domains permit cleartext or weak TLS | 34 | medium |

Not counted: Hard-coded cleartext http:// URLs (114) · Raw CFStream / NSStream socket (bypasses ATS) (114) · References CFStream TLS-relaxation keys (80) · Embedded certificate / public-key material (9) · No ATS certificate pinning (NSPinnedDomains) despite exception domains (4)

### MASVS-STORAGE · Storage

Local data at rest: files, databases, Keychain. **12 of 150 apps.**

MASWE-0004 Sensitive Data Hardcoded in the App Package (12)

| Finding | Apps | Worst severity |
|---|---:|---|
| Possible hardcoded secret (Generic Credential 11, JSON Web Token 1) | 12 | medium |

Not counted: Backup-exclusion API in use (NSURLIsExcludedFromBackupKey) (143) · References NSFileProtectionNone (119) · References kSecAttrAccessibleAlways (108) · Public client identifier (45) · Unencrypted SQLite store ships in the bundle (14)

### MASVS-CRYPTO · Cryptography

Cryptographic primitives, modes and key handling. **0 of 150 apps.**

| Finding | Apps | Worst severity |
|---|---:|---|

Not counted: Keychain API in use (SecItem) (149) · Weak hash primitive (MD5 / SHA-1) (147) · Non-cryptographic random number generator (143)

### MASVS-PLATFORM · Platform

Platform APIs, IPC, WebViews and background execution. **0 of 150 apps.**

| Finding | Apps | Worst severity |
|---|---:|---|

Not counted: WKWebView in use (149) · Registers custom URL schemes (inbound deep-link surface) (148) · UIPasteboard / generalPasteboard access (147) · WKUserScript injection (143) · WKScriptMessageHandler JS→native bridge (135) · Runtime JavaScript evaluation in WebView (75) · Time-sensitive notifications (56) · Communication-style push (54) · Critical-alert push entitlement (2) · WebView file-URL access keys referenced (allowFileAccessFromFileURLs) (1)

### MASVS-CODE · Code quality

Build settings, hardening and embedded secrets. **0 of 150 apps.**

| Finding | Apps | Worst severity |
|---|---:|---|

Not counted: Dynamic loader in use (dlopen / dlsym) (150) · Minimum iOS version (150) · No stack-smashing protection (stack canary) (43)

### MASVS-RESILIENCE · Resilience

Anti-tampering, anti-analysis and malware indicators. **0 of 150 apps.**

| Finding | Apps | Worst severity |
|---|---:|---|

Not counted: dyld image-list introspection (146) · Debug symbols left in binaries (85) · Web Inspector toggle set on a WebView or JavaScript context (isInspectable) (19)

### MASVS-AUTH · Authentication

Authentication and authorization mechanisms. **0 of 150 apps.**

| Finding | Apps | Worst severity |
|---|---:|---|

Not counted: FaceID / LocalAuthentication biometrics (134)

### APPLE-POLICY · Apple policy

App Store obligations: privacy-manifest declarations, tracking domains, ATT consent and the kids category. **0 of 150 apps.**

| Finding | Apps | Worst severity |
|---|---:|---|

Not counted: Declared collected data types (135) · Privacy manifest declares undefined collected-data values (55) · SDKs on Apple's privacy-manifest list without a manifest (30) · Privacy manifest gap (23) · Tracker domains reached but not declared in the privacy manifest (23) · App manifest declares a reason reserved for third-party SDKs (18) · Tracking capability without an ATT consent gate (9) · Permission purpose strings that explain nothing (6) · Privacy manifest declares reasons Apple does not approve (1)

### INDICATORS · Indicators outside MASVS

Observations no MASWE weakness or MASTG test describes. Each cites its own source: Apple documentation or published research. **4 of 150 apps.**

| Finding | Apps | Worst severity |
|---|---:|---|
| Session-replay SDK linked | 4 | medium |

Not counted: Endpoints owned by … (150) · Main executable is FairPlay-encrypted (150) · Background modes declared (146) · Imports getifaddrs() for network interface enumeration (142) · Content-available silent push (137) · UserDefaults shared within an App Group (declared reason 1C8F.1) (131) · Reads system proxy settings (125) · Embedded SDK provenance (110) · Background fetch mode (UIBackgroundModes "fetch") (102) · Background audio mode (persistence channel) (86) · BGTaskScheduler silent background wake-ups (73) · Begin / end expiring background task (67) · On-device ML only (no cloud AI endpoint) (64) · UIBackgroundModes contains "processing" (BGTaskScheduler channel) (53) · UIBackgroundModes contains "voip" (38) · Background URLSession configuration (37) · PushKit VoIP push (silent wakeup) (36) · UIBackgroundModes contains "location" (36) · References to regional super-app ecosystem domains (12) · Sentry crash + telemetry SDK (12) · National-standard (non-NIST) cryptography (8) · LLM SDK linked (5) · VPN tunnel interface name in strings (5) · NEVPNManager / NETunnelProviderManager use (2)

### Mitigations observed

Evidence of a published mitigation (App Attest, backup exclusion, capture detection). A plus for the app, never tallied as a weakness. **143 of 150 apps.**

| Finding | Apps | Worst severity |
|---|---:|---|
| Keychain access control in use (SecAccessControlCreateWithFlags) | 106 | info |
| Sets an expiration date on pasteboard items (positive signal) | 79 | info |
| fork / posix_spawn execution probe | 63 | info |
| Declared Age Range entitlement (positive disclosure signal) | 62 | info |
| Screen-capture detection | 62 | info |
| Declared Age Range API in use | 51 | info |
| Jailbreak filesystem paths probed | 43 | info |
| App Attest / DeviceCheck attestation in use (positive signal) | 37 | info |
| Keeps pasteboard items on this device (positive signal) | 33 | info |
| Frida instrumentation indicators | 25 | info |
| MobileSubstrate / CydiaSubstrate references | 24 | info |
| Restricts custom keyboards app-wide (positive signal) | 17 | info |
| Probes Cydia / Sileo / Filza URL schemes | 13 | info |
| Default data-protection class declared (positive signal) | 12 | info |
| SSL certificate pinning (informational) | 11 | info |
| Family Controls / Screen Time capability | 1 | info |
| isJailbroken / jailbreak detection variable | 1 | info |

## Most findings by severity (top 20)

| # | App | Bundle ID | Ver | Findings | Crit | High | Med | Low | Trackers | Secrets |
|---:|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| 1 | UPS | `com.ups.m.iphone` | 10.34.2 | 90 | 0 | 0 | 26 | 0 | 3 | 29 |
| 2 | McDonald's | `com.mcdonalds.gma` | 26.72.3 | 96 | 0 | 0 | 22 | 0 | 5 | 40 |
| 3 | TextFree | `com.pinger.textfreeWithVoice` | 13.26.2 | 103 | 0 | 0 | 16 | 0 | 15 | 0 |
| 4 | TextMe | `com.textmeinc.textme2` | 3.54.1 | 94 | 0 | 0 | 14 | 0 | 13 | 0 |
| 5 | X | `com.atebits.Tweetie2` | 12.27.1 | 96 | 0 | 0 | 14 | 0 | 4 | 8 |
| 6 | Duolingo | `com.duolingo.DuolingoMobile` | 7.140.0 | 97 | 0 | 0 | 13 | 0 | 12 | 0 |
| 7 | Vinted | `lt.manodrabuziai.fr` | 26.36.1 | 96 | 0 | 0 | 13 | 0 | 11 | 0 |
| 8 | Hidden app A | `hidden.app.a` |  | 94 | 0 | 0 | 12 | 0 | 12 | 0 |
| 9 | Wizz | `com.vlbapps.wizz` | 11.6.0 | 97 | 0 | 0 | 12 | 0 | 12 | 0 |
| 10 | Letterboxd | `com.letterboxd.LetterboxdApp` | 4.12.6 | 77 | 0 | 0 | 11 | 0 | 10 | 0 |
| 11 | TextNow | `com.tinginteractive.usms` | 26.37.1 | 97 | 0 | 0 | 11 | 0 | 11 | 0 |
| 12 | Life360 | `com.life360.safetymap` | 26.35.0 | 90 | 0 | 0 | 10 | 0 | 9 | 2 |
| 13 | SeatGeek | `com.seatgeek.SeatGeek` | 2026.38.0 | 83 | 0 | 0 | 10 | 0 | 7 | 0 |
| 14 | Talkatone | `im.talkme.talkmeim` | 7.1.6 | 81 | 0 | 0 | 10 | 0 | 8 | 0 |
| 15 | Widgetable | `com.widgetable.theme` | 4.1.080 | 90 | 0 | 0 | 10 | 0 | 7 | 0 |
| 16 | Yik Yak | `com.yikyak.2` | 5.8.8 | 80 | 0 | 0 | 10 | 0 | 10 | 0 |
| 17 | BlinkDrama | `com.blink.drama.ios` | 3.5.0 | 73 | 0 | 0 | 9 | 0 | 7 | 0 |
| 18 | DramaBox | `com.storymatrix.drama` | 6.8.0 | 87 | 0 | 0 | 9 | 0 | 8 | 0 |
| 19 | NetShort | `com.netshort.abroad` | 2.3.1 | 82 | 0 | 0 | 9 | 0 | 8 | 0 |
| 20 | SHEIN | `zzkko.com.ZZKKO` | 15.4.2 | 73 | 0 | 0 | 9 | 0 | 5 | 0 |

Ordered by critical, then high, then medium, then low. A tally, not a score.

