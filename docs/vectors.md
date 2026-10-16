# Detection vectors

A vector is a category of behaviour ISAT looks for. Each one has a code under one of six
constructs (`DCS-02`, `SURV-01`, …), a [MASVS group](severity.md#masvs-groups) and MITRE ATT&CK
Mobile techniques. Vectors are declared in
`Sources/ScannerKit/Resources/Rules/taxonomy/vectors.json`.

Every vector maps to OWASP MASWE weaknesses and, where they apply, MASTG tests, CWE and a CVSS
v4.0 vector (`Rules/taxonomy/crosswalk.json`).

Detectors are either YAML rules (`Rules/vectors/*.yaml`, evaluated by `RuleEngine`) or Swift
analyzers called from `Pipeline/Scanner.swift`, plus the tracker database and the `Info.plist`
permission and manifest checks. Severity runs `info < low < medium < high < critical` and is
derived from CVSS v4.0 for security findings and from the WP 248 criteria for privacy findings
(see [severity.md](severity.md)). `ISAT --rules-info` lists the rules by construct with
MASWE/MASTG coverage.

## Summary

| Construct | Code | Title | MASVS group | Detectors |
|---|---|---|---|---|
| **DCS** Data collection | DCS-01 | Device & environment fingerprinting | Privacy | YAML |
| | DCS-02 | Location tracking | Privacy | YAML |
| | DCS-03 | Content access (clipboard/contacts/photos/calendar) | Privacy | YAML |
| | DCS-04 | Behavioural biometrics & motion sensors | Privacy | YAML |
| | DCS-05 | Audio / video / screen capture | Privacy | YAML |
| | DCS-06 | Installed-app enumeration | Privacy | YAML + Info.plist |
| | DCS-07 | Proximity & cross-device sensing | Privacy | YAML |
| **TRK** Tracking | TRK-01 | Analytics / attribution / anti-fraud SDKs | Privacy | YAML + tracker DB |
| | TRK-02 | Data-broker embedding | Privacy | YAML |
| | TRK-04 | Server region / data residency | Privacy | programmatic |
| | TRK-05 | AI / LLM data egress | Privacy | programmatic |
| **TGAP** Transparency gap | TGAP-01 | Privacy-manifest gap (used vs declared) | Privacy | programmatic |
| | TGAP-02 | Consent / ATT ordering integrity | Privacy | programmatic |
| | TGAP-03 | Child-safety & age-assurance signals | Privacy | YAML + programmatic (store metadata) |
| **SURV** Surveillance & evasion | SURV-01 | VPN / proxy detection | Privacy | YAML |
| | SURV-02 | Anti-analysis / anti-debug / anti-jailbreak | Resilience | YAML |
| | SURV-03 | Hidden background exfiltration | Privacy | YAML |
| | SURV-04 | Obfuscation indicators | Resilience | YAML |
| | SURV-05 | Known spyware / stalkerware IOCs | Resilience | YAML |
| **SECH** Security hygiene | SECH-01 | Transport security (ATS/TLS/pinning) | Network | YAML + programmatic |
| | SECH-02 | Data-at-rest protection | Storage | YAML |
| | SECH-03 | Cryptography | Cryptography | YAML |
| | SECH-04 | Binary hardening | Code | programmatic |
| | SECH-05 | Hardcoded secrets & credentials | Storage | programmatic |
| | SECH-06 | Code signing / entitlement posture | Code | YAML |
| | SECH-07 | Authentication & keychain protection | Auth | YAML |
| | SECH-08 | SDK provenance & supply chain | Code | programmatic |
| | SECH-09 | Platform version | Code | programmatic |
| **PLAT** Platform surface | PLAT-01 | WebView / JavaScript bridge | Platform | YAML |
| | PLAT-02 | Deep-link / URL-scheme handler exposure | Platform | programmatic |
| | PLAT-03 | App extensions & custom keyboards | Platform | programmatic |
| | PLAT-04 | Background-activation surface | Platform | YAML + Info.plist |

---

# DCS: Data-Collection Surface

## DCS-01: Device & environment fingerprinting
- **MITRE:** T1426, T1422 · **Detects:** IDFA/IDFV, sysctl hardware probes, boot time, disk space, carrier data.

| Rule | Signal | Severity |
|---|---|---|
| `DCS-01.sysctl_hw_kern` | `hw.machine` / `kern.osversion` / `hw.cputype` sysctl names | info |
| `DCS-01.sysctlbyname_import` | imports `sysctlbyname` / `sysctl` | info |
| `DCS-01.idfa_idfv` | `ASIdentifierManager` / `advertisingIdentifier` / `identifierForVendor` | info |
| `DCS-01.carrier_info` | `CTTelephonyNetworkInfo` / `CTCarrier` / MCC-MNC | info |
| `DCS-01.battery_uptime_telemetry` | `batteryLevel` / `simLocation` / `carrierName` | info |
| `DCS-01.file_metadata_fingerprint` | `NSFileCreationDate` / `NSFileSystemFreeSize` | info |
| `DCS-01.boottime_fingerprint` | `kern.boottime` / `SystemBootTime` privacy category | info |
| `DCS-01.user_defaults_appgroup_fingerprint` | `UserDefaults` privacy category (cross-app IDFA share) | info |

## DCS-02: Location tracking
- **MITRE:** T1430 · **Detects:** CoreLocation use, especially background or significant-change monitoring.

| Rule | Signal | Severity |
|---|---|---|
| `DCS-02.cl_location_manager` | `CLLocationManager` | info |
| `DCS-02.significant_change_monitoring` | `startMonitoringSignificantLocationChanges` (info without the Always key) | medium |
| `DCS-02.always_authorization` | `requestAlwaysAuthorization` / `setAllowsBackgroundLocationUpdates:` calls (continuous background location; info without `NSLocationAlwaysAndWhenInUseUsageDescription`) | medium |
| `DCS-02.beacon_ranging` | iBeacon ranging (`startRangingBeacons` / `didRangeBeacons`), Bluetooth micro-location | info |
| `DCS-02.region_monitoring` | `startMonitoringForRegion` / region-event delegate / `CLMonitor` (geofence; info without the Always key) | medium |
| `DCS-02.visit_monitoring` | `startMonitoringVisits` / `CLVisit` (info without the Always key) | medium |

## DCS-03: Content access (clipboard / contacts / photos / calendar)
- **MITRE:** T1409, T1636.003, T1414 · **Detects:** pasteboard reads, contacts / photo-library access, calendar/reminders.

| Rule | Signal | Severity |
|---|---|---|
| `DCS-03.uipasteboard_read` | `UIPasteboard` / `generalPasteboard` | info |
| `DCS-03.contacts_access` | `CNContactStore` / `ABAddressBook` | info |
| `DCS-03.photo_library` | `PHPhotoLibrary` | info |
| `DCS-03.calendar_access` | `EKEventStore` / `EKCalendar` | info |
| `DCS-03.pasteboard_expiration` | `UIPasteboardOptionExpirationDate` imported (positive signal, MASTG-TEST-0279) | info |
| `DCS-03.pasteboard_local_only` | `UIPasteboardOptionLocalOnly` imported (positive signal, MASTG-TEST-0280) | info |

## DCS-04: Behavioural biometrics & motion sensors
- **MITRE:** T1417 · **Detects:** touch event capture, accelerometer/gyroscope motion fingerprinting.

| Rule | Signal | Severity |
|---|---|---|
| `DCS-04.touch_biometrics` | `majorRadius` / `forceTouch` / `preciseLocationInView` | info |
| `DCS-04.core_motion` | `CMMotionManager` / `CMAccelerometer` / `CMGyro` (benign in ARKit/SceneKit) | info |
| `DCS-04.face_id_biometrics` | `LAContext` / `LocalAuthentication` (neutral: the app gets only success or failure; event-bound use needs the encrypted call site) | info |

## DCS-05: Audio / video / screen capture
- **MITRE:** T1429, T1512, T1513 · **Detects:** camera/mic capture, screen-recording detection/capture.

| Rule | Signal | Severity |
|---|---|---|
| `DCS-05.audio_recording` | `AVAudioRecorder` / `requestRecordPermission` | info |
| `DCS-05.video_capture` | `AVCaptureSession` / `AVCaptureDevice` | info |
| `DCS-05.screen_capture_detect` | `UIScreen.isCaptured` / capture-changed notification | info |
| `DCS-05.background_audio_mode` | `UIBackgroundModes` contains `audio` | info |

## DCS-06: Installed-app enumeration
- **MITRE:** T1418, T1426 · **Detects:** probing which other apps are installed via URL schemes / `canOpenURL` / `LSApplicationQueriesSchemes`.

| Rule | Signal | Severity |
|---|---|---|
| `DCS-06.canOpenURL` | `canOpenURL` symbol / `LSApplicationQueriesSchemes` string (0-bit presence) | info |
| `DCS-06.remote_control_apps` | AnyDesk / TeamViewer / QuickSupport strings (anti-fraud pattern) | medium |
| `DCS-06.competitor_url_schemes` | competitor / messenger / banking URL schemes in queries | info |

The `Info.plist` analyzer also emits `DCS-06.ls_application_queries_schemes` enumerating every declared query scheme (severity scales with count).

## DCS-07: Proximity & cross-device sensing
- **MITRE:** T1422, T1430 · **Detects:** BLE/UWB/Wi-Fi/Bonjour scanning and retail-beacon SDKs, which reveal the user's physical and household surroundings.

| Rule | Signal | Severity |
|---|---|---|
| `DCS-07.ble_scanning` | CoreBluetooth central-manager scanning (`scanForPeripheralsWithServices`) | info |
| `DCS-07.uwb_ranging` | ultra-wideband ranging (`NISession` / `NearbyInteraction`) | info |
| `DCS-07.wifi_info` | `CNCopyCurrentNetworkInfo` / `NEHotspotHelper` / BSSID (location proxy) | info |
| `DCS-07.beacon_sdk` | retail proximity SDK (Estimote, Kontakt.io, inMarket, Radar, Gimbal) | medium |
| `DCS-07.bonjour_services` | `NSBonjourServices` enumeration | info |
| `DCS-07.local_network` | `NWBrowser` / Bonjour local-network device enumeration | info |

---

# TRK: Tracking Intensity

## TRK-01: Analytics / attribution / anti-fraud SDKs
- **MITRE:** T1437 · **Detects:** known analytics / attribution / anti-fraud SDKs that collect device and behaviour data. Vendor **domains** are classified separately via the tracker DB (`Resources/Rules/trackers/trackers.json`).

| Rule | SDK | Severity |
|---|---|---|
| `TRK-01.appmetrica` | Yandex AppMetrica | info |
| `TRK-01.mytracker` | VK / Mail.ru MyTracker | medium |
| `TRK-01.group_ib_sdk` | Group-IB Fraud Hunting Platform | medium |
| `TRK-01.kaspersky_sdk` | Kaspersky mobile security | medium |
| `TRK-01.appsflyer` | AppsFlyer | medium |
| `TRK-01.firebase_analytics` | Firebase Analytics | info |
| `TRK-01.sentry` | Sentry crash + telemetry | info |
| `TRK-01.session_replay_sdk` | session-replay SDK or vendor module by framework name (FullStory, Quantum Metric, LogRocket, Smartlook, Amplitude / Mixpanel / Dynatrace Session Replay); App Review 2.5.14 | medium |
| `TRK-01.adjust` / `TRK-01.branch` | Adjust / Branch attribution | low |
| `TRK-01.ok_tracer` | ok.tracer | low |
| `TRK-01.huawei_hms` | Huawei Mobile Services | info |

Tracker-DB attribution/anti-fraud SDKs (domain-keyed) include AppsFlyer, Adjust, Branch, Singular, Kochava, ThreatMetrix, Iovation, Sift, Forter and FingerprintJS; each surfaces as a `tracker.<id>` finding titled "Tracker SDK: …". Identity comes only from telemetry hosts, never from a company's website or CDN: `facebook.com`, `instagram.com` and `fbcdn.net` are Meta the social network (`meta.social`, `meta.cdn`, not trackers), while the Facebook SDK is `graph.facebook.com`, `ep1/ep6.facebook.com` and `connect.facebook.net`. A tracker entry may also list `frameworks` (exact names in `Frameworks/`); a match adds the SDK even when its hosts sit in encrypted code (FBSDKCoreKit, FBAudienceNetwork).

## TRK-02: Data-broker embedding
- **MITRE:** T1437 · **Detects:** location/behaviour brokers named in FTC actions and investigative research.

| Rule | Broker | Severity |
|---|---|---|
| `TRK-02.xmode` | X-Mode / Outlogic | medium |
| `TRK-02.anomaly_six` | Anomaly Six / Sybil | medium |
| `TRK-02.babel_street` | Babel Street / Locate-X | medium |
| `TRK-02.safegraph` | SafeGraph / Veraset | medium |
| `TRK-02.predicio_cuebiq` | Predicio / Cuebiq / Teemo | medium |
| `TRK-02.foursquare_pilgrim` | Foursquare Pilgrim / Placed | medium |
| `TRK-02.vermillion_strike` | Vermillion Strike / Near Intelligence | medium |

## TRK-04: Server region / data residency
- **MITRE:** T1437 · **Programmatic** (`Privacy/ConsentProvenanceAnalyzer.swift`). Groups classified endpoints by the owner's country and emits `TRK-04.egress.<country>` for each jurisdiction the app references. Always info: the country is the owner's home jurisdiction, not where a server sits.

## TRK-05: AI / LLM data egress
- **MITRE:** T1437 · **Programmatic** (`Privacy/AIEgressAnalyzer.swift`). LLM, vision and speech SDKs and cloud AI endpoints referenced by the app.

| Rule | Signal | Severity |
|---|---|---|
| `TRK-05.llm_api_endpoints` | cloud LLM hosts (`api.openai.com`, `api.anthropic.com`, Gemini, Mistral, Azure OpenAI, …) | info |
| `TRK-05.llm_sdk_symbols` | linked LLM client SDK (OpenAI, Anthropic, Google Generative AI, Vertex AI, …) | info |
| `TRK-05.speech_to_cloud` | `SFSpeechRecognizer` + cloud STT endpoint (Deepgram / AssemblyAI / …) | info |
| `TRK-05.screen_context_to_llm` | screenshot/image-render API co-occurring with a cloud LLM endpoint | medium |
| `TRK-05.on_device_ml` | on-device ML (CoreML / Foundation Models) with no cloud endpoint (positive signal) | info |

---

# TGAP: Transparency Gap

## TGAP-01: Privacy-manifest gap (used vs declared)
- **MITRE:** T1426 · **Programmatic** (`Privacy/PrivacyManifestGapAnalyzer.swift`). For each of Apple's five **Required-Reason API** categories used in a binary but not declared in `PrivacyInfo.xcprivacy`, emits a `privacy.gap.<category>` finding (info). This is an App Store policy gap.

Also emits `TGAP-01.undeclared_tracking_domains` (info, MASTG-TEST-0281) when the app ships a
privacy manifest declaring at least one tracking domain, yet reaches advertising or attribution
hosts that no declaration covers (a host counts as covered when it matches a declared entry
exactly or is a subdomain of one, as the system matches at runtime). iOS blocks requests to the
declared domains when ATT permission is withheld; an undeclared one keeps working. An app with no
manifest at all is covered by the manifest-gap rule above and is not reported twice.

Categories: `FileTimestamp`, `SystemBootTime`, `DiskSpace`, `ActiveKeyboards`, `UserDefaults`. C-call indicators (`stat`/`fstat`/`lstat`/`getattrlist`/`statfs`) are matched as **exact symbols** (underscore-tolerant) to avoid firing on substrings like `state`/`status`.

The API list per category is Apple's own, from the
[`NSPrivacyAccessedAPIType`](https://developer.apple.com/documentation/bundleresources/app-privacy-configuration/nsprivacyaccessedapitypes/nsprivacyaccessedapitype)
page. `getattrlist`, `fgetattrlist` and `getattrlistat` appear under both file timestamps and disk
space there, so declaring either category covers them.

`Privacy/PrivacyManifestValidator.swift` checks the manifests themselves against Apple's rules
(all info, policy gaps):

| Rule | Signal |
|---|---|
| `TGAP-01.manifest_reason_invalid` | a reason code that is not one of the 17 Apple approves for its category, or an unknown category |
| `TGAP-01.manifest_reason_missing` | a category declared with no reason |
| `TGAP-01.manifest_sdk_only_reason` | the app's own manifest declares `0A2A.1` or `C56D.1`, which Apple reserves for third-party SDKs |
| `TGAP-01.listed_sdk_without_manifest` | a dynamic framework on [Apple's list of SDKs that must ship a manifest](https://developer.apple.com/support/third-party-SDK-requirements/) contains none |
| `TGAP-01.manifest_data_type_invalid` | an `NSPrivacyCollectedDataType` or purpose value that is not on Apple's lists |
| `TGAP-01.manifest_tracking_mismatch` | `NSPrivacyTracking` true without tracking domains, or domains without `NSPrivacyTracking` |
| `TGAP-01.declared_data_collection` | inventory (info): the collected data types the manifests declare, and how many are linked or used for tracking |

## TGAP-02: Consent / ATT ordering integrity
- **MITRE:** T1437 · **Programmatic** (`Privacy/ConsentProvenanceAnalyzer.swift`). Emits `TGAP-02.tracking_without_att` (info) when an advertising, attribution or data-broker SDK is present but the app declares no App Tracking Transparency prompt. That breaks App Store rules and GDPR Art. 5/25. Endpoints owned by the app's publisher (the tracker-DB owner of the domain its bundle ID is written under, so `com.spotify.client` maps to Spotify) do not count unless they are advertising or attribution: Apple defines tracking as linking with data from properties "not owned by you" (App Privacy Details). A parent or sister company still counts (guideline 5.1.1(i) lists "parent, subsidiary or other related entities" among the parties an app shares data with).

## TGAP-03: Child-safety & age-assurance signals
- **MITRE:** T1437 · **Programmatic** (`Privacy/ChildSafetyAnalyzer.swift`). Consumes App Store metadata (genre / content rating) as evidence; store-metadata rules fire in mass-scan, binary-signal rules fire offline too.

| Rule | Signal | Severity |
|---|---|---|
| `TGAP-03.kids_category_trackers` | kids-genre app embedding advertising/attribution SDKs | medium |
| `TGAP-03.coppa_flag_mismatch` | SDK COPPA / child-directed flags in a kids-genre app | medium |
| `TGAP-03.declared_age_range_api` | Apple Declared Age Range API in use (positive disclosure signal) | info |
| `TGAP-03.age_gate_absent` | kids-genre app with no age-gate / age-assurance signal | info |
| `TGAP-03.family_controls` | `com.apple.developer.family-controls` (Screen Time / parental controls) | info |
| `TGAP-03.declared_age_range_entitlement` | `com.apple.developer.declared-age-range` (positive signal) | info |

---

# SURV: Surveillance & Evasion

## SURV-01: VPN / proxy detection
- **MITRE:** T1422 · **Detects:** checks for VPN tunnels and proxy settings. Many rules carry framework allow-lists (`attribution.benign_in_frameworks`, e.g. WireGuardKit, OpenVPNAdapter, NetworkExtension) so legitimate VPN apps aren't over-flagged.

| Rule | Signal | Severity |
|---|---|---|
| `SURV-01.utun_interface_string` | concrete tunnel iface name (`utun0`, `ipsec0`, …, digit-suffixed), case-sensitive; `ipsec3`/`ipsec4` excluded (OpenSSL curve names) | info |
| `SURV-01.getifaddrs_import` | imports `getifaddrs()` | info |
| `SURV-01.nevpnmanager` | `NEVPNManager` / `NETunnelProviderManager` | info |
| `SURV-01.proxy_settings_read` | `CFNetworkCopySystemProxySettings` / HTTP-proxy keys | info |
| `SURV-01.ip_check_endpoints` | IP-echo services (ipify, ifconfig.me, checkip.amazonaws.com) | info |
| `SURV-01.vpn_app_enumeration` | probes installed VPN-client apps via URL schemes | info |

## SURV-02: Anti-analysis / anti-debug / anti-jailbreak
- **MITRE:** T1633 · **Detects:** Frida / Cydia / debugger / dyld checks and ptrace tricks. Polarity **defensive**: evidence of hardening, reported at info. `dyld_image_introspection` is neutral: crash reporters and the Swift runtime enumerate loaded images too.

| Rule | Signal | Severity |
|---|---|---|
| `SURV-02.frida_indicators` | `frida-server` / `frida-gadget` / port `27042` | info |
| `SURV-02.cydia_substrate` | `CydiaSubstrate` / `MobileSubstrate` / `libsubstrate` | info |
| `SURV-02.jailbreak_url_schemes` | `cydia://` / `sileo://` / `filza://` probes | info |
| `SURV-02.jailbreak_file_paths` | jailbreak-only paths (Cydia/apt/MobileSubstrate/jailbreakd) | info |
| `SURV-02.ptrace_deny_attach` | `PT_DENY_ATTACH` / `ptrace` | info |
| `SURV-02.dyld_image_introspection` | `_dyld_image_count` / `_dyld_get_image_name` | info |
| `SURV-02.fork_posix_spawn` | imports `_fork` / `_posix_spawn` (weak: linked ≠ called) | info |
| `SURV-02.is_jailbroken_naming` | `isJailbroken` / `is_rooted` / `jailbreak_detected` | info |

When the main executable is FairPlay-encrypted, `meta.fairplay_main` (info) is recorded as a coverage note.

## SURV-03: Hidden background exfiltration
- **MITRE:** T1437, T1646 · **Detects:** background URL sessions, `BGTaskScheduler`, expiring background tasks used for telemetry drain.

| Rule | Signal | Severity |
|---|---|---|
| `SURV-03.background_url_session` | `backgroundSessionConfigurationWithIdentifier` | info |
| `SURV-03.bg_task_scheduler` | `BGTaskScheduler` / `BGProcessingTaskRequest` | info |
| `SURV-03.expiring_bg_task` | `beginBackgroundTaskWithExpirationHandler` | info |
| `SURV-03.background_fetch` | `UIBackgroundModes` contains `fetch` | info |

## SURV-04: Obfuscation indicators
- **MITRE:** T1406 · **Detects:** runtime string decoding, suspicious constant tables, obfuscated symbol names.

| Rule | Signal | Severity |
|---|---|---|
| `SURV-04.runtime_string_decode` | `deobfuscate` / `xor_decode` / `decryptString` helper names | info |
| `SURV-04.byte_array_constants` | 12+ byte `0xNN, …` runs (string-decoder arrays) | info |
| `SURV-04.tampered_classnames` | `_OBJC_CLASS_$_` + 1–3 letter prefix + 4-digit counter (renaming-obfuscator shape) | info |

## SURV-05: Known spyware / stalkerware IOCs
- **MITRE:** T1456, T1404 · **Detects:** two tiers: state-grade mercenary spyware (CVSS 10.0, **critical**; Citizen Lab / Kaspersky) and consumer stalkerware (CVSS 8.7, **high**; Coalition Against Stalkerware / EFF). Indicators are hand-curated and referenced.

| Rule | Family | Severity |
|---|---|---|
| `SURV-05.pegasus_nso_strings` | NSO Pegasus (BLASTPASS / HOMAGE) | critical |
| `SURV-05.predator_intellexa` | Intellexa / Cytrox Predator | critical |
| `SURV-05.reign_quadream` | QuaDream Reign (ENDOFDAYS) | critical |
| `SURV-05.finfisher` | Gamma Group FinFisher / FinSpy | critical |
| `SURV-05.hermit_rcs` | Hermit / RCS Lab Tykelab | critical |
| `SURV-05.lockdown_bypass_strings` | FORCEDENTRY / BLASTPASS / Lockdown-evasion markers | critical |
| `SURV-05.candiru_devilstongue` | Candiru / DevilsTongue | critical |
| `SURV-05.paragon_graphite` | Paragon Graphite | critical |
| `SURV-05.triangulation_triangledb` | Operation Triangulation / TriangleDB | critical |
| `SURV-05.stalkerware_families` | consumer stalkerware SDK markers (mSpy, FlexiSPY, Cocospy, …) | high |
| `SURV-05.stalkerware_domains` | stalkerware panel / C2 domains | high |
| `SURV-05.stalkerware_capabilities` | covert-monitoring capability markers (corroborated) | high |

---

# SECH: Security Hygiene

## SECH-01: Transport security (ATS / TLS / pinning)
- **MITRE:** T1521 · ATS posture is parsed **programmatically** (`Security/ATSAnalyzer.swift`); two YAML rules cover ATS-bypassing socket APIs.

| Rule | Signal | Severity |
|---|---|---|
| `SECH-01.allows_arbitrary_loads` (prog.) | `NSAllowsArbitraryLoads=YES` (global ATS off) | medium |
| `SECH-01.allows_arbitrary_scoped` (prog.) | ATS off for web content, media or local networking | medium |
| `SECH-01.insecure_exception_domains` (prog.) | exception domains permitting cleartext / TLS<1.2 | medium |
| `SECH-01.missing_pinning` (prog.) | exception domains present but no `NSPinnedDomains` | low |
| `SECH-01.cfstream_plaintext_socket` | raw `CFStream`/`NSStream` socket (TLS opt-in) | info |
| `SECH-01.disabled_cert_validation` | `kCFStreamSSLValidatesCertificateChain` / allow-any-cert in code strings (decrypted binaries only) | critical |
| `SECH-01.cfstream_tls_relaxation_referenced` | CFStream TLS-relaxation keys imported | info |
| `SECH-01.hardcoded_http_urls` | hosts named in `http://` URLs, less XML-namespace and loopback hosts (MASTG-TEST-0321) | info |

## SECH-02: Data-at-rest protection
- **MITRE:** T1409 · **Detects:** world-readable files, plaintext databases, `NSFileProtectionNone`, Keychain misuse markers.

| Rule | Signal | Severity |
|---|---|---|
| `SECH-02.file_protection_none` | `NSFileProtectionNone` in code strings (decrypted binaries only) | medium |
| `SECH-02.file_protection_none_referenced` | `NSFileProtectionNone` imported | info |
| `SECH-02.plaintext_sqlite` | a bundled file with the `SQLite format 3` magic **and** no encryption layer linked (`StorageAnalyzer`, not YAML) | info |
| `SECH-02.userdefaults_credentials` | credential-like keys written to `NSUserDefaults` | medium |
| `SECH-02.keychain_accessible_always` | `kSecAttrAccessibleAlways(ThisDeviceOnly)` in code strings (readable while locked; decrypted binaries only) | medium |
| `SECH-02.keychain_accessible_always_referenced` | the same constants imported (often by a Keychain wrapper) | info |
| `SECH-02.backup_exclusion_marker` | `NSURLIsExcludedFromBackupKey` in use (positive signal) | info |
| `SECH-02.data_protection_entitlement` | `com.apple.developer.default-data-protection` declared (positive signal) | info |

## SECH-03: Cryptography
- **MITRE:** T1521 · **Detects:** weak primitives, ECB mode, hardcoded keys/certs.

| Rule | Signal | Severity |
|---|---|---|
| `SECH-03.weak_hash` | `CC_MD5` / `CC_SHA1` or CryptoKit `Insecure.MD5` / `Insecure.SHA1` (overwhelmingly checksums) | info |
| `SECH-03.embedded_certificates` | embedded PEM cert / public key (normal for pinning) | info |
| `SECH-03.cert_pinning` | TrustKit / `AFSecurityPolicy` / pinning delegate | info |
| `SECH-03.insecure_randomness` | `rand`/`srand`/`random`/`drand48`, `arc4random() %` bias | info |

## SECH-04: Binary hardening
- **MITRE:** T1633 · **Programmatic** (`Security/BinaryHardeningAnalyzer.swift`). Checks each Mach-O for **PIE/ASLR** (`MH_PIE`), **stack canary** (`__stack_chk_*`), **ARC** (`objc_release`/`objc_storeStrong`) and **FairPlay encryption**. The flags are reported as themselves in the Hardening tab; there is no letter grade.

`SECH-04.debug_symbols` (info, MASTG-TEST-0219) counts debugger stab entries (`N_SO`, `N_OSO`, `N_FUN`
and the rest of `<mach-o/stab.h>`) left in each binary's symbol table. `N_OPT` is excluded: the
linker writes one (`radr://5614542`) into stripped binaries too.

## SECH-05: Hardcoded secrets & credentials
- **MITRE:** T1409 · **Programmatic** (`Security/SecretScanner.swift`). Regex matchers with Shannon-entropy gating for the generic pattern; matched tokens are redacted. Severity is the CVSS v4.0 score of the credential class: cloud credential and live-service key 9.3 (**critical**), bearer token 6.9 and generic credential 6.3 (**medium**). Public client identifiers (Firebase and Maps keys under their SDK's setting, OAuth client IDs, OAuth client secrets in a native provider configuration per RFC 8252 §8.5) are info.

Detects: AWS access key, Google API key & OAuth client, Slack token & webhook, Stripe secret key, GitHub token & fine-grained PAT, GitLab PAT, Twilio API key, Anthropic `sk-ant-`, OpenAI `sk-proj-`/`sk-`, HuggingFace `hf_`, SendGrid, Mapbox, Telegram bot token, PEM/OpenSSH private key, JWT, and generic high-entropy `api_key`/`secret`/`token`/`password` assignments.

## SECH-06: Code signing / entitlement posture
- **MITRE:** T1631 · **Detects:** entitlement posture, debuggable/re-signed markers, distribution profile signals.

| Rule | Signal | Severity |
|---|---|---|
| `SECH-06.app_group_entitlement` | `application-groups` (cross-app sharing) | info |
| `SECH-06.universal_links_associated` | `associated-domains` / universal links | info |
| `SECH-06.keychain_access_group` | `keychain-access-groups` (cross-app credential share) | info |
| `SECH-06.network_extension_provider` | NetworkExtension provider entitlement | info |
| `SECH-06.systemextension` / `SECH-06.driverkit` | system-extension / DriverKit install entitlement | medium |
| `SECH-06.aps_environment_production` | `aps-environment` (push) | info |
| `SECH-06.get_task_allow` | `get-task-allow` (debuggable binary; shouldn't ship) | high |
| `SECH-06.dynamic_codesigning` | `dynamic-codesigning` (JIT / RWX memory) | medium |
| `SECH-06.private_entitlements` | `com.apple.private.*` (re-sign / tamper indicator) | medium |
| `SECH-06.dynamic_loader_imports` | imports `dlopen` / `dlsym` (dynamic code loading, MASWE-0049) | info |
| `SECH-06.outdated_signature_format` | `CodeDirectory v` below `20400`, Apple's re-sign threshold (MASTG-TEST-0220) | info |
| `SECH-06.*_entitlement` | twelve sensitive-capability entitlements: Wi-Fi info, HealthKit (and its clinical-record and background-delivery variants), HomeKit, contact notes, NFC reader, notification filtering, location push, SensorKit, multicast, AutoFill credential provider (MASTG-TEST-0362) | info |

## SECH-07: Authentication & keychain protection
- **MITRE:** (none) · **Detects:** local-authentication policy strength and Keychain protection.

| Rule | Signal | Severity |
|---|---|---|
| `SECH-07.keychain_in_use` | `SecItemAdd`/`SecItemCopyMatching` (Keychain in use) | info |
| `SECH-07.access_control_flags` | `SecAccessControlCreateWithFlags` imported (positive signal) | info |
| `SECH-07.app_attest` | `com.apple.developer.devicecheck.appattest-environment` (App Attest in use) | info |

## SECH-08: SDK provenance & supply chain
- **MITRE:** T1474 · **Programmatic** (`Privacy/ConsentProvenanceAnalyzer.swift`). Emits `SECH-08.sdk_owner.<owner>` (info) per distinct embedded-SDK owner, as an inventory of the supply chain. Data-broker and AI recipients carry their own findings under TRK-02 and TRK-05.

## SECH-09: Platform version
- **Programmatic** (`Plist/PlatformVersionAnalyzer.swift`), bound to MASWE-0041 and MASWE-0042.
  `SECH-09.platform_versions` (info) records `MinimumOSVersion`, the build SDK (`DTPlatformVersion`,
  `DTSDKName`) and Xcode (`DTXcode`) from Info.plist. `SECH-09.sdk_below_upload_minimum` (info)
  fires when the build SDK is older than the one App Store Connect requires for uploads, read from
  `Rules/platform/requirements.json` ([iOS 26 SDK since 28 April 2026](https://developer.apple.com/news/upcoming-requirements/?id=04282026a)).

---

# PLAT: Platform Attack Surface

## PLAT-01: WebView / JavaScript bridge
- **MITRE:** T1417 · **Detects:** `WKWebView`, JS evaluation bridges, message handlers, injected scripts. Bridges are a common channel for credential and user-agent exfiltration.

| Rule | Signal | Severity |
|---|---|---|
| `PLAT-01.wkwebview_use` | `WKWebView` / `WKWebViewConfiguration` | info |
| `PLAT-01.js_message_handler` | `WKScriptMessageHandler` (JS→native bridge) | info |
| `PLAT-01.js_evaluate` | `evaluateJavaScript` | info |
| `PLAT-01.user_script_injection` | `WKUserScript` injection at document start/end | info |
| `PLAT-01.legacy_uiwebview` | deprecated `UIWebView` (no process isolation) | high |
| `PLAT-01.webview_inspectable` | `isInspectable = true` shipped in release (remote-debug door) | info |
| `PLAT-01.file_url_access` | `allowFileAccessFromFileURLs` / `allowUniversalAccessFromFileURLs` | info |
| `PLAT-01.js_bridge_all_frames` | message-handler script injected into all frames (`forMainFrameOnly:false`) | medium |

## PLAT-02: Deep-link / URL-scheme handler exposure
- **MITRE:** T1474, T1631 · **Programmatic** (`Plist/InfoPlistAnalyzer.swift`). Emits `PLAT-02.custom_url_schemes` (info) enumerating the custom URL schemes the app registers via `CFBundleURLSchemes` (standard schemes excluded). These are inbound, unverified entry points. MASWE-0029 makes it a weakness only when a sensitive flow relies on the scheme or the handler skips validation, which MASTG-TEST-0370/0371 read from the handler code. This is the *handler* side; DCS-06 is the *query* side.

## PLAT-03: App extensions & custom keyboards
- **MITRE:** T1417 · **Programmatic** (`Security/AppExtensionAnalyzer.swift`). Walks `PlugIns/*.appex/Info.plist`.

| Rule | Signal | Severity |
|---|---|---|
| `PLAT-03.keyboard_open_access` | custom keyboard with `RequestsOpenAccess=YES` (can send keystrokes off the device once the user allows Full Access) | medium |
| `PLAT-03.custom_keyboard` | custom keyboard without open access (informational) | info |
| `PLAT-03.truepredicate_activation` | extension activates on all content (`NSExtensionActivationRule=TRUEPREDICATE`) | info |
| `PLAT-03.custom_keyboards_restricted` | `UIApplicationKeyboardExtensionPointIdentifier` imported: the app can refuse third-party keyboards (positive signal, MASTG-TEST-0389) | info |

## PLAT-04: Background-activation surface
- **MITRE:** T1541, T1398, T1645 · **Detects:** background-execution and remote-wakeup surface: `UIBackgroundModes`, VoIP/background processing, and silent / VoIP / critical push.

| Rule | Signal | Severity |
|---|---|---|
| `PLAT-04.bg_location_mode` | `UIBackgroundModes` contains `location` | info |
| `PLAT-04.bg_voip_mode` | `UIBackgroundModes` contains `voip` | info |
| `PLAT-04.bg_processing` | `UIBackgroundModes` contains `processing` | info |
| `PLAT-04.voip_push` | `PKPushRegistry` / `didReceiveIncomingPush` | info |
| `PLAT-04.silent_remote_notification` | `content-available` silent push + `remote-notification` mode | info |
| `PLAT-04.critical_alerts` | critical-alert push entitlement | info |
| `PLAT-04.communication_push` | communication-style push entitlement | info |
| `PLAT-04.time_sensitive` | time-sensitive notifications entitlement | info |

The `Info.plist` analyzer also emits `PLAT-04.background_modes` summarising all suspicious background modes (high when `location`/`voip` present).

---

# Sources

Every rule cites at least one page in its `references:` field. The citations appear under each
finding in the report, in `report.json` and in SARIF.

The list of permitted sources is
[`Resources/Rules/taxonomy/sources.json`](../Sources/ScannerKit/Resources/Rules/taxonomy/sources.json):
OWASP MASVS/MASTG/MASWE, Apple Developer and Apple Platform Security, FIRST CVSS, MITRE ATT&CK and
CWE, NIST, IETF RFCs, Citizen Lab, Kaspersky Securelist, the Coalition Against
Stalkerware and EFF, the US FTC, LINDDUN, EUR-Lex and Exodus Privacy, plus first-party SDK vendor
documentation used only to identify an SDK.

`CitationTests` fails when a rule cites nothing, cites a URL outside that list, or cites an Android
MASTG test. The attribution table in [`THIRD_PARTY.md`](../THIRD_PARTY.md) is generated from the
rules' citations by `ISAT --sources-report`.

Spyware and broker indicators are picked by hand from the cited reporting. Third-party code that is
bundled or linked (`ipatool`, Yams, ECharts) is listed in `THIRD_PARTY.md`.
