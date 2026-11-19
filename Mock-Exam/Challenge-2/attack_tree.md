graph TD
    A1["Compromise OpenEMR confidentiality, integrity, availability, or accountability through potential weaknesses"]
    B1["Compromise staff, administrator, or patient authentication"]
    A1 --> B1
    C1["Obtain credentials and defeat applicable authentication controls"]
    B1 --> C1
    D1["Use phishing, credential reuse, or password guessing where login protections are insufficient"]
    C1 --> D1
    D2["Capture and relay TOTP codes through phishing where phishing-resistant MFA is not enforced"]
    C1 --> D2
    D3["Guess or reuse TOTP codes where verification lacks rate limits or replay prevention"]
    C1 --> D3
    D4["Exploit missing WebAuthn challenge, origin, relying-party, or user-verification checks"]
    C1 --> D4
    C2["Bypass MFA through enrollment, recovery, or alternate authentication paths"]
    B1 --> C2
    D5["Enroll an attacker-controlled factor without sufficient identity verification"]
    C2 --> D5
    D6["Abuse weak MFA reset procedures, recovery codes, or administrator-assisted recovery"]
    C2 --> D6
    D7["Reach legacy, portal, LDAP, or alternate login routes that do not enforce required MFA"]
    C2 --> D7
    D8["Access protected functions using a partially authenticated session before MFA completion"]
    C2 --> D8
    C3["Take over patient identities through portal enrollment and account recovery"]
    B1 --> C3
    D9["Link a self-registered account to another patient's record through weak identity matching"]
    C3 --> D9
    D10["Exploit predictable, leaked, reusable, or incorrectly scoped password-reset tokens"]
    C3 --> D10
    D11["Poison reset links through untrusted host headers or redirect parameters"]
    C3 --> D11
    D12["Use a compromised recovery mailbox to reset credentials or approve account changes"]
    C3 --> D12
    C4["Exploit optional LDAP or Active Directory authentication weaknesses"]
    B1 --> C4
    D13["Manipulate LDAP queries where authentication inputs are not safely handled"]
    C4 --> D13
    D14["Intercept directory credentials where encrypted transport and certificate validation are absent"]
    C4 --> D14
    D15["Abuse incorrect directory-group mapping or fail-open behavior to obtain application privileges"]
    C4 --> D15
    B2["Hijack sessions or abuse authenticated browser interactions"]
    A1 --> B2
    C5["Steal or reuse authenticated sessions"]
    B2 --> C5
    D16["Obtain session cookies through compromised endpoints, exposed session storage, or insecure transport"]
    C5 --> D16
    D17["Exploit session fixation where identifiers are not rotated after login or privilege changes"]
    C5 --> D17
    D18["Reuse sessions that remain valid after logout, password reset, account disablement, or MFA changes"]
    C5 --> D18
    D19["Exploit overly broad cookie domains, missing cookie protections, or cross-site session confusion"]
    C5 --> D19
    C6["Execute attacker-controlled scripts in staff or patient browsers"]
    B2 --> C6
    D20["Store scripts in clinical notes, demographics, messages, forms, filenames, or imported content"]
    C6 --> D20
    D21["Exploit reflected or DOM-based XSS in search, reporting, portal, or legacy front-end components"]
    C6 --> D21
    D22["Render active uploaded HTML or SVG content under the application's trusted origin"]
    C6 --> D22
    C7["Induce unauthorized actions through an authenticated user's browser"]
    B2 --> C7
    D23["Exploit missing or ineffective CSRF checks on administrative, clinical, or account-management actions"]
    C7 --> D23
    D24["Abuse state-changing GET endpoints or cross-origin trust misconfigurations"]
    C7 --> D24
    D25["Use clickjacking where sensitive workflows lack framing protections"]
    C7 --> D25
    B3["Cross role, patient, or practice authorization boundaries"]
    A1 --> B3
    C8["Access another patient's records through missing object-level authorization"]
    B3 --> C8
    D26["Change record identifiers in demographics, encounters, labs, messages, appointments, or billing requests"]
    C8 --> D26
    D27["Access documents, thumbnails, exports, or download links without checking patient ownership"]
    C8 --> D27
    D28["Abuse incorrect guardian, proxy, household, or delegated-access relationships"]
    C8 --> D28
    C9["Escalate from patient or limited staff permissions to privileged functions"]
    B3 --> C9
    D29["Call backend administrative endpoints protected only by hidden user-interface controls"]
    C9 --> D29
    D30["Exploit inconsistent phpGACL enforcement across core pages, modules, reports, and APIs"]
    C9 --> D30
    D31["Modify roles, account ownership, or protected record fields through mass assignment"]
    C9 --> D31
    D32["Reuse stale privileges after role changes or exploit authorization-check race conditions"]
    C9 --> D32
    C10["Escape multi-site practice isolation"]
    B3 --> C10
    D33["Manipulate site selectors, host routing, or request parameters to select another practice"]
    C10 --> D33
    D34["Reuse sessions, tokens, caches, or background-job identifiers not bound to the correct site"]
    C10 --> D34
    D35["Read another site's documents or configuration through shared filesystem permissions"]
    C10 --> D35
    D36["Reach other practice databases through shared or overprivileged database credentials"]
    C10 --> D36
    C11["Misuse legitimate privileged access"]
    B3 --> C11
    D37["Use excessive staff privileges to browse or export records unrelated to assigned duties"]
    C11 --> D37
    D38["Abuse administrator powers to create accounts, weaken access controls, or redirect data flows"]
    C11 --> D38
    B4["Compromise OAuth, OpenID Connect, SMART, REST, or FHIR interfaces"]
    A1 --> B4
    C12["Subvert OAuth authorization and SMART launch flows"]
    B4 --> C12
    D39["Steal authorization codes through permissive redirect URI matching or open redirects"]
    C12 --> D39
    D40["Exploit missing PKCE enforcement, state validation, nonce validation, or client binding"]
    C12 --> D40
    D41["Tamper with SMART patient, encounter, or launch context where bindings are not verified"]
    C12 --> D41
    D42["Register deceptive or overprivileged clients where dynamic registration and consent controls are weak"]
    C12 --> D42
    C13["Forge, steal, or replay API credentials and tokens"]
    B4 --> C13
    D43["Exploit incorrect JWT signature, algorithm, issuer, audience, expiry, or key validation"]
    C13 --> D43
    D44["Replay client assertions where assertion lifetimes and unique identifiers are not enforced"]
    C13 --> D44
    D45["Steal client secrets, signing keys, access tokens, or refresh tokens from apps, logs, or configuration"]
    C13 --> D45
    D46["Maintain access through missing refresh-token rotation, reuse detection, or revocation"]
    C13 --> D46
    C14["Exceed intended API data-access permissions"]
    B4 --> C14
    D47["Use patient-scoped tokens against other patients or system-scoped endpoints"]
    C14 --> D47
    D48["Exploit inconsistent scope enforcement across REST, FHIR, portal, search, and batch operations"]
    C14 --> D48
    D49["Retrieve restricted related resources through FHIR includes, reverse includes, history, or search results"]
    C14 --> D49
    D50["Read protected fields or modify immutable properties through excessive response data or weak field authorization"]
    C14 --> D50
    D51["Access Bulk FHIR export jobs, status endpoints, manifests, or output files without proper ownership checks"]
    C14 --> D51
    B5["Exploit server-side input handling and file-processing weaknesses"]
    A1 --> B5
    C15["Inject database queries"]
    B5 --> C15
    D52["Reach unsafe SQL construction through search, reporting, billing, portal, or API parameters"]
    C15 --> D52
    D53["Trigger second-order SQL injection through previously stored or imported data"]
    C15 --> D53
    D54["Use successful SQL injection to read PHI, alter clinical records, or change account and audit data"]
    C15 --> D54
    C16["Execute code through unsafe server-side processing"]
    B5 --> C16
    D55["Inject operating-system commands through backup, conversion, fax, or administrative utilities"]
    C16 --> D55
    D56["Exploit unsafe PHP deserialization or attacker-controlled template evaluation"]
    C16 --> D56
    D57["Exploit unsafe file inclusion or exploitable PHP and dependency vulnerabilities in deployed versions"]
    C16 --> D57
    C17["Abuse document upload, extraction, and rendering"]
    B5 --> C17
    D58["Upload executable content where extension, content, storage, and execution controls are insufficient"]
    C17 --> D58
    D59["Overwrite application files through unsafe upload filenames or archive extraction paths"]
    C17 --> D59
    D60["Exploit vulnerable PDF, image, scanner, or document-conversion libraries with crafted files"]
    C17 --> D60
    C18["Read or overwrite files through path-handling weaknesses"]
    B5 --> C18
    D61["Traverse document, export, download, or site paths to reach files outside authorized directories"]
    C18 --> D61
    D62["Abuse symbolic links, temporary-file races, or insecure filesystem permissions"]
    C18 --> D62
    D63["Read sqlconf.php, integration secrets, session files, or encryption keys after gaining file access"]
    C18 --> D63
    C19["Abuse server-side network access and XML parsing"]
    B5 --> C19
    D64["Trigger SSRF through remote imports, URL previews, integration configuration, or metadata retrieval"]
    C19 --> D64
    D65["Use SSRF to reach internal services or cloud metadata where network and metadata protections permit"]
    C19 --> D65
    D66["Exploit external entity resolution in CCDA or other XML processing to read files or reach internal services"]
    C19 --> D66
    B6["Compromise deployment, host, database, or cloud infrastructure"]
    A1 --> B6
    C20["Abuse exposed deployment and maintenance surfaces"]
    B6 --> C20
    D67["Reach setup.php or sql_upgrade.php where installation and upgrade controls remain accessible"]
    C20 --> D67
    D68["Access diagnostic pages, administrative consoles, default accounts, or development endpoints"]
    C20 --> D68
    D69["Retrieve source archives, repository metadata, configuration copies, or directory listings from the web root"]
    C20 --> D69
    C21["Exploit web stack and reverse-proxy weaknesses"]
    B6 --> C21
    D70["Exploit known vulnerabilities in unsupported PHP 7.x deployments or unpatched web-stack components"]
    C21 --> D70
    D71["Abuse Apache, Nginx, or PHP-FPM routing errors to execute unintended files or disclose source"]
    C21 --> D71
    D72["Exploit proxy parsing differences, trusted forwarding headers, or cache rules to bypass controls or expose PHI"]
    C21 --> D72
    D73["Reach an exposed origin server directly to bypass reverse-proxy access restrictions"]
    C21 --> D73
    C22["Obtain host or container administrative access"]
    B6 --> C22
    D74["Use stolen SSH keys, weak remote-administration credentials, or exposed management services"]
    C22 --> D74
    D75["Escalate application-user access through vulnerable host software or unsafe service permissions"]
    C22 --> D75
    D76["Escape container boundaries through privileged containers, exposed Docker sockets, or sensitive host mounts"]
    C22 --> D76
    D77["Use writable cron scripts, backup scripts, or service configuration to gain persistent execution"]
    C22 --> D77
    C23["Compromise database and cloud control planes"]
    B6 --> C23
    D78["Access exposed MySQL or MariaDB services using stolen credentials or weak database authentication"]
    C23 --> D78
    D79["Abuse excessive database privileges to access additional schemas, files, or administrative functions"]
    C23 --> D79
    D80["Use leaked cloud credentials or overprivileged instance identities to access storage, snapshots, or compute resources"]
    C23 --> D80
    C24["Intercept traffic across inadequately protected network boundaries"]
    B6 --> C24
    D81["Capture or alter browser, proxy-to-origin, database, or integration traffic lacking authenticated encryption"]
    C24 --> D81
    D82["Redirect connections through compromised DNS or missing TLS certificate and SFTP host-key validation"]
    C24 --> D82
    B7["Compromise modules, dependencies, or software delivery"]
    A1 --> B7
    C25["Execute malicious third-party modules with application privileges"]
    B7 --> C25
    D83["Use compromised administrator access or weak installer authorization to install a malicious module"]
    C25 --> D83
    D84["Trick administrators into installing a trojanized or counterfeit extension"]
    C25 --> D84
    D85["Exploit vulnerable installed modules to reach shared PHI, secrets, and application functionality"]
    C25 --> D85
    C26["Tamper with dependencies, updates, or deployment artifacts"]
    B7 --> C26
    D86["Compromise package maintainers, dependency sources, build pipelines, or deployment credentials"]
    C26 --> D86
    D87["Substitute unverified application updates, module archives, or container images"]
    C26 --> D87
    D88["Inject malicious browser code through compromised JavaScript dependencies or third-party asset hosting"]
    C26 --> D88
    B8["Abuse external integrations and trusted healthcare data exchanges"]
    A1 --> B8
    C27["Impersonate trusted integration senders or services"]
    B8 --> C27
    D89["Use stolen SFTP keys, API credentials, SMTP credentials, or Direct messaging credentials"]
    C27 --> D89
    D90["Forge callbacks or webhooks where sender signatures, freshness, and destination bindings are not verified"]
    C27 --> D90
    D91["Compromise a laboratory, clearinghouse, HISP, e-prescribing, payment, or telehealth provider trusted by the application"]
    C27 --> D91
    C28["Inject or misassociate exchanged healthcare data"]
    B8 --> C28
    D92["Submit malformed or malicious HL7, X12, CCDA, registry, or Direct message content to vulnerable importers"]
    C28 --> D92
    D93["Manipulate patient identifiers, ordering-provider identifiers, or reconciliation rules to attach data to the wrong record"]
    C28 --> D93
    D94["Replay valid messages where deduplication, ordering, and transaction binding are insufficient"]
    C28 --> D94
    C29["Redirect outgoing PHI and integration traffic"]
    B8 --> C29
    D95["Change laboratory, clearinghouse, registry, backup, or messaging destinations to attacker-controlled endpoints"]
    C29 --> D95
    D96["Alter patient contact details or recipient mappings to receive reminders, records, faxes, or secure messages"]
    C29 --> D96
    D97["Exploit exposed telehealth invitations, recordings, or provider tokens to access consultations"]
    C29 --> D97
    B9["Expose or exfiltrate sensitive patient and operational data"]
    A1 --> B9
    C30["Retrieve documents, backups, or exports outside application authorization"]
    B9 --> C30
    D98["Directly download files under sites/<site>/documents where web-server access restrictions are absent"]
    C30 --> D98
    D99["Access publicly exposed backup buckets, database dumps, VM snapshots, or shared storage"]
    C30 --> D99
    D100["Reuse unprotected export links, temporary report files, or excessively long-lived signed download URLs"]
    C30 --> D100
    C31["Recover data from secondary disclosure channels"]
    B9 --> C31
    D101["Read PHI or secrets in debug output, exception traces, audit records, API logs, or monitoring systems"]
    C31 --> D101
    D102["Recover PHI from browser caches, shared proxy caches, print spools, temporary files, or abandoned sessions"]
    C31 --> D102
    D103["Obtain production records copied into less protected test, development, support, or analytics environments"]
    C31 --> D103
    D104["Infer patient membership or sensitive facts from enumeration responses, counts, or error differences"]
    C31 --> D104
    C32["Defeat storage confidentiality controls"]
    B9 --> C32
    D105["Read unencrypted database, document, backup, or snapshot media after storage access"]
    C32 --> D105
    D106["Recover encryption keys stored with encrypted data or accessible to compromised application and backup accounts"]
    C32 --> D106
    D107["Use compromised application access to obtain plaintext despite encryption at rest"]
    C32 --> D107
    C33["Extract PHI in bulk through otherwise legitimate functionality"]
    B9 --> C33
    D108["Abuse reporting, database backup, patient export, or Bulk FHIR permissions to collect large datasets"]
    C33 --> D108
    D109["Enumerate records gradually where access monitoring and extraction limits do not detect misuse"]
    C33 --> D109
    B10["Manipulate clinical, scheduling, billing, or payment workflows"]
    A1 --> B10
    C34["Alter care-critical clinical information"]
    B10 --> C34
    D110["Change allergies, medications, diagnoses, lab results, notes, or care plans using compromised write access"]
    C34 --> D110
    D111["Bypass signing, amendment, provenance, or approval controls to conceal unauthorized clinical changes"]
    C34 --> D111
    D112["Manipulate clinical decision rules, order mappings, or units to produce misleading care recommendations"]
    C34 --> D112
    D113["Abuse weak concurrency controls to overwrite recent clinical updates or duplicate orders"]
    C34 --> D113
    C35["Abuse prescribing and medication inventory workflows"]
    B10 --> C35
    D114["Impersonate authorized prescribers or bypass required approval controls for prescription requests"]
    C35 --> D114
    D115["Alter pharmacy destinations, dosage information, refill requests, or medication inventory records"]
    C35 --> D115
    C36["Commit billing or payment fraud"]
    B10 --> C36
    D116["Modify coding, fee sheets, claims, remittances, or payment-posting records through unauthorized access"]
    C36 --> D116
    D117["Manipulate transaction amounts, account bindings, refunds, or gateway callbacks"]
    C36 --> D117
    D118["Replay non-idempotent financial requests or change settlement destinations"]
    C36 --> D118
    C37["Disrupt patient coordination through workflow manipulation"]
    B10 --> C37
    D119["Cancel or alter appointments, referrals, reminders, or staff messages without appropriate authorization"]
    C37 --> D119
    D120["Merge, split, or reassign patient records through insufficiently protected identity-management functions"]
    C37 --> D120
    B11["Disrupt application availability or destroy recoverability"]
    A1 --> B11
    C38["Exhaust public-facing application resources"]
    B11 --> C38
    D121["Flood web, portal, API, login, or TLS endpoints where resource limits are insufficient"]
    C38 --> D121
    D122["Trigger expensive FHIR searches, bulk exports, reports, or clinical-quality calculations"]
    C38 --> D122
    D123["Consume worker, memory, or storage capacity with oversized uploads, archive expansion, or complex document parsing"]
    C38 --> D123
    D124["Abuse login lockouts, registration, reset messages, or notification endpoints to deny access or exhaust quotas"]
    C38 --> D124
    C39["Disable databases, storage, or background processing"]
    B11 --> C39
    D125["Exhaust database connections or induce costly queries, contention, and long-running locks"]
    C39 --> D125
    D126["Fill disks with documents, logs, temporary exports, or repeated backups"]
    C39 --> D126
    D127["Overload cron jobs, integration queues, or retry mechanisms with malformed or repeated work"]
    C39 --> D127
    D128["Exploit synchronous dependency handling so external-service outages block critical workflows"]
    C39 --> D128
    C40["Deploy ransomware or destructive changes after obtaining write or execution access"]
    B11 --> C40
    D129["Encrypt or delete patient documents, databases, configuration, or application code"]
    C40 --> D129
    D130["Stop clinical services or corrupt records needed for safe patient care"]
    C40 --> D130
    D131["Spread destructive access across practices through shared hosts, accounts, or storage"]
    C40 --> D131
    C41["Prevent recovery from outages or compromise"]
    B11 --> C41
    D132["Delete or encrypt reachable backups using application, administrator, or cloud credentials"]
    C41 --> D132
    D133["Disable backup schedules, shorten retention, or alter backup destinations"]
    C41 --> D133
    D134["Poison backup contents or destroy required recovery keys and configuration"]
    C41 --> D134
    B12["Conceal unauthorized activity and sustain compromised access"]
    A1 --> B12
    C42["Evade or tamper with application audit trails"]
    B12 --> C42
    D135["Use unlogged module, API, export, or direct-database access paths"]
    C42 --> D135
    D136["Modify or delete audit records through excessive database or administrative permissions"]
    C42 --> D136
    D137["Disable audit logging or tamper-evident checks through compromised settings or code"]
    C42 --> D137
    D138["Recompute audit checksums where verification secrets and logs share the compromised trust boundary"]
    C42 --> D138
    D139["Forge log entries or corrupt audit interpretation through unsanitized logged input"]
    C42 --> D139
    C43["Suppress detection and accountability"]
    B12 --> C43
    D140["Alter clocks, user attribution, alert destinations, or logging configuration"]
    C43 --> D140
    D141["Flood logs or exhaust logging storage to obscure malicious events"]
    C43 --> D141
    D142["Exploit shared accounts or weak service-account attribution to disguise the responsible actor"]
    C43 --> D142
    C44["Maintain access after initial compromise"]
    B12 --> C44
    D143["Create hidden privileged users, additional MFA factors, or unauthorized OAuth clients"]
    C44 --> D143
    D144["Retain unrevoked refresh tokens, API keys, integration credentials, or SSH keys"]
    C44 --> D144
    D145["Persist through malicious modules, altered application files, scheduled tasks, or poisoned deployment artifacts"]
    C44 --> D145