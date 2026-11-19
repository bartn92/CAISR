## Spoofing

### S1 — Staff authentication and PHP session impersonation

```gherkin
Feature: Prevent impersonation through alternate staff login paths and stolen PHP sessions

  Background:
    Given an OpenEMR test deployment containing synthetic patient records
    And a clinician account authorized to access PHI and initiate prescription workflows
    And staff authentication policy requires MFA on every enabled login path

  Scenario Outline: Stolen staff credentials cannot bypass MFA through alternate authentication
    Given an attacker possesses the clinician's password but not an MFA factor
    When the attacker authenticates through "<login_path>"
    Then no authenticated application session should be issued before successful MFA
    And PHI and record-changing endpoints should remain inaccessible
    And the authentication event should identify the account and login path without recording credentials

    Examples:
      | login_path                 |
      | primary staff login        |
      | alternate LDAP-backed login|
      | legacy direct login handler|

  Scenario: A stolen PHP session cannot authorize a sensitive action without fresh verification
    Given an attacker has copied an authenticated clinician PHP session cookie
    And prescription initiation requires fresh MFA verification
    When the attacker submits a prescription request using the copied cookie without fresh verification
    Then the prescription request should not be committed
    And the application should require verification bound to the clinician and sensitive action
    And the rejected attempt should be audited without recording the session cookie

  Scenario: Revoked and expired PHP sessions cannot be replayed
    Given an attacker has copied a clinician's authenticated PHP session cookie
    When the clinician logs out or an administrator revokes that session
    Then replaying the cookie should not provide access to PHI
    And replaying it against a record-changing endpoint should not modify records
    And the same rejection should apply after the configured idle or absolute session timeout

  Scenario: Legitimate MFA login establishes a protected session
    Given the clinician has valid credentials and an enrolled MFA factor
    And the browser has a pre-authentication PHP session identifier
    When the clinician successfully completes authentication and MFA
    Then a new session identifier should replace the pre-authentication identifier
    And the session cookie should have Secure, HttpOnly, and the configured SameSite protection
    And the clinician should access only records and workflows allowed by their role and site
```

### S2 — Patient Portal registration and account recovery

```gherkin
Feature: Prevent Patient Portal accounts from being linked to another patient's chart

  Background:
    Given an existing patient chart contains synthetic demographics and a registered email address
    And Patient Portal chart association requires approved identity verification beyond knowledge of demographics
    And recovery policy does not permit email access alone to replace patient identity verification

  Scenario: Knowledge of patient demographics does not permit fraudulent chart association
    Given an attacker knows the existing patient's name, date of birth, and email address
    When the attacker self-registers using those details and an attacker-controlled email address
    Then the account should not be associated with the existing patient's chart
    And no records, lab results, appointments, or patient messages should be disclosed
    And the response should not reveal whether the supplied demographics match an existing chart

  Scenario Outline: Password-reset tokens remain bound to the intended patient account
    Given a password-reset token was issued for patient account A
    When an attacker attempts "<misuse>"
    Then no password or chart association should be changed
    And the attempted misuse should be recorded without logging the reset token

    Examples:
      | misuse                                                   |
      | redeeming the token while specifying patient account B    |
      | changing the site selector during token redemption        |
      | redeeming the token after its configured expiration       |
      | redeeming the token after it has already been used        |
      | redeeming the token after a replacement token invalidated it |

  Scenario: Compromise of patient email alone cannot complete account takeover
    Given an attacker controls the patient's email inbox
    But the attacker cannot satisfy the independent recovery verification
    When the attacker follows a valid password-reset email
    Then the attacker should not obtain an authenticated patient session
    And the attacker should not replace enrolled factors or change chart associations
    And recovery should require the approved independent verification process

  Scenario: Verified patient registration and recovery affect only the correct chart
    Given the patient completes the approved identity-verification process
    When the patient completes registration or an authorized password reset
    Then the portal account should be associated only with the verified patient and site
    And a successful reset should invalidate the reset token and sessions required by recovery policy
    And the patient should receive a security notification without unnecessary PHI
```

### S3 — SMART on FHIR client impersonation and system-client keys

```gherkin
Feature: Prevent OAuth application and system-client impersonation

  Background:
    Given SMART on FHIR authorization and dynamic client registration are enabled
    And a trusted application and a bulk-access system client are registered
    And tests use synthetic FHIR resources and disposable signing keys

  Scenario: Dynamic registration does not confer the identity or trust of an existing application
    Given a malicious application copies the trusted application's display name and logo
    When it submits dynamic client registration requesting privileged scopes
    Then registration should follow the configured client approval policy
    And it should not inherit the trusted application's client identifier, approval status, or scopes
    And any consent screen should distinguish the client's verified identity from its supplied branding

  Scenario Outline: Authorization responses cannot be redirected or rebound to an attacker
    Given an authorization transaction exists for the trusted SMART application
    When an attacker attempts "<attack>"
    Then the transaction should not issue a usable code or token to the attacker
    And no PHI should be returned
    And the rejection should not expose authorization codes or tokens in logs

    Examples:
      | attack                                                        |
      | use an unregistered redirect URI                              |
      | use a redirect URI with an attacker-controlled subdomain suffix|
      | use a redirect URI with an unregistered path or query          |
      | substitute a missing or mismatched state value in the callback |
      | redeem the code using the wrong PKCE verifier                  |
      | redeem the code for a different client or redirect URI         |
      | redeem an already consumed authorization code                 |

  Scenario Outline: Invalid system-client assertions cannot obtain bulk-access tokens
    Given the bulk-access system client authenticates using signed JWT assertions
    When a token request contains "<assertion_condition>"
    Then client authentication should fail
    And no access token or bulk export should be created
    And the failure should identify the client and validation category without exposing the assertion

    Examples:
      | assertion_condition                         |
      | a signature from an unregistered key        |
      | an incorrect audience                       |
      | inconsistent issuer and subject             |
      | an expired assertion                        |
      | a previously accepted assertion identifier  |
      | a signature from a revoked signing key      |

  Scenario: Key-compromise response prevents continued use of a stolen system-client key
    Given an attacker has copied a valid bulk-access client signing key
    And an administrator has completed the configured client-compromise revocation procedure
    When the attacker uses the compromised key or a previously issued affected token
    Then access should be rejected within the documented revocation propagation bound
    And the event should be correlated with the compromised client
    And the replacement approved key should work only with the client's authorized scopes and sites

  Scenario: An approved SMART application completes a correctly bound authorization flow
    Given the approved application uses its registered redirect URI and a fresh authorization transaction
    When the user consents and the application completes state validation and PKCE verification
    Then the application should receive only the approved scopes and patient context
    And the authorization code should be single-use
```

### S4 — External provider impersonation

```gherkin
Feature: Authenticate laboratories, clearinghouses, and payment providers

  Background:
    Given OpenEMR receives HL7 results, X12 remittances, and payment notifications
    And each integration has a configured provider identity, site, and allowed message types

  Scenario Outline: Unverified provider identity cannot authorize an inbound message
    Given an attacker submits a fabricated integration message
    When the message arrives with "<identity_condition>"
    Then the message should be rejected or quarantined before operational posting
    And no clinical result, account balance, or payment status should change
    And the failed provider verification should be audited

    Examples:
      | identity_condition                                  |
      | missing required credentials                        |
      | revoked integration credentials                     |
      | a certificate issued for a different peer identity  |
      | an untrusted or expired client certificate          |
      | an invalid required provider message signature      |
      | valid credentials belonging to another provider site|

  Scenario: Stolen credentials alone cannot bypass a configured independent peer check
    Given a laboratory integration requires both an integration credential and mutual TLS
    And an attacker possesses the credential but not the laboratory's approved client key
    When the attacker submits an HL7 result
    Then peer authentication should fail
    And the result should not enter the clinical import queue

  Scenario: A verified provider can submit only authorized message types
    Given a laboratory connection satisfies all configured identity checks
    When it submits a valid HL7 result for its authorized site and patient mapping
    Then the result should proceed to integrity and linkage validation
    But a payment notification submitted using the same laboratory identity should be rejected
    And the audit trail should retain the verified provider identity
```

## Tampering

### T1 — SQL injection in legacy PHP and API endpoints

```gherkin
Feature: Prevent SQL injection from changing clinical and financial records

  Background:
    Given a test database contains synthetic allergies, medications, encounters, insurance, and billing entries
    And baseline values and integrity hashes have been recorded
    And legacy PHP search, reporting, billing, and API endpoints are available for authorized testing

  Scenario Outline: Crafted query inputs cannot alter database statements
    Given an authenticated user can access the "<endpoint>" endpoint
    When the user submits a bounded SQL-injection test corpus through query, form, and JSON fields
    Then input should be rejected or treated strictly as data
    And no injected statement should execute
    And unrelated clinical and financial baseline records should remain unchanged
    And responses should not expose SQL statements, schema details, or database credentials

    Examples:
      | endpoint         |
      | patient search   |
      | clinical report  |
      | billing lookup   |
      | patient API      |

  Scenario: Reporting database credentials cannot modify operational records
    Given a reporting workflow is intended to perform read-only queries
    When its database identity is tested for update, delete, schema-change, and file-write privileges
    Then those operations should be denied
    And permitted report queries should still succeed
    And no excessive database privilege should be available through the reporting connection

  Scenario: Legitimate special characters remain valid data
    Given a clinician is authorized to update a synthetic patient's allergy notes
    When the clinician saves text containing apostrophes, quotation marks, and Unicode characters
    Then the text should be stored accurately using parameterized database operations
    And only the authorized patient's intended field should change
    And the change should be attributed to the clinician in the audit trail
```

### T2 — Stored XSS and missing CSRF protection

```gherkin
Feature: Prevent stored browser content and cross-site requests from changing records

  Background:
    Given staff browsers render clinical forms, patient messages, demographics, and document metadata
    And synthetic patient records and a controlled browser test harness are available

  Scenario Outline: Stored active content does not execute when viewed by staff
    Given an attacker can submit content through "<source>"
    When the attacker stores script, event-handler, URL, and markup test inputs
    And a staff member views the content in all applicable display and preview contexts
    Then output should be encoded or sanitized for each rendering context
    And no attacker-supplied script or active URL should execute
    And no record-changing request or anti-CSRF token disclosure should occur

    Examples:
      | source                     |
      | clinical form text         |
      | Patient Portal message     |
      | demographic field          |
      | imported document metadata |

  Scenario Outline: Cross-site requests cannot change application state
    Given a clinician has an authenticated session
    And an external test page attempts to change clinical, scheduling, billing, or administrative data
    When a state-changing request contains "<csrf_condition>"
    Then the application should reject the request before committing changes
    And the original records should remain unchanged
    And a GET request to the same workflow should not perform the state change

    Examples:
      | csrf_condition                       |
      | no required anti-CSRF token          |
      | an invalid anti-CSRF token           |
      | a token from another user's session  |
      | a token invalidated by session renewal|

  Scenario: Authorized same-origin changes remain functional
    Given a clinician has permission to edit a synthetic encounter
    When the clinician submits a same-origin request with a valid session-bound anti-CSRF token
    Then the intended encounter update should succeed
    And authorization should still be checked independently of CSRF validation
    And the update should be audited
```

### T3 — Document path traversal and file overwrite

```gherkin
Feature: Constrain document upload, import, and restore file writes

  Background:
    Given test sites A and B store documents under separate "sites/<site>/documents" directories
    And baseline hashes exist for patient documents, site configuration, integration queues, and backups
    And upload, import, and restore functionality is exercised only in an isolated test deployment

  Scenario Outline: Crafted filenames cannot escape the authorized destination
    Given a user can submit a file through "<workflow>"
    When the user supplies parent-directory, encoded traversal, absolute-path, mixed-separator, and archive-entry traversal filenames
    Then resolved destinations should remain inside the authorized storage root
    And unsafe entries should be rejected before being written
    And no other patient's documents, site configuration, integration files, or backups should change

    Examples:
      | workflow        |
      | document upload |
      | document import |
      | backup restore  |

  Scenario: Symbolic links and filename collisions cannot overwrite protected files
    Given a test destination contains a symbolic link to another site's file
    And an existing document filename belongs to another patient
    When an upload attempts to use the symbolic link or collide with the existing filename
    Then the application should prevent unauthorized replacement
    And filesystem permissions should independently deny writes outside the allowed site storage
    And baseline hashes for protected files should remain unchanged

  Scenario: Authorized document replacement is limited and traceable
    Given a staff member has permission to replace a document for patient A in site A
    When the staff member submits a valid replacement through the supported workflow
    Then only the explicitly selected document should be replaced or versioned
    And the previous version should be retained where required by policy
    And the audit record should identify the actor, patient, site, and affected document
```

### T4 — Altered or replayed HL7/X12 imports

```gherkin
Feature: Preserve integration message integrity, uniqueness, and record linkage

  Background:
    Given HL7 and X12 messages are staged before a cron-driven import
    And authenticated receipt establishes a protected message digest or equivalent integrity evidence
    And synthetic patient, encounter, and remittance mappings are configured

  Scenario: Staging-directory modification is detected before import
    Given an authentic laboratory message has passed receipt validation
    When a test actor changes its staged result values before the cron importer reads it
    Then the importer should detect the integrity mismatch
    And quarantine the message without posting clinical results
    And preserve the received-message identity and integrity failure for investigation

  Scenario Outline: Replayed or conflicting messages cannot cause duplicate postings
    Given a message from a verified provider has already been imported successfully
    When the provider submits "<replay_condition>"
    Then the importer should enforce uniqueness within the documented provider and site namespace
    And no duplicate result or financial posting should be created
    And conflicting content should be quarantined rather than silently replacing accepted data

    Examples:
      | replay_condition                                 |
      | the identical HL7 message and message identifier |
      | the identical X12 remittance and transaction key |
      | changed content using the accepted identifier    |

  Scenario Outline: Authenticated messages still require valid patient and encounter linkage
    Given a compromised integration account submits a structurally valid message
    When the message contains "<linkage_condition>"
    Then it should not be posted to an unrelated patient or encounter
    And the linkage failure should be queued for authorized reconciliation
    And no fallback to an arbitrary matching patient should occur

    Examples:
      | linkage_condition                              |
      | an unknown patient identifier                  |
      | ambiguous patient demographics                 |
      | an encounter belonging to a different patient  |
      | a patient identifier from another site         |

  Scenario: A valid new message is imported exactly once
    Given a verified provider submits a new message with valid integrity and unambiguous linkage
    When the importer processes the message and subsequently retries after a simulated acknowledgement failure
    Then the intended clinical or financial change should exist exactly once
    And both processing attempts should correlate to the same source message and resulting record
```

## Repudiation

### R1 — Database audit-log modification

```gherkin
Feature: Detect alteration or deletion of PHI-access audit history

  Background:
    Given PHI-access events are recorded alongside operational database records
    And a separately protected audit destination or integrity anchor exists outside database-administrator control
    And tests use synthetic audit events

  Scenario Outline: Database-level audit tampering remains detectable
    Given a test database administrator can modify the operational audit table
    When the administrator performs "<tampering>"
    Then verification should detect the missing, altered, or reordered history
    And the independently protected audit evidence should remain intact
    And an alert should identify the affected interval without claiming the altered history is trustworthy

    Examples:
      | tampering                                      |
      | delete selected PHI-access events               |
      | change an actor, patient, or action field       |
      | rewrite timestamps to reorder events           |
      | truncate the audit table                       |
      | recompute local checksums after changing events|

  Scenario: Database compromise does not expose audit-integrity secrets
    Given an attacker has the application's database credentials
    When the attacker attempts to retrieve signing keys or modify external integrity anchors
    Then those materials should be inaccessible with the compromised credentials
    And checksum or signature verification should not rely solely on attacker-writable database values

  Scenario: Disabling audit integrity cannot occur silently
    Given tamper-evident audit protection is required by deployment policy
    When an administrator disables optional checksums or interrupts protected audit forwarding
    Then the change or interruption should generate an independently retained security event
    And the configured protected buffering or fail-closed policy should take effect
    And restored forwarding should preserve event order and expose any unrecoverable gaps

  Scenario: Legitimate PHI access creates verifiable audit evidence
    Given a uniquely authenticated clinician is authorized to view a synthetic patient chart
    When the clinician views the chart
    Then a verifiable event should record the actor, patient, site, action, outcome, and timestamp
    And integrity verification should succeed without giving the verifier permission to rewrite the evidence
```

### R2 — Shared accounts and unattended workstations

```gherkin
Feature: Improve attribution of clinically significant staff actions

  Background:
    Given clinical notes, prescription requests, billing edits, and document downloads require attributable staff identities
    And individual staff authentication, session locking, and sensitive-action verification are configured

  Scenario: Shared interactive accounts cannot perform attributable clinical work
    Given an account is designated as a shared or non-person service account
    When someone attempts to use it for interactive clinical notes or prescription workflows
    Then the application should require an approved individual staff identity
    And it should not record the shared account as sufficient attribution for the action

  Scenario: An unattended workstation locks at the configured idle boundary
    Given a clinician leaves an authenticated workstation unattended
    When the configured inactivity timeout is reached
    Then PHI access and state-changing requests should require reauthentication
    And replaying a previously opened form should not commit a change without reauthentication
    And reauthentication should not silently transfer the prior clinician's privileges to another user

  Scenario: Sensitive actions require verification beyond possession of an unlocked session
    Given another person attempts to use a clinician's unlocked session
    And prescription signing requires fresh identity verification
    When that person submits a prescription without completing verification
    Then the prescription should not be signed or released
    And the failed verification should be audited without falsely asserting a verified human identity

  Scenario: Individually verified actions retain useful attribution
    Given a clinician completes the required individual authentication and action verification
    When the clinician signs a note or changes a billing entry
    Then the audit trail should record the individual identity, session reference, verification context, and action outcome
    And the clinical record should retain the applicable version history
    And audit exports should distinguish verified identity evidence from workstation or network metadata
```

### R3 — OAuth and background-import traceability

```gherkin
Feature: Trace integration activity from initiating identity to resulting records

  Background:
    Given OAuth clients can change FHIR resources and background jobs can import HL7/X12 records
    And application, authorization-server, and importer events support correlation identifiers

  Scenario: User-delegated OAuth changes retain both user and application identity
    Given a clinician authorizes a SMART application to update an allowed synthetic FHIR resource
    When the application performs the update
    Then the audit event should contain the client identifier and initiating clinician identity
    And it should contain the site, effective scopes, resource identifier, outcome, and correlation identifier
    And the resulting resource version should be traceable to that event
    And access tokens and client secrets should not be logged

  Scenario: Automated imports and exports are distinguishable from human actions
    Given a system client requests an export or a background job imports an HL7/X12 message
    When processing completes
    Then the audit trail should identify the service identity, client or provider, site, and job identifier
    And imports should record the source message identifier and resulting record changes
    And exports should record the authorized selection and generated artifacts
    And the event should explicitly indicate when no initiating human user exists

  Scenario: Retries and failures preserve end-to-end causality
    Given an integration message fails after processing begins and is subsequently retried
    When the retry succeeds
    Then each attempt should retain the original source correlation and a distinct attempt identifier
    And the audit trail should distinguish attempted changes from committed changes
    And an investigator should be able to trace the final record back to the verified source message
```

### R4 — Privileged host and application event correlation

```gherkin
Feature: Correlate privileged administration with application security changes

  Background:
    Given administrators can install modules, change ACLs, restore backups, and edit "sqlconf.php" through SSH
    And host and application security logs are forwarded to a separately protected audit service
    And an approved maximum clock-skew bound is configured

  Scenario Outline: Privileged changes retain host-to-application attribution
    Given an administrator uses an individually attributable privileged session
    When the administrator performs "<operation>"
    Then the relevant host or application events should identify the administrator, site, target, outcome, and timestamp
    And related events should be correlatable through session, change, job, or artifact identifiers
    And credentials and configuration secret values should not appear in audit records

    Examples:
      | operation                         |
      | install an application module     |
      | change a phpGACL permission        |
      | restore an approved backup        |
      | edit sqlconf.php through SSH      |

  Scenario: Excessive timestamp skew is detected and made visible to investigators
    Given a test host clock differs from the audit service beyond the approved bound
    When a privileged configuration change occurs
    Then monitoring should flag the clock synchronization failure
    And audit events should preserve source time and trusted receipt time
    And correlation should not silently present an uncertain event order as definitive

  Scenario: Rotation and forwarding interruption do not silently remove privileged events
    Given privileged events are generated across a log rotation boundary
    When audit forwarding is interrupted and subsequently restored
    Then protected buffering should retain events within the configured outage capacity
    And replay should preserve event identities and permit duplicate detection
    And any overflow or irrecoverable loss should generate an explicit gap alert
```

## Information Disclosure

### I1 — Cross-patient and cross-site object access

```gherkin
Feature: Enforce patient-level and site-level authorization on every data access

  Background:
    Given sites A and B contain distinct synthetic patient records and documents
    And patient A, restricted staff A, and an OAuth client have explicitly bounded access
    And OAuth scopes alone do not grant access to every patient or site

  Scenario Outline: Identifier substitution does not disclose unauthorized records
    Given "<actor>" is authorized only for its assigned patient or site
    When the actor substitutes an unauthorized "<identifier>" in a request
    Then the application should deny access or return a non-disclosing not-found response
    And the response body, headers, and errors should contain no unauthorized PHI
    And the denied access should be audited without disclosing the target's details to the actor

    Examples:
      | actor             | identifier                      |
      | portal patient A  | patient identifier              |
      | restricted staff A| document identifier             |
      | OAuth client      | FHIR resource reference         |
      | restricted staff A| site selector                   |
      | OAuth client      | patient reference in a request body |

  Scenario: Search, references, and exports preserve authorization boundaries
    Given an OAuth client has a valid read scope but access only to patient A in site A
    When it uses FHIR search, pagination, includes, reverse includes, history, and export operations
    Then every returned resource and linked reference should satisfy patient and site authorization
    And totals, summaries, continuation links, and error details should not reveal unauthorized records
    And changing a continuation token or export selection should not widen access

  Scenario: Shared caches do not leak a previous user's authorized response
    Given authorized staff have retrieved a patient document through the application
    When an unauthorized user requests the same URL through the same proxy or browser cache context
    Then no cached PHI should be returned to the unauthorized user
    And sensitive responses should use the configured private or no-store caching policy

  Scenario: Correctly authorized object access succeeds
    Given a clinician is assigned to patient A in site A
    When the clinician requests an allowed chart section and document for patient A
    Then only the authorized content should be returned
    And the access should be logged with the clinician, patient, and site
```

### I2 — Direct document, configuration, and backup exposure

```gherkin
Feature: Prevent web-server and filesystem bypasses of application authorization

  Background:
    Given documents are stored under "sites/<site>/documents"
    And "sqlconf.php", configuration copies, database dumps, and backups contain protected information
    And test files contain synthetic PHI and canary credentials rather than production secrets

  Scenario Outline: Direct web requests cannot retrieve protected storage
    Given an unauthenticated user knows or guesses "<target>"
    When the user requests it through the public web server and configured aliases
    Then no protected file content or directory listing should be returned
    And alternate HTTP methods and byte-range requests should not bypass the restriction
    And the response should not reveal filesystem paths or canary credentials

    Examples:
      | target                                |
      | sites/siteA/documents/patient-file.pdf |
      | sites/siteA/sqlconf.php                |
      | a configuration backup copy            |
      | a database dump                        |
      | a backup archive                       |

  Scenario: Traversal in file retrieval cannot expose configuration or other sites
    Given a document-download endpoint accepts a file or document selector
    When a user supplies encoded traversal, absolute paths, or a symbolic-link escape
    Then path resolution should not leave the authorized document root
    And "sqlconf.php" and other sites' documents should remain unreadable
    And errors should not reveal database credentials or file contents

  Scenario: Authorized document delivery uses the controlled application path
    Given a clinician is authorized to retrieve a synthetic patient document
    When the clinician downloads it through the application
    Then patient and site authorization should be checked before delivery
    And the response should not expose an unrestricted storage URL
    And the document access should be audited
```

### I3 — Bulk FHIR artifacts, cloud backups, and stolen snapshots

```gherkin
Feature: Protect bulk export artifacts and offsite backup data

  Background:
    Given Bulk FHIR export and offsite backups contain synthetic PHI
    And export artifacts and backups have separate authorization, retention, and encryption policies
    And encryption keys are managed separately from copied data

  Scenario Outline: Export status and download access cannot exceed export authorization
    Given client A created an export for its authorized site
    When "<requester>" accesses the export status, manifest, or output files
    Then access should require the artifact's documented authorization conditions
    And access outside the export's client, tenant, patient selection, or validity period should be denied
    And no broader dataset should be disclosed

    Examples:
      | requester                              |
      | an unauthenticated requester           |
      | a different OAuth client               |
      | a client from another site             |
      | the original client after access revocation |
      | a requester using an expired download URL  |

  Scenario: Signed export URLs remain bounded bearer capabilities
    Given the deployment uses signed URLs for approved export downloads
    When a valid URL is used and then tested after expiration or after path modification
    Then only the originally authorized object should be downloadable during its validity period
    And expired or modified URLs should fail
    And URLs should not be exposed through referrers, public logs, or shared manifests
    And their lifetime should not exceed the approved export-download policy

  Scenario: Unintended cloud identities cannot list or retrieve backups
    Given backups are stored in an offsite cloud location
    When anonymous users, unrelated tenant identities, and an over-broad test role attempt access
    Then listing, reading, copying, and changing backup policy should be denied
    And public-access and cross-account exposure checks should identify no unintended grants
    And denied access should be visible in cloud audit records

  Scenario: A copied snapshot does not contain the means to decrypt itself
    Given a tester copies a backup or storage snapshot without access to the approved key service
    When the tester inspects and attempts to restore the copied data
    Then PHI should remain unreadable
    And usable decryption keys should not be present alongside the copied data
    And an approved recovery identity should still be able to restore and verify the backup
```

### I4 — Messaging, logs, telehealth links, and transport leakage

```gherkin
Feature: Minimize PHI and credential exposure through communications and supporting services

  Background:
    Given OpenEMR sends reminders, faxes, Direct messages, and telehealth invitations
    And diagnostic logs, API logs, networked database connections, and SMTP routes are configured
    And approved recipient mappings and minimum-necessary content policies are defined

  Scenario Outline: Outbound communications use verified recipients and minimum necessary content
    Given a synthetic patient has an approved "<channel>" recipient mapping
    When a message is generated and the recipient mapping is missing, ambiguous, or belongs to another patient
    Then delivery should be blocked pending authorized correction
    And no fallback recipient should receive the message
    And valid delivery should contain only the fields approved for that channel

    Examples:
      | channel              |
      | appointment reminder |
      | fax                  |
      | Direct message       |
      | telehealth invitation|

  Scenario: Telehealth links do not grant unintended or indefinite access
    Given a telehealth invitation is issued for a synthetic patient appointment
    When an unintended recipient attempts to join without required identity verification
    Then access should follow the configured participant-verification policy
    And an expired or revoked invitation should not permit entry
    And the link should not expose patient details or reusable application credentials

  Scenario: Logs and provider accounts expose only permitted information
    Given diagnostic and API logging are enabled during authentication and clinical workflows
    When requests contain passwords, cookies, bearer tokens, reset links, and synthetic PHI
    Then logs should redact secrets and unnecessary PHI
    And log readers and provider-side test roles should access only their approved data
    And error and retry paths should apply the same redaction controls

  Scenario Outline: Sensitive network connections fail closed when transport protection is unavailable
    Given "<connection>" is required to use authenticated encrypted transport
    When the peer offers plaintext fallback or an invalid certificate
    Then the connection should fail without sending credentials or PHI
    And valid encrypted communication with the approved peer should succeed
    And monitoring should report the transport validation failure

    Examples:
      | connection                 |
      | networked MySQL/MariaDB     |
      | application-to-SMTP relay   |
      | required protected SMTP hop|
```

## Denial of Service

### D1 — Expensive searches, exports, reports, and conversions

```gherkin
Feature: Bound expensive workloads without interrupting clinical care

  Background:
    Given an isolated performance environment contains representative synthetic data
    And approved request, concurrency, runtime, memory, and temporary-storage limits are configured
    And clinical workflow availability objectives are defined before testing

  Scenario Outline: Repeated expensive requests are limited before shared resources are exhausted
    Given a test client can invoke "<workload>"
    When it submits controlled requests up to and beyond the configured quota
    Then excess work should be rejected or placed in a bounded queue
    And the response should provide the documented throttling behavior
    And PHP-FPM workers, database connections, and temporary disk usage should remain within safe limits
    And unrelated chart access, scheduling, and prescription workflows should meet availability objectives

    Examples:
      | workload            |
      | expensive FHIR search|
      | Bulk FHIR export    |
      | CQM report          |
      | document conversion |

  Scenario: Multiple accounts cannot bypass aggregate workload limits
    Given several test accounts and clients share the same site and worker pools
    When they collectively exceed site-level or global concurrency limits
    Then aggregate limits should apply in addition to per-account limits
    And workloads from another site should retain their reserved capacity
    And queued work should not grow without a configured bound

  Scenario: Boundary-sized legitimate work completes and releases resources
    Given a permitted workload is at the documented maximum supported size
    When it completes, times out, or is cancelled
    Then successful work should return the expected result within its supported limits
    And all paths should release workers, database connections, locks, and temporary files
    And metrics should return to the established baseline within the cleanup bound
```

### D2 — Oversized uploads, compressed archives, and poison messages

```gherkin
Feature: Bound document and clinical-message parsing resources

  Background:
    Given upload and import pipelines process documents, archives, CCDA, and HL7
    And tests run with synthetic inputs and controlled resource ceilings
    And compressed size, expanded size, nesting, parsing time, queue retry, and storage limits are configured

  Scenario Outline: Inputs exceeding parser or storage limits are stopped safely
    Given a portal user or integration submits "<input>"
    When the pipeline validates and parses the input
    Then processing should stop at the relevant configured limit
    And partial files and database changes should be cleaned up or safely quarantined
    And no unbounded memory, CPU, or disk consumption should occur
    And other patients' upload and import jobs should continue

    Examples:
      | input                                          |
      | a file one byte above the upload size limit     |
      | an archive exceeding the expanded-size limit   |
      | an archive exceeding the nesting-depth limit   |
      | malformed CCDA with excessive parser complexity|
      | malformed HL7 exceeding segment limits         |
      | XML attempting prohibited external resolution |

  Scenario: A poison message does not block subsequent valid imports
    Given a malformed message repeatedly fails import at the head of a queue
    And valid laboratory messages follow it
    When the configured retry limit is reached
    Then the malformed message should move to a bounded dead-letter or quarantine queue
    And later valid messages should be processed
    And operators should receive a diagnostic alert without unnecessary PHI

  Scenario: Storage high-water marks preserve application availability
    Given import staging storage is near its configured high-water mark
    When an upload would exceed the safe capacity threshold
    Then the upload should be rejected or deferred before exhausting shared storage
    And database, audit, and clinical workflow storage should retain their reserved capacity
    And a valid input at the supported boundary should succeed when sufficient capacity is available
```

### D3 — Ransomware and destruction across sites and backups

```gherkin
Feature: Limit destructive application compromise and prove recoverability

  Background:
    Given an isolated recovery environment contains synthetic databases, documents, and backups for sites A and B
    And a test harness simulates execution as site A's web-service account
    And recovery time and recovery point objectives are approved
    And no destructive test targets production resources

  Scenario: Application compromise cannot destroy independent backups or another site
    Given the simulated attacker can modify files normally writable by site A's runtime
    When the harness attempts controlled writes to site B and protected backup repositories
    Then operating-system, storage, and credential boundaries should deny those writes
    And the runtime should not possess backup deletion or retention-policy credentials
    And backup and site B integrity checks should remain unchanged

  Scenario: Destructive activity generates actionable detection
    Given disposable site A documents and database records are monitored
    When the harness performs a bounded sequence of abnormal deletion or rewrite operations
    Then monitoring should alert within the configured detection objective
    And the response process should support isolating affected runtime and integration credentials
    And audit evidence should remain available outside the compromised runtime

  Scenario: Recovery succeeds without trusting compromised writable backups
    Given site A's disposable operational data and writable local backup copy are marked compromised
    When responders restore from a verified immutable or offline recovery point
    Then database and document consistency checks should pass
    And restored clinical workflows should meet the approved recovery time objective
    And measured data loss should meet the approved recovery point objective
    And compromised credentials and executable artifacts should not be reinstated
```

### D4 — External provider outages and retry cascades

```gherkin
Feature: Contain failures of laboratory, clearinghouse, prescribing, and notification services

  Background:
    Given provider connections are represented by controlled test doubles
    And connection timeouts, response deadlines, circuit breakers, retry limits, and queue bounds are configured

  Scenario Outline: Slow providers do not exhaust shared application workers
    Given "<provider>" accepts connections but does not respond within its deadline
    When users or jobs submit integration requests
    Then calls should time out within the configured bound
    And repeated failures should activate the configured circuit breaker
    And unrelated clinical workflows should remain within availability objectives
    And the user should see an accurate pending or failed status rather than a false success

    Examples:
      | provider                 |
      | laboratory               |
      | clearinghouse            |
      | e-prescribing service    |
      | notification provider    |

  Scenario: Repeated provider errors produce bounded, non-synchronized retries
    Given a provider returns persistent errors or rate-limit responses
    When background jobs retry delivery
    Then retries should use the configured backoff and jitter
    And documented retry-after instructions should be respected where applicable
    And attempts and queue growth should stop at their configured bounds
    And exhausted jobs should be surfaced for controlled reconciliation

  Scenario: Recovery drains queued work without duplicate external actions
    Given a provider processed a request but its acknowledgement was lost
    And the provider subsequently recovers
    When queued work is retried and reconciled
    Then supported idempotency or reconciliation controls should prevent duplicate prescriptions, claims, or payments
    And unresolved outcomes should require explicit reconciliation rather than blind resubmission
    And queue draining should not exceed configured concurrency limits
```

## Elevation of Privilege

### E1 — Administrative handlers, phpGACL, and OAuth scope mapping

```gherkin
Feature: Enforce server-side privileges independently of user-interface visibility

  Background:
    Given patient, low-privilege staff, and administrator test accounts exist
    And phpGACL and object-level authorization govern administrative and clinical operations
    And patient OAuth scopes are distinct from staff-only write privileges

  Scenario Outline: Direct requests cannot bypass administrative authorization
    Given "<actor>" cannot access the administrative control in the user interface
    When the actor directly invokes the PHP handler or API for "<operation>"
    Then server-side authorization should deny the operation
    And no configuration, account, ACL, or financial record should change
    And changing HTTP methods or adding role-related request fields should not bypass the denial

    Examples:
      | actor               | operation                    |
      | portal patient      | change ACLs                  |
      | low-privilege staff | create an administrator      |
      | low-privilege staff | change global configuration  |
      | portal patient      | perform a privileged billing edit |

  Scenario: Patient OAuth scopes cannot map to staff-only write operations
    Given a patient application has a valid token with approved patient write scopes
    When it calls staff-only operations or targets an unauthorized patient or site
    Then both scope mapping and object authorization should deny the request
    And adding a requested scope or staff identity to the request body should not increase privileges
    And no staff session should be created from the patient token

  Scenario: Permission changes take effect for active sessions
    Given a staff member has an active session with an administrative permission
    When an administrator revokes that permission
    Then subsequent protected operations should be denied within the documented propagation bound
    And cached authorization results should not preserve the revoked privilege indefinitely
    And the permission change and denied action should be audited

  Scenario: An authorized administrator performs a permitted site-scoped change
    Given an administrator is authorized to manage users in site A only
    When the administrator changes an allowed user setting in site A
    Then the change should succeed and be audited
    But the equivalent request targeting site B should be denied
```

### E2 — Exposed installation and upgrade scripts

```gherkin
Feature: Restrict setup.php and sql_upgrade.php after deployment

  Background:
    Given OpenEMR installation has completed in an isolated test deployment
    And baseline database schema, privileged accounts, and configuration hashes are recorded
    And installation and upgrade operations require explicit approved maintenance state

  Scenario Outline: Deployment scripts cannot be invoked by unauthorized users
    Given "<actor>" can reach the web server
    When the actor requests "setup.php" or "sql_upgrade.php" directly using supported HTTP methods
    Then installation and schema-changing operations should be unavailable to that actor
    And no privileged account, configuration, or schema change should occur
    And responses should not disclose database connection secrets

    Examples:
      | actor                    |
      | an unauthenticated user  |
      | a portal patient         |
      | a low-privilege staff user|

  Scenario: Request manipulation cannot simulate an authorized installation state
    Given the deployment is installed and maintenance mode is disabled
    When a test user supplies forged setup-state parameters or calls an internal upgrade step directly
    Then installation state should be determined from trusted server-side controls
    And no database or configuration operation should execute
    And the attempt should be recorded as a security-relevant event

  Scenario: Authorized maintenance is bounded and leaves scripts protected
    Given an authorized administrator explicitly enables approved maintenance mode
    And a verified recovery point exists
    When the administrator executes the supported upgrade workflow
    Then only the approved migration steps should run
    And execution and outcome should be audited
    And interrupted or failed migration should follow the documented recovery procedure
    And completing maintenance should restore restrictions on installation and upgrade scripts
```

### E3 — Malicious modules and executable uploads

```gherkin
Feature: Prevent untrusted extensions and uploaded files from becoming application code

  Background:
    Given module installation and document upload are enabled in an isolated OpenEMR test deployment
    And module provenance approval and executable-directory restrictions are configured
    And uploaded files and approved application code have separate storage policies

  Scenario: Module installation requires both administrator authorization and provenance approval
    Given a module package lacks required approval or fails its configured signature or integrity check
    When a low-privilege user or administrator attempts to install it
    Then the package should not be activated or execute installation hooks
    And authorization and provenance failures should be distinguished in audit records
    And an attacker-supplied manifest should not be treated as trusted approval evidence

  Scenario Outline: Uploaded content cannot execute as PHP
    Given a user can upload patient documents but cannot deploy application code
    When the user uploads "<file_variant>" containing an inert execution canary
    And attempts to access it through every configured public storage mapping
    Then the content should be rejected or served only as non-executable data
    And the canary should never execute
    And no upload should be written into an executable application directory

    Examples:
      | file_variant                           |
      | a PHP extension                        |
      | a double extension                     |
      | a mixed-case executable extension      |
      | a file with mismatched MIME type       |
      | an archive containing executable files |

  Scenario: Module storage paths cannot overwrite application code or another site
    Given an otherwise installable test module contains an archive entry outside its assigned module path
    When the administrator submits the package
    Then path validation should reject the unsafe package before activation
    And application code, sqlconf.php, integration secrets, and other sites' files should remain unchanged
    And package extraction should not follow unsafe symbolic links

  Scenario: Approved module deployment is controlled and auditable
    Given an authorized administrator selects a provenance-approved module
    When the module is installed through the supported deployment workflow
    Then only approved paths and migration operations should be changed
    And the audit trail should record the administrator, module version, artifact hash, site, and outcome
    And the deployment should preserve the configured cross-site filesystem isolation
```

### E4 — Web-service account escalation through cron, containers, and host mounts

```gherkin
Feature: Prevent application runtime compromise from becoming host compromise

  Background:
    Given an isolated host runs OpenEMR under a restricted web-service account
    And privileged backup and synchronization jobs run through cron or a service manager
    And disposable canary files represent host configuration, SSH credentials, and offsite-backup secrets

  Scenario Outline: The web-service account cannot alter privileged execution inputs
    Given a privileged job references "<target>"
    When a test harness running as the web-service account attempts to modify or replace that target
    Then operating-system permissions should deny the modification
    And parent-directory replacement and symbolic-link substitution should also be denied
    And the privileged job should execute only its trusted, unchanged inputs

    Examples:
      | target                          |
      | backup script                   |
      | synchronization script          |
      | cron definition                 |
      | service unit or environment file|
      | executable searched through PATH|
      | configuration sourced by the job|

  Scenario: A compromised application container cannot access host control interfaces
    Given the application runs in a container with the approved hardened configuration
    When a runtime-account test attempts privileged operations or access to host control mounts
    Then unnecessary capabilities and privilege escalation should be unavailable
    And the host container-runtime socket should not be accessible
    And host filesystems should not be writable through unintended mounts
    And host SSH and backup canary secrets should remain unreadable

  Scenario: Privileged jobs do not execute application-controlled data
    Given the web-service account can write files to an approved document or integration staging directory
    When a privileged backup or synchronization job processes filenames and metadata from that directory
    Then filenames and metadata should be treated as data rather than shell commands or executable configuration
    And the job should not load scripts or environment settings from application-writable paths
    And controlled canary checks should confirm that no unintended command executed

  Scenario: Least-privilege application and backup operations remain functional
    Given protected scripts and service definitions are owned by the approved deployment identity
    When the application performs normal document operations and the scheduled backup runs
    Then both workflows should succeed using only their assigned permissions
    And the backup identity should not expose its credentials to the web-service account
    And host and application audit events should retain attributable execution identities
```