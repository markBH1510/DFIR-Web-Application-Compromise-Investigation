# DIGITAL FORENSICS & INCIDENT RESPONSE (DFIR) REPORT
## Forensic Analysis of Web Application Integrity Failure and API Exposure

---

| **Attribute** | **Value** |
| :--- | :--- |
| **Case Reference** | `IR-2026-0511-LARA` |
| **Investigation Type** | Post-Incident Digital Forensics & Root Cause Analysis |
| **Target Architecture** | Laravel 10.x / PHP 8.2-FPM / Nginx / Redis / Horizon |
| **Incident Classification** | Unauthorized Application Code Modification & Service Disruption |
| **Overall Severity** | **HIGH** (Integrity Failure / Denial of Service) |
| **Data Breach Status** | **UNVERIFIED / UNPROVEN** (No Forensic Evidence of Data Exfiltration) |
| **Report Status** | Independent Technical Investigation — Final v1.0 |

---

## 1. Executive Summary

During the forensic examination of host server telemetry (Nginx FastCGI logs and Laravel application runtimes), an unauthorized modification incident was confirmed against the production application codebase. 

On **11 May 2026 between 09:00:15 UTC and 09:49:59 UTC**, unauthorized file writes altered core application files:
1. `routes/web.php` (Line 30, subsequently shifted to Line 31)
2. `app/Providers/EventServiceProvider.php` (Line 11)

The injected payloads contained an invalid syntax pattern: duplicate aliased PHP `use` declarations:
```php
use Illuminate\Support\Facades\Storage as Storage;
use App\Events\PaymentSuccessEvent as PaymentSuccessEvent;
```

Because PHP enforces class alias resolution at compile-time prior to runtime execution, these duplicate declarations produced immediate **PHP Fatal Errors (`E_ERROR`)**. This structural defect created a **"Self-Defeating Payload"**: any malicious route, backdoor, or web shell intended by the modification failed compilation and never executed. However, it caused an immediate denial of service on requests routing through the affected components during this specific window.

Forensic validation of log telemetry refutes claims of a prolonged multi-week total outage or confirmed customer data exfiltration:
* The route disruption was active strictly during a **49-minute window** on 11 May 2026 before being suppressed or mitigated.
* An event provider compile error recurred on 18 May 2026 for a **single minute (08:18:46 to 08:19:51 UTC)** affecting payment callback processing.
* Failures in scheduled export cleanup jobs (`filament_exports`) resulted from missing-directory exceptions (`DirectoryNotFoundException`) in newly deployed releases rather than malicious bulk data purging.

---

## 2. Technical Evidence & Artifact Analysis

### 2.1 The Entry Vector: Public GraphQL Endpoint
The initial interaction originated via unauthenticated HTTP/2 POST requests directed at `/graphql`.

* **Timestamp:** `2026-05-10 06:04:29 UTC`
* **Log Record:**
  ```text
  [error] 820#820: *322798 recv() failed (104: Connection reset by peer) while reading response header from upstream, client: 198.51.100.110, server: target-app, request: "POST /graphql HTTP/2.0", upstream: "fastcgi://unix:/var/run/php/php8.2-fpm.sock:"
  ```
* **Forensic Finding:** A concurrent inspection of the web server master process log (`error.log`) reveals a configuration reload and master process respawn at the exact second (`2026/05/10 06:04:29 [warn] protocol options redefined`). The upstream connection reset occurred due to FastCGI socket termination during process recycling rather than an Out-of-Memory (OOM) condition or payload crash.

---

### 2.2 Exploitation & Route File Integrity Failure
On 11 May 2026, two coordinated source IPs executed concurrent requests triggering application-wide FastCGI compile errors.

#### Initial Injection Window:
* **Timestamp:** `2026-05-11 09:00:15 UTC`
* **Telemetry Data:**
  ```text
  [error] 730500#730500: *39517 FastCGI sent in stderr: "PHP message: PHP Fatal error: 
  Cannot use Illuminate\Support\Facades\Storage as Storage because the name is already in use in /var/www/releases/release_id/routes/web.php on line 30"
  client: 203.0.113.148, request: "POST /graphql HTTP/2.0"
  ```
* **Repeat Probing:** Between `09:00:39` and `09:04:27 UTC`, source IP `198.51.100.110` transmitted 6 consecutive requests to `/graphql`, each failing with the identical line 30 compile error, confirming the persistence of the corrupt file state on disk.

#### Secondary File Modification (Line Shift):
* **Timestamp:** `2026-05-11 09:49:59 UTC`
* **Telemetry Data:**
  ```text
  [error] 730500#730500: *40288 FastCGI sent in stderr: "PHP message: PHP Fatal error: 
  Cannot use Illuminate\Support\Facades\Storage as Storage because the name is already in use in /var/www/releases/release_id/routes/web.php on line 31"
  client: 203.0.113.148, request: "GET /en/E61KG/simple-invoice HTTP/2.0"
  ```
* **Forensic Finding:** The shift from line 30 to line 31 indicates a re-write of `routes/web.php` adding an extra line above the import. Following this request at 09:49:59 UTC, no further compile errors for `routes/web.php` appear in any subsequent logs, proving the error was resolved within 50 minutes.

---

### 2.3 Secondary Injection: Payment Pipeline Interruption
On 18 May 2026, an identical syntax conflict was triggered in `app/Providers/EventServiceProvider.php`.

* **Observation Window:** `2026-05-18 08:18:46 UTC` to `08:19:51 UTC` (Duration: 65 seconds)
* **Telemetry Data:**
  ```text
  [error] 730500#730500: *303853 FastCGI sent in stderr: "PHP message: PHP Fatal error: 
  Cannot use App\Events\PaymentSuccessEvent as PaymentSuccessEvent because the name is already in use in /var/www/releases/release_id/app/Providers/EventServiceProvider.php on line 11"
  client: 2001:db8::1, request: "GET /ar/payment/EK2WD/redirect?resultIndicator=d0219... HTTP/2.0", referrer: "https://gateway.paymentprovider.com/"
  ```
* **Business Impact:** Legitimate transactions returning from the external payment gateway could not trigger the `PaymentSuccessEvent` listener during this 65-second window. The orders were processed by the gateway but failed automated status updates in the application database.

---

### 2.4 Investigation of Alleged Data Exfiltration (Filament Exports)
The scheduled job `PurgeExportedFilamentFilesJob` failed consistently beginning 25 May 2026 at midnight (`00:00:19 UTC`):

```text
production.ERROR: The "/var/www/releases/release_id/storage/app/filament_exports" directory does not exist.
{"exception":"[object] (Symfony\\Component\\Finder\\Exception\\DirectoryNotFoundException(code: 0)
at .../vendor/symfony/finder/Finder.php:649)
#2 .../app/Jobs/PurgeExportedFilamentFilesJob.php(20): Illuminate\\Support\\Facades\\Facade::__callStatic()
```

#### Forensic Assessment:
1. **Directory Lifecycle:** In the Filament administration framework, the directory `storage/app/filament_exports` is only initialized upon an administrator performing an export operation.
2. **Code Flaw:** The maintenance job executes `$finder->in($path)` without verifying directory existence (`File::exists($path)`). In freshly deployed release paths, the missing directory throws a fatal `DirectoryNotFoundException`.
3. **Conclusion:** Telemetry does not support the hypothesis of malicious evidence destruction or data exfiltration. The exception is an unhandled boundary condition in application code.

---

## 3. Indicators of Compromise (IOCs)

### Network Indicators
| Indicator | Protocol / Port | Context |
| :--- | :--- | :--- |
| `198.51.100.110` | HTTPS (TCP 443) | Primary /graphql probing and verification source |
| `203.0.113.148` | HTTPS (TCP 443) | Coordinated source for initial exploitation and invoice probing |

### Host / File Indicators
| File Path | Signature / Pattern | Forensic Implication |
| :--- | :--- | :--- |
| `routes/web.php` | `use Illuminate\Support\Facades\Storage as Storage;` | Unauthorized line insertion; compile-time failure |
| `app/Providers/EventServiceProvider.php` | `use App\Events\PaymentSuccessEvent as PaymentSuccessEvent;` | Duplicate alias insertion; payment pipeline interruption |
| `storage/app/filament_exports` | Directory Missing | Non-existent target directory causing scheduler errors |

---

## 4. Root Cause Analysis & Engineering Vulnerabilities

1. **Failure of Least Privilege on Codebase Directories:** The PHP-FPM execution user possessed write permissions over production source code directories (`routes/` and `app/Providers/`). Web server worker processes should have strictly read-only access to source code.
2. **Missing GraphQL Shielding:** The GraphQL gateway allowed arbitrary queries/mutations to be submitted without strict input validation, depth limiting, or schema-level authorization checks.
3. **Absence of Real-Time File Integrity Monitoring (FIM):** Modification of primary routing and provider files occurred in production without tripping automated alerting mechanisms until end-user errors surfaced.

---

## 5. Strategic Remediation & Hardening Plan

### Phase 1: Immediate Containment (P0)
* **Filesystem Lockdown:** Enforce immutable permissions on all application release files:
  ```bash
  chown -R root:www-data /var/www/releases/current/
  find /var/www/releases/current/ -type d -exec chmod 755 {} \;
  find /var/www/releases/current/ -type f -exec chmod 644 {} \;
  chmod -R 775 /var/www/releases/current/storage /var/www/releases/current/bootstrap/cache
  ```
* **Disable GraphQL Introspection:** Enforce production config to disable public introspection queries and restrict schema discovery.
* **Firewall Rule Enforcement:** Block source IPs `198.51.100.110` and `203.0.113.148` across all perimeter ingress points.

### Phase 2: System Eradication & Integrity Verification (P1)
* **Codebase Differential Audit:** Execute full clean verification against primary repository commits:
  ```bash
  git status --ignored
  git diff HEAD
  ```
* **Credential Rotation:** Rotate application encryption keys (`APP_KEY`), database passwords, and third-party gateway API secrets.
* **Queue & Session Purge:** Invalidate all active Redis sessions and inspect Laravel Horizon queues for unregistered job classes.

### Phase 3: Long-Term Defenses (P2)
* **Automated FIM Deployment:** Deploy tools such as OSSEC or AIDE to trigger high-priority alerts on any checksum alteration within `routes/`, `app/`, or `config/`.
* **Scheduler Exception Handling:** Refactor `PurgeExportedFilamentFilesJob` to verify directory existence prior to invoking Symfony Finder:
  ```php
  if (!Storage::disk('local')->exists('filament_exports')) {
      return;
  }
  ```
