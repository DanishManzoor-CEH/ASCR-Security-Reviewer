# Secure Coding Guidance Knowledge Base

A condensed, self-written reference covering the OWASP Top 10 (2021) risk
categories and the corresponding secure-coding controls. This file seeds the
FAISS vector index so the application works immediately after cloning. Drop a
full OWASP PDF into this same `data/` folder to extend the knowledge base —
every PDF, Markdown and text file here is indexed automatically.

---

## A01:2021 — Broken Access Control

**Risk.** The application enforces authorisation on the client, or trusts an
identifier supplied by the caller, letting a user read or modify records that
belong to somebody else (insecure direct object reference), escalate to an
administrative role, or reach an endpoint that should be restricted.

**Remediation.**
- Deny by default. Every route, handler and resource requires an explicit allow rule.
- Enforce authorisation server-side on every request, never once at login and never in the UI layer.
- Derive the acting user's identity from the authenticated session or verified token, never from a request parameter such as `user_id` in the query string or body.
- Check ownership of the specific record before reading, updating or deleting it, not just that the caller holds a role.
- Use opaque or random identifiers rather than sequential integers for externally exposed resources.
- Invalidate sessions and tokens on logout and on privilege change; keep token lifetimes short.
- Log access-control failures and rate-limit repeated denials, since they signal enumeration.

## A02:2021 — Cryptographic Failures

**Risk.** Sensitive data is transmitted or stored without adequate protection:
plaintext transport, weak or broken algorithms, fast hashes for passwords,
predictable randomness, hardcoded or reused keys.

**Remediation.**
- Never store passwords with MD5, SHA-1 or a plain SHA-256. Use a memory-hard, salted password hash: Argon2id (preferred), scrypt, or bcrypt with an appropriate work factor. Each password gets a unique salt, which modern libraries generate automatically.
- Use AES-256 in an authenticated mode (GCM or a construction such as ChaCha20-Poly1305). Never ECB mode, which leaks plaintext structure. Never reuse a nonce or IV with the same key.
- Retire DES, 3DES, RC4, MD5 and SHA-1 for any security purpose.
- Generate keys, tokens, session identifiers, password-reset links and nonces with a cryptographically secure random source: `secrets` in Python, `crypto.randomBytes` in Node.js, `SecureRandom` in Java. Never `random`, `Math.random()` or a time-seeded PRNG.
- Enforce TLS everywhere, disable certificate-verification bypasses (`verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify: true`), and pin minimum TLS 1.2.
- Classify data first: encrypt what needs confidentiality at rest, and do not store what you do not need.

## A03:2021 — Injection (SQL, NoSQL, OS Command, LDAP, XSS)

**Risk.** Untrusted input is concatenated into an interpreter's instruction —
a SQL statement, a shell command, an LDAP filter, a template, or an HTML
document — so the attacker controls the structure and not just the data.

### SQL Injection
- Use parameterised queries / prepared statements for every query, without exception. In Python DB-API that means `cursor.execute("SELECT * FROM users WHERE name = ?", (name,))` — the placeholder style varies (`?`, `%s`, `:name`) but the parameters are always passed separately.
- Never build SQL by string concatenation, `%`-formatting, `.format()`, or f-strings with user input.
- Where an identifier (table or column name) must be dynamic, validate it against a hardcoded allow-list; identifiers cannot be parameterised.
- Prefer a well-maintained ORM's query builder, but note that raw-SQL escape hatches in ORMs reintroduce the risk.
- Apply least privilege to the database account: no DDL rights for an application that only reads and writes rows.

### OS Command Injection
- Avoid shelling out at all; use a native library for the task.
- If a subprocess is unavoidable, pass an argument list and never a shell string: `subprocess.run(["python", script_path], shell=False)`. Avoid `os.system`, `os.popen`, `eval`, `exec` and `shell=True`.
- Validate any user-supplied component against a strict allow-list of expected values.

### Cross-Site Scripting
- Escape output contextually: HTML body, HTML attribute, JavaScript, URL and CSS contexts all require different encoding.
- Let the template engine auto-escape; do not disable it with `|safe`, `dangerouslySetInnerHTML`, `innerHTML` or `v-html` on untrusted content.
- Add a restrictive Content-Security-Policy and set cookies `HttpOnly`, `Secure` and `SameSite`.
- Sanitise rich-text input with a vetted library (DOMPurify, bleach) rather than a hand-written regular expression.

### Path Traversal
- Never concatenate user input into a filesystem path. Resolve the candidate path to its canonical form and confirm it remains inside the intended base directory before opening it.
- Strip or reject `..`, absolute paths, null bytes and symlinks; prefer mapping a user-supplied key to a server-side filename through a lookup table.

## A04:2021 — Insecure Design

**Risk.** The weakness is in the architecture, not the implementation: no rate
limiting, no threat model, business logic that trusts client-side state, missing
segregation of tenants.

**Remediation.**
- Threat model before building; write abuse cases alongside use cases.
- Enforce business limits server-side (transfer caps, quota, retries, workflow ordering).
- Rate-limit authentication, password reset, and any expensive or enumerable endpoint.
- Segregate tenants and environments; never let test fixtures or debug routes ship to production.

## A05:2021 — Security Misconfiguration

**Risk.** Debug mode in production, verbose stack traces returned to users,
default credentials, permissive CORS, unnecessary features enabled, cloud storage
left world-readable.

**Remediation.**
- Disable debug and set generic error pages in production; log details server-side only.
- Remove default accounts and sample applications; change every default password.
- Set security headers: HSTS, X-Content-Type-Options, X-Frame-Options or frame-ancestors, Referrer-Policy.
- Restrict CORS to an explicit origin allow-list; never reflect the `Origin` header and never combine wildcard origins with credentials.
- Keep configuration in environment variables or a secrets manager, and keep it out of version control.

## A06:2021 — Vulnerable and Outdated Components

**Risk.** A dependency with a known CVE is the shortest path into an application.

**Remediation.**
- Pin dependency versions and commit a lockfile.
- Run automated dependency scanning (`pip-audit`, `npm audit`, Dependabot, Trivy) in CI and fail the build on high-severity advisories.
- Remove unused dependencies; every package is attack surface.
- Track an SBOM and monitor advisories for the components you actually ship.

## A07:2021 — Identification and Authentication Failures

**Risk.** Credential stuffing succeeds, sessions never expire, password reset can
be brute-forced, MFA is absent, or session identifiers are predictable.

**Remediation.**
- Support multi-factor authentication and check passwords against known-breached lists.
- Do not cap password length low or forbid special characters; length beats composition rules.
- Rate-limit and exponentially back off failed logins; use a generic failure message so the response does not reveal whether the account exists.
- Regenerate the session identifier on login and privilege change; expire sessions on idle and absolute timeouts.
- Make password-reset tokens random, single-use and short-lived.

## A08:2021 — Software and Data Integrity Failures

**Risk.** Deserialising attacker-controlled data, loading plugins or updates
without signature verification, or trusting an unpinned CI dependency.

**Remediation.**
- Never deserialise untrusted input with `pickle`, `marshal`, PyYAML's `yaml.load` with the unsafe loader, Java native serialisation, or PHP `unserialize`. Use a data-only format: JSON, or `yaml.safe_load`.
- Where object deserialisation is unavoidable, enforce a strict type allow-list and validate the payload's integrity with a signature or MAC first.
- Verify signatures on updates, packages and plugins; use subresource integrity for third-party scripts.
- Protect the CI/CD pipeline as production infrastructure.

## A09:2021 — Security Logging and Monitoring Failures

**Risk.** An intrusion is not detected because nothing meaningful was logged, or
the logs themselves leak secrets.

**Remediation.**
- Log authentication successes and failures, access-control denials, input-validation failures and high-value transactions with enough context to investigate.
- Never log passwords, tokens, session identifiers, full card numbers or other sensitive fields; mask them at the logging boundary.
- Ship logs to tamper-resistant centralised storage, and alert on patterns rather than single events.
- Ensure logs cannot themselves be injected: sanitise newlines in user-controlled values before writing them.

## A10:2021 — Server-Side Request Forgery (SSRF)

**Risk.** The server fetches a URL supplied by a user, letting an attacker reach
internal services, cloud metadata endpoints, or localhost.

**Remediation.**
- Validate the user-supplied URL against an allow-list of schemes, hosts and ports.
- Resolve the hostname and block private, loopback, link-local and metadata ranges — including after redirects, and re-check on every hop to defeat DNS rebinding.
- Disable automatic redirect following, or re-validate each redirect target.
- Isolate the fetching component at the network layer so it cannot reach internal subnets.

---

## Cross-Cutting Controls

### Secrets Management
Hardcoded API keys, database passwords, private keys and tokens in source code
leak through repositories, container images, logs and client bundles — and stay
in git history after removal. Load secrets from environment variables or a
managed secret store (AWS Secrets Manager, HashiCorp Vault, `st.secrets`),
keep them out of version control via `.gitignore`, rotate anything that has ever
been committed, and scan the repository history with a tool such as gitleaks.

### Input Validation
Validate on the server, against an allow-list, as close to the entry point as
possible: type, length, range, format and business rules. Treat every external
source as untrusted — request bodies, headers, cookies, query strings, uploaded
files, webhook payloads and responses from third-party APIs. Validation
complements, but never replaces, context-appropriate output encoding and
parameterised interfaces.

### Error Handling
Fail closed. Catch exceptions specifically rather than swallowing every error,
return a generic message to the caller, and keep stack traces, SQL text, file
paths and internal hostnames server-side.

### Least Privilege
Run processes as a non-root user, grant database and cloud roles the minimum
permissions the workload needs, scope tokens narrowly, and set short expiries.

### File Upload Handling
Validate the content type by inspecting the file, not by trusting the supplied
extension or `Content-Type` header. Store uploads outside the web root, generate
a server-side filename, cap the size, and scan for malware where the risk
warrants it.

### False-Positive Guidance for Reviewers
A construct is **not** a finding when: the query is parameterised and the value
is bound rather than concatenated; the credential is read from an environment
variable or secret store; the input is validated against an allow-list before
reaching the sink; the value is developer-controlled and cannot be influenced by
a request; randomness is used for a non-security purpose such as jitter or
sampling; or the concern is purely stylistic. Flagging these erodes trust in the
report — verify reachability of attacker-controlled input to the sink before
confirming a finding.
