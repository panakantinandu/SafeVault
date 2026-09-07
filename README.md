# SafeVault

A secure ASP.NET Core web application for managing sensitive user data (credentials, profile
records), built to demonstrate defense-in-depth against the most common web attack classes:
SQL injection, XSS, and broken access control.

## Security model

| Concern | Mechanism |
|---|---|
| SQL injection | Every database call uses parameterized queries (`Microsoft.Data.Sqlite` with bound `$param` placeholders). No SQL string is ever built by concatenating user input. |
| XSS | Allowlist input validation rejects unsafe characters outright; any user-controlled value that is echoed back is passed through `HtmlEncoder` before being written into a response. |
| Password storage | Passwords are hashed with PBKDF2-HMAC-SHA256 (100,000 iterations, random 16-byte salt per user) via `Rfc2898DeriveBytes`. Plaintext passwords are never stored, logged, or compared directly. |
| Authentication | `/login` verifies credentials against the stored hash and issues a signed JWT (HMAC-SHA256) carrying the username and role as claims. |
| Authorization (RBAC) | Every account has a role (`user` or `admin`), validated against an allowlist at write time. Routes are protected with ASP.NET Core's `[Authorize]`/`RequireAuthorization`, including an `AdminOnly` policy gating the admin route. No HTTP-reachable endpoint lets a caller grant themselves `admin` — self-registration always yields `user`. |

## Project structure

```
SafeVault.sln
database.sql                          Production schema (MySQL-flavored)
src/SafeVault.Web/
  Program.cs                          Minimal API endpoints, auth/authz wiring
  Data/UserRepository.cs              Parameterized queries, user CRUD
  Security/PasswordHasher.cs          PBKDF2 password hashing/verification
  Security/JwtTokenService.cs         JWT issuance
  Validation/InputValidator.cs        Allowlist validation, sanitization, HTML encoding
  wwwroot/webform.html                Registration form
tests/SafeVault.Tests/
  TestInputValidation.cs              Unit tests: validators/sanitizers vs. SQLi & XSS payloads
  TestDatabaseSecurity.cs             Unit tests: repository layer, injection, roles
  TestAuthorization.cs                Integration tests: login, JWT, role-gated routes
  TestAttackScenarios.cs              End-to-end HTTP attack simulations (SQLi/XSS)
```

The app uses SQLite (`Microsoft.Data.Sqlite`) as its runtime database — no external server
required to run or test it. `database.sql` documents the equivalent production schema for a
server-based engine (MySQL-style syntax) if you deploy against one instead.

## API endpoints

| Method | Route | Auth | Description |
|---|---|---|---|
| `POST` | `/submit` | none | Register a new user (`username`, `email`, `password` form fields). Always creates a `user`-role account. |
| `POST` | `/login` | none | Authenticate (`username`, `password` form fields). Returns `{ token, role }` on success. |
| `GET` | `/search?q=` | none | Search usernames by substring (parameterized `LIKE`, results HTML-encoded). |
| `GET` | `/account/profile` | any authenticated user | Returns the caller's username and role from their JWT. |
| `GET` | `/admin/dashboard` | `admin` role only | Placeholder admin-only route. |

Authenticated requests pass the token from `/login` as `Authorization: Bearer <token>`.

## Running it

Requires the [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0).

```bash
dotnet run --project src/SafeVault.Web
```

The app serves the registration form at `/webform.html` and listens for the API routes above.

### Configuration

By default the app uses a local SQLite file (`safevault.db`) and generates a random JWT
signing key on every process start (fine for local development — tokens simply stop
validating across restarts). For anything beyond local use, set:

```
ConnectionStrings:Default   e.g. "Data Source=/path/to/safevault.db"
Jwt:SigningKey              a persistent, secret key (never commit this)
```

via environment variables, user-secrets, or your deployment platform's configuration — never
in a file committed to source control.

## Testing

```bash
dotnet test
```

The test suite includes:
- **Unit tests** for input validation/sanitization and the repository layer, firing real SQL
  injection and XSS payloads (`' OR '1'='1`, `<script>alert('xss')</script>`, etc.) at each
  layer in isolation.
- **Integration tests** (`WebApplicationFactory`) that drive the actual HTTP pipeline —
  registration, login, JWT issuance, and role-gated route access — including negative cases
  (wrong password, forged/tampered token, insufficient role).
- **Attack-simulation tests** that post the same malicious payloads to the live endpoints and
  assert the app rejects them cleanly (no data corruption, no unhandled errors, no reflected
  script tags).

## Known limitations

- SQLite is used for simplicity and testability; a production deployment handling real
  financial records should run against a hardened, access-controlled database server, with
  TLS in transit and encryption at rest.
- There is no session revocation/refresh-token flow — issued JWTs are valid for their full
  lifetime (1 hour) once issued.
- Admin accounts must be provisioned directly (there is no self-service or invite-based path
  to the `admin` role), which is intentional but means an out-of-band provisioning process is
  required in a real deployment.
