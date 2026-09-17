# Auth Module — Setup & Testing Guide

Covers the Login/Auth module: registration, login, JWT issuance, role-based
access control, and admin-provisioned accounts. See `docs/cust_auth_swagger_api.yaml`
for the full API contract.

Roles: `CUSTOMER`, `BANK_OFFICER`, `ADMIN`. Customers self-register.
`BANK_OFFICER` and `ADMIN` accounts are only ever created by an existing
`ADMIN`, through `POST /api/auth/users` — except for the very first `ADMIN`,
which is created automatically on startup (see below).

## 1. Configure MySQL

By default the app expects MySQL on `localhost:3306` with a `banking_db`
database (auto-created if missing). Either run MySQL locally with those
defaults, or override via environment variables:

| Variable      | Default     |
|---------------|-------------|
| `DB_HOST`     | `localhost` |
| `DB_USERNAME` | `root`      |
| `DB_PASSWORD` | *(empty)*   |

Hibernate creates/updates tables automatically (`ddl-auto=update`) — no
manual schema setup needed.

## 2. Configure `INITIAL_ADMIN_PASSWORD`

The very first `ADMIN` account is created automatically the first time the
app starts, **if no `ADMIN` exists yet**, using the password in the
`INITIAL_ADMIN_PASSWORD` environment variable. It is never hard-coded, never
logged, and always BCrypt-hashed before storage.

Optional companion variables (both have safe defaults):

| Variable                | Default             |
|--------------------------|--------------------|
| `INITIAL_ADMIN_USERNAME` | `admin`            |
| `INITIAL_ADMIN_EMAIL`    | `admin@bank.local` |
| `INITIAL_ADMIN_PASSWORD` | *(none — required to bootstrap)* |

**If `INITIAL_ADMIN_PASSWORD` is not set**, the app still starts normally —
it just skips creating the admin and logs a warning. Set the variable and
restart whenever you're ready.

### Setting it in Eclipse (Windows or any OS)

1. Right-click the project → **Run As → Run Configurations…**
2. Select your Spring Boot run configuration (or create one for
   `DemoApplication`).
3. Go to the **Environment** tab → **New…**
4. Add:
   - Name: `INITIAL_ADMIN_PASSWORD`
   - Value: a strong password of your choosing (this is **not** committed
     anywhere — pick your own)
5. (Optional) Add `INITIAL_ADMIN_USERNAME` / `INITIAL_ADMIN_EMAIL` the same
   way if you don't want the defaults.
6. Click **Apply**, then **Run**.

### Setting it from a terminal (Windows / macOS / Linux)

```powershell
# Windows PowerShell (current session only)
$env:INITIAL_ADMIN_PASSWORD = "YourStrongPasswordHere"
.\mvnw.cmd spring-boot:run
```

```bash
# macOS / Linux
export INITIAL_ADMIN_PASSWORD="YourStrongPasswordHere"
./mvnw spring-boot:run
```

**Never commit a real password into `application.properties` or source
control** — it should only ever exist as an environment variable on your
own machine.

## 3. How the initial ADMIN is created

On every startup, `AdminInitializer` checks `AUTH_USERS` for an existing
`ADMIN`:

- **None exists** → creates exactly one, using `INITIAL_ADMIN_PASSWORD`
  (BCrypt-hashed), with `role = ADMIN`, `status = ACTIVE`.
- **One already exists** → does nothing. Restarting the app repeatedly
  never creates duplicates.
- **None exists AND the password isn't set** → skips bootstrap, logs a
  warning, app still starts.

There is no public API to create the first admin — this startup check is
the only path.

## 4. Start the application

```bash
./mvnw spring-boot:run
```

The app comes up on `http://localhost:8080`.

## 5. Log in as the initial ADMIN

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"YourStrongPasswordHere"}'
```

Response:

```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9...",
  "tokenType": "Bearer",
  "expiresIn": 36000,
  "role": "ADMIN"
}
```

## 6. Copy the JWT

Copy the `token` value from the response above (without quotes) — you'll
use it as a Bearer token on every request to `/api/auth/users`.

## 7. Call `POST /api/auth/users` with the token

```bash
curl -X POST http://localhost:8080/api/auth/users \
  -H "Authorization: Bearer <paste-token-here>" \
  -H "Content-Type: application/json" \
  -d '{"username":"officer01","email":"officer@bank.com","password":"Bank@123456","role":"BANK_OFFICER"}'
```

## 8. Create a BANK_OFFICER

Same call as above with `"role":"BANK_OFFICER"`. Requires a valid ADMIN
token; any other role gets `403 Forbidden`.

## 9. Create another ADMIN

Same endpoint, `"role":"ADMIN"` in the body instead.

## 10. How customers register

Public, no token needed:

```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"jane_doe","email":"jane@example.com","password":"Password123!"}'
```

Always created with `role: CUSTOMER` — this cannot be overridden by the
client.

## 11. How each role logs in

All roles use the same endpoint — `POST /api/auth/login` with
`username`/`password`. The JWT returned contains whichever role is stored
on that account (`CUSTOMER`, `BANK_OFFICER`, or `ADMIN`).

## 12. Testing the protected endpoint in Postman

1. **POST** `http://localhost:8080/api/auth/login` → Body → raw → JSON →
   `{"username":"admin","password":"..."}` → Send.
2. Copy `token` from the response.
3. New request: **POST** `http://localhost:8080/api/auth/users`.
4. **Authorization** tab → Type: **Bearer Token** → paste the token.
5. **Body** → raw → JSON → e.g.
   `{"username":"officer01","email":"officer@bank.com","password":"Bank@123456","role":"BANK_OFFICER"}`.
6. Send. Expect `201 Created`. Try the same request with no Authorization
   header (expect `401`), or with a customer's token (expect `403`).

## Running the tests

```bash
./mvnw test
```

Uses H2 in-memory (see `application-test.properties`) — no MySQL or
`INITIAL_ADMIN_PASSWORD` needed to run the test suite.
