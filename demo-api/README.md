# demo-api — deliberately vulnerable target

This service is the API that **Monika** protects. It is intentionally insecure
(CLAUDE.md rule 10). **Do not harden it.** Its weaknesses are what the detectors detect.

Runs on port **9000**, and is **never published to the host** — only the `monika`
proxy talks to it (CLAUDE.md §5).

## Routes and intended weaknesses (PRD §10.2)

| Route | Weakness |
|-------|----------|
| `POST /api/login` | No lockout; distinct errors for unknown-user vs wrong-password (user enumeration). Issues an HS256 JWT (`sub`, `jti`, `role`, 30-min `exp`). |
| `POST /api/step-up` | Correct behaviour: verifies password, issues a fresh 5-min token (used by the CHALLENGE rung). |
| `GET /api/users/{id}` | IDOR — no ownership check; returns the full row incl. `password_hash` and `ssn`. |
| `GET /api/users/{id}/orders` | IDOR — no ownership check; returns orders with `user_id`. |
| `GET /api/search?q=` | String-concatenated SQL against `demo.products`; genuinely injectable. |
| `GET /api/admin/users` | No role check; returns all users. |
| `GET /api/products` | Returns `cost_price` and `supplier_margin`; supports `?page=`. |
| `POST /api/transfer` | No idempotency key, no amount cap, no balance check. **Unmonitored** — see below. |

### `POST /api/transfer` is intentionally unmonitored

Per `docs/DECISIONS.md` **D-11**, no Monika detector covers `/api/transfer` in Tier 1–2.
It remains in this API as a known-uncovered vulnerable route (rule 10 forbids removing it).

## Seed data (`app/seed.py`, idempotent)

- **50 users**, sequential IDs **700–749** (DECISIONS.md D-09). Every user has
  `password_hash`, `ssn`, `email`, `balance`. User **749** is the only `admin`.
- **Weak passwords**: `700` → `password`, `715` → `123456`, `730` → `qwerty`.
- **Demo attacker: user `742`**, password **`hunter2`** (DECISIONS.md D-09). Its token is
  used to demonstrate IDOR against users `700..730`. Do not extend the seed range.
- **~10 orders per user** (≈500 total), `user_id` set to the owner.
- **200 products**, each with `cost_price` and `supplier_margin`.

Passwords are stored as **unsalted SHA-256** — intentionally weak, so a leaked
`password_hash` is crackable (part of the DATA_EXPOSURE story).

## OpenAPI export

```bash
make openapi        # writes demo-api/openapi.json from the app (no server needed)
```

Tier 3 (T19) imports this schema and round-trips it to `config/endpoints.yaml`.

## Data location

Tables live in a `demo` schema inside the shared `monika` Postgres database, so they
never collide with Monika's control-plane tables.
