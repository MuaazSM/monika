"""Idempotent seed for the demo API (CLAUDE.md rule 10 — realistic, vulnerable data).

- 50 users, IDs 700..749 (DECISIONS.md D-09). Three have weak passwords.
  User 742 is the demo attacker account with a known password ("hunter2"); see README.
- ~10 orders per user, order.user_id = owner.
- 200 products, each with cost_price and supplier_margin.

Deterministic (no RNG) so `alembic`-style reruns and CI produce identical data. Safe to
run repeatedly: every write is an upsert.
"""

from __future__ import annotations

import asyncio

from .auth import hash_password
from .db import create_pool, ensure_schema

WEAK = {700: "password", 715: "123456", 730: "qwerty"}
ATTACKER_ID = 742
ATTACKER_PASSWORD = "hunter2"  # documented in README; used by traffic-gen (T9)

CATEGORIES = ["widgets", "gadgets", "gizmos", "sprockets", "cogs"]
ITEMS = ["Standard Plan", "Pro Plan", "Add-on Pack", "Support Hours", "Hardware Unit"]


def _password_for(uid: int) -> str:
    if uid in WEAK:
        return WEAK[uid]
    if uid == ATTACKER_ID:
        return ATTACKER_PASSWORD
    return f"pw-{uid}-secret"


async def seed() -> None:
    pool = await create_pool()
    try:
        await ensure_schema(pool)
        async with pool.acquire() as conn:
            async with conn.transaction():
                # Users 700..749
                for uid in range(700, 750):
                    role = "admin" if uid == 749 else "user"
                    await conn.execute(
                        """
                        INSERT INTO demo.users
                            (id, username, email, password_hash, ssn, role, balance)
                        VALUES ($1,$2,$3,$4,$5,$6,$7)
                        ON CONFLICT (id) DO UPDATE SET
                            username=EXCLUDED.username, email=EXCLUDED.email,
                            password_hash=EXCLUDED.password_hash, ssn=EXCLUDED.ssn,
                            role=EXCLUDED.role, balance=EXCLUDED.balance
                        """,
                        uid,
                        f"user{uid}",
                        f"user{uid}@example.com",
                        hash_password(_password_for(uid)),
                        f"{uid:03d}-45-{6000 + uid}",
                        role,
                        round(1000 + (uid - 700) * 13.5, 2),
                    )

                # ~10 orders per user, stable ids
                order_id = 1
                for uid in range(700, 750):
                    for k in range(10):
                        await conn.execute(
                            """
                            INSERT INTO demo.orders (id, user_id, item, amount, status)
                            VALUES ($1,$2,$3,$4,$5)
                            ON CONFLICT (id) DO UPDATE SET
                                user_id=EXCLUDED.user_id, item=EXCLUDED.item,
                                amount=EXCLUDED.amount, status=EXCLUDED.status
                            """,
                            order_id,
                            uid,
                            ITEMS[k % len(ITEMS)],
                            round(19.99 + k * 10, 2),
                            "completed",
                        )
                        order_id += 1

                # 200 products
                for pid in range(1, 201):
                    cost = round(5 + (pid % 50) * 1.25, 2)
                    price = round(cost * 2.4, 2)
                    margin = round(price - cost, 2)
                    cat = CATEGORIES[pid % len(CATEGORIES)]
                    await conn.execute(
                        """
                        INSERT INTO demo.products
                            (id, name, description, category, price, cost_price, supplier_margin)
                        VALUES ($1,$2,$3,$4,$5,$6,$7)
                        ON CONFLICT (id) DO UPDATE SET
                            name=EXCLUDED.name, description=EXCLUDED.description,
                            category=EXCLUDED.category, price=EXCLUDED.price,
                            cost_price=EXCLUDED.cost_price, supplier_margin=EXCLUDED.supplier_margin
                        """,
                        pid,
                        f"Product {pid}",
                        f"A fine {cat[:-1]} number {pid}",
                        cat,
                        price,
                        cost,
                        margin,
                    )
        print("demo-api seed complete: 50 users (700..749), ~500 orders, 200 products")
    finally:
        await pool.close()


if __name__ == "__main__":
    asyncio.run(seed())
