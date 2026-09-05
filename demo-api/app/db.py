"""asyncpg connection pool and schema DDL.

Tables live in a `demo` schema so they never collide with monika's own tables in the
same database. Search deliberately concatenates strings against `demo.products` — that
is the point of this service (CLAUDE.md rule 10), do not parameterise it.
"""

from __future__ import annotations

import asyncpg

from .settings import DATABASE_URL

SCHEMA_DDL = """
CREATE SCHEMA IF NOT EXISTS demo;

CREATE TABLE IF NOT EXISTS demo.users (
    id            integer PRIMARY KEY,
    username      text    UNIQUE NOT NULL,
    email         text    NOT NULL,
    password_hash text    NOT NULL,
    ssn           text    NOT NULL,
    role          text    NOT NULL DEFAULT 'user',
    balance       numeric NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS demo.orders (
    id       integer PRIMARY KEY,
    user_id  integer NOT NULL REFERENCES demo.users(id),
    item     text    NOT NULL,
    amount   numeric NOT NULL,
    status   text    NOT NULL DEFAULT 'completed'
);

CREATE TABLE IF NOT EXISTS demo.products (
    id              integer PRIMARY KEY,
    name            text    NOT NULL,
    description     text    NOT NULL,
    category        text    NOT NULL,
    price           numeric NOT NULL,
    cost_price      numeric NOT NULL,
    supplier_margin numeric NOT NULL
);
"""


async def create_pool() -> asyncpg.Pool:
    """Open the process-wide connection pool."""
    return await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=8)


async def ensure_schema(pool: asyncpg.Pool) -> None:
    """Create the demo schema and tables if they do not exist."""
    async with pool.acquire() as conn:
        await conn.execute(SCHEMA_DDL)
