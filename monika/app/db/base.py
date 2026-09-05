"""Declarative base. Models arrive in T8 — this module stays model-free until then."""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for every Monika ORM model."""
