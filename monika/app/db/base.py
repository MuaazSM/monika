"""Declarative base every Monika ORM model (app/incidents/models.py) binds to."""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for every Monika ORM model."""
