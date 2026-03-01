# Copyright (c) 2026 Tanmay Dikey <enceladus441@gmail.com>
# SPDX-License-Identifier: MIT
"""
AgentArmor — Zero-Trust Middleware for Agentic Coding
======================================================
Version 1.0.0

Author
------
  Tanmay Dikey <enceladus441@gmail.com>
  https://github.com/TanmayD03/Agent-Armor

Quick start::

    from agent_armor import AgentArmor

    armor = AgentArmor()
    report = armor.process(raw_ai_code, filename="api.py")
    print(report.status)          # APPROVED | WARNED | BLOCKED
    print(report.hardened_code)
"""

from .pipeline import AgentArmor, ArmorReport

__version__ = "1.0.0"
__author__ = "Tanmay Dikey"
__email__ = "enceladus441@gmail.com"
__description__ = "Zero-Trust Middleware for Agentic Coding"
__url__ = "https://github.com/TanmayD03/Agent-Armor"

__all__ = ["AgentArmor", "ArmorReport"]
