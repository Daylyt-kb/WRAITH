"""
WRAITH v2.0 — Agent Package
All agents inherit from WraithAgent (in agents.base).
No top-level imports here to avoid circular dependencies.
"""

# Nothing imported at module level.
# Each agent module imports WraithAgent directly from agents.base.
# Tests and other code should import agents directly:
#   from agents.ghost import GhostAgent
#   from agents.commander import Commander
#   from agents.base import WraithAgent
