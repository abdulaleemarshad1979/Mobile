"""
CyberSentinel — WebSocket Connection Manager
Handles:
  • Connection limits (MAX_WS_CONNECTIONS)
  • Safe JSON sending (silently drops broken connections)
  • Active connection tracking for /health endpoint
"""

from __future__ import annotations

import asyncio
from fastapi import WebSocket

from config import settings
from logger import get_logger

log = get_logger("ws_manager")


class ConnectionManager:

    def __init__(self):
        self._active: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    @property
    def count(self) -> int:
        return len(self._active)

    async def connect(self, ws: WebSocket) -> bool:
        """
        Accept and register a WebSocket connection.
        Returns False if connection limit reached.
        """
        async with self._lock:
            if len(self._active) >= settings.MAX_WS_CONNECTIONS:
                await ws.accept()
                await ws.send_json({
                    "type": "error",
                    "message": f"Server busy — max {settings.MAX_WS_CONNECTIONS} concurrent connections. Try again shortly.",
                })
                await ws.close()
                log.warning('"WS connection rejected — limit reached (%d)"', settings.MAX_WS_CONNECTIONS)
                return False
            await ws.accept()
            self._active.add(ws)
            log.info('"WS connected — total: %d"', len(self._active))
            return True

    async def disconnect(self, ws: WebSocket):
        self._active.discard(ws)
        log.info('"WS disconnected — total: %d"', len(self._active))

    @staticmethod
    async def send_json(ws: WebSocket, payload: dict):
        """Send JSON safely — swallow closed-connection errors."""
        try:
            await ws.send_json(payload)
        except Exception:
            pass  # Client already gone; caller handles cleanup


manager = ConnectionManager()
