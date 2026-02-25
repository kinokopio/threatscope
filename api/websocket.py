"""WebSocket API for real-time task progress notifications.

This module provides WebSocket endpoints for:
- Real-time task progress updates
- Analysis step notifications
- Live log streaming
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from weakref import WeakSet

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ws", tags=["websocket"])


@dataclass
class ProgressMessage:
    """Progress update message."""

    task_id: str
    event: str  # task_started, step_started, step_completed, task_completed, error
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_json(self) -> str:
        return json.dumps(
            {
                "task_id": self.task_id,
                "event": self.event,
                "data": self.data,
                "timestamp": self.timestamp,
            }
        )


class ConnectionManager:
    """Manages WebSocket connections and message broadcasting."""

    def __init__(self):
        # All active connections
        self._connections: WeakSet[WebSocket] = WeakSet()
        # Task-specific subscriptions: task_id -> set of websockets
        self._task_subscriptions: dict[str, set[WebSocket]] = {}
        # Lock for thread-safe operations
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        """Accept a new WebSocket connection.

        Args:
            websocket: WebSocket connection to accept.
        """
        await websocket.accept()
        self._connections.add(websocket)
        logger.info(f"WebSocket connected: {id(websocket)}")

    async def disconnect(self, websocket: WebSocket) -> None:
        """Handle WebSocket disconnection.

        Args:
            websocket: WebSocket that disconnected.
        """
        self._connections.discard(websocket)

        # Remove from all task subscriptions
        async with self._lock:
            for task_id in list(self._task_subscriptions.keys()):
                self._task_subscriptions[task_id].discard(websocket)
                if not self._task_subscriptions[task_id]:
                    del self._task_subscriptions[task_id]

        logger.info(f"WebSocket disconnected: {id(websocket)}")

    async def subscribe_task(self, websocket: WebSocket, task_id: str) -> None:
        """Subscribe a WebSocket to task updates.

        Args:
            websocket: WebSocket to subscribe.
            task_id: Task ID to subscribe to.
        """
        async with self._lock:
            if task_id not in self._task_subscriptions:
                self._task_subscriptions[task_id] = set()
            self._task_subscriptions[task_id].add(websocket)

        logger.debug(f"WebSocket {id(websocket)} subscribed to task {task_id}")

    async def unsubscribe_task(self, websocket: WebSocket, task_id: str) -> None:
        """Unsubscribe a WebSocket from task updates.

        Args:
            websocket: WebSocket to unsubscribe.
            task_id: Task ID to unsubscribe from.
        """
        async with self._lock:
            if task_id in self._task_subscriptions:
                self._task_subscriptions[task_id].discard(websocket)
                if not self._task_subscriptions[task_id]:
                    del self._task_subscriptions[task_id]

    async def broadcast(self, message: ProgressMessage) -> None:
        """Broadcast message to all connected clients.

        Args:
            message: Message to broadcast.
        """
        if not self._connections:
            return

        json_msg = message.to_json()
        disconnected = []

        for websocket in self._connections:
            try:
                await websocket.send_text(json_msg)
            except Exception:
                disconnected.append(websocket)

        # Clean up disconnected
        for ws in disconnected:
            await self.disconnect(ws)

    async def send_to_task_subscribers(self, message: ProgressMessage) -> None:
        """Send message to subscribers of a specific task.

        Args:
            message: Message to send.
        """
        task_id = message.task_id
        subscribers = self._task_subscriptions.get(task_id, set())

        if not subscribers:
            return

        json_msg = message.to_json()
        disconnected = []

        for websocket in subscribers:
            try:
                await websocket.send_text(json_msg)
            except Exception:
                disconnected.append(websocket)

        # Clean up disconnected
        for ws in disconnected:
            await self.disconnect(ws)

    async def send_personal(self, websocket: WebSocket, message: dict) -> None:
        """Send a message to a specific WebSocket.

        Args:
            websocket: Target WebSocket.
            message: Message dictionary to send.
        """
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.warning(f"Failed to send personal message: {e}")

    @property
    def connection_count(self) -> int:
        """Get number of active connections."""
        return len(self._connections)


# Global connection manager instance
manager = ConnectionManager()


@router.websocket("/progress")
async def websocket_progress(websocket: WebSocket):
    """WebSocket endpoint for receiving progress updates.

    Clients can subscribe to specific tasks by sending:
    {"action": "subscribe", "task_id": "xxx"}

    They will then receive progress updates for that task.
    """
    await manager.connect(websocket)

    try:
        while True:
            # Receive messages from client
            data = await websocket.receive_json()

            action = data.get("action")
            task_id = data.get("task_id")

            if action == "subscribe" and task_id:
                await manager.subscribe_task(websocket, task_id)
                await manager.send_personal(
                    websocket,
                    {
                        "status": "subscribed",
                        "task_id": task_id,
                    },
                )

            elif action == "unsubscribe" and task_id:
                await manager.unsubscribe_task(websocket, task_id)
                await manager.send_personal(
                    websocket,
                    {
                        "status": "unsubscribed",
                        "task_id": task_id,
                    },
                )

            elif action == "ping":
                await manager.send_personal(websocket, {"status": "pong"})

    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await manager.disconnect(websocket)


@router.websocket("/logs/{task_id}")
async def websocket_logs(websocket: WebSocket, task_id: str):
    """WebSocket endpoint for streaming task logs.

    Args:
        websocket: WebSocket connection.
        task_id: Task ID to stream logs for.
    """
    await manager.connect(websocket)
    await manager.subscribe_task(websocket, task_id)

    try:
        # Keep connection alive and wait for disconnect
        while True:
            # Just keep the connection alive
            data = await websocket.receive_json()
            if data.get("action") == "ping":
                await manager.send_personal(websocket, {"status": "pong"})

    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket logs error: {e}")
        await manager.disconnect(websocket)


# Helper functions for sending progress updates


async def notify_task_started(task_id: str, file_path: str) -> None:
    """Notify that a task has started.

    Args:
        task_id: Task ID.
        file_path: Path to file being analyzed.
    """
    message = ProgressMessage(
        task_id=task_id,
        event="task_started",
        data={"file_path": file_path},
    )
    await manager.send_to_task_subscribers(message)


async def notify_step_started(task_id: str, step_id: str, step_name: str) -> None:
    """Notify that a step has started.

    Args:
        task_id: Task ID.
        step_id: Step ID.
        step_name: Human-readable step name.
    """
    message = ProgressMessage(
        task_id=task_id,
        event="step_started",
        data={"step_id": step_id, "step_name": step_name},
    )
    await manager.send_to_task_subscribers(message)


async def notify_step_completed(
    task_id: str,
    step_id: str,
    status: str,
    duration_ms: int = 0,
    error: str | None = None,
) -> None:
    """Notify that a step has completed.

    Args:
        task_id: Task ID.
        step_id: Step ID.
        status: Step status (completed, failed, skipped).
        duration_ms: Step duration in milliseconds.
        error: Error message if failed.
    """
    message = ProgressMessage(
        task_id=task_id,
        event="step_completed",
        data={
            "step_id": step_id,
            "status": status,
            "duration_ms": duration_ms,
            "error": error,
        },
    )
    await manager.send_to_task_subscribers(message)


async def notify_task_completed(
    task_id: str,
    status: str,
    result_summary: dict | None = None,
) -> None:
    """Notify that a task has completed.

    Args:
        task_id: Task ID.
        status: Task status (completed, failed).
        result_summary: Summary of results.
    """
    message = ProgressMessage(
        task_id=task_id,
        event="task_completed",
        data={
            "status": status,
            "result_summary": result_summary or {},
        },
    )
    await manager.send_to_task_subscribers(message)


async def notify_error(task_id: str, error: str, step_id: str | None = None) -> None:
    """Notify of an error.

    Args:
        task_id: Task ID.
        error: Error message.
        step_id: Optional step ID where error occurred.
    """
    message = ProgressMessage(
        task_id=task_id,
        event="error",
        data={"error": error, "step_id": step_id},
    )
    await manager.send_to_task_subscribers(message)


def get_connection_manager() -> ConnectionManager:
    """Get the global connection manager.

    Returns:
        ConnectionManager instance.
    """
    return manager
