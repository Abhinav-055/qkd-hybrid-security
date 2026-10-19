"""Handshake state machine, shared by initiator and responder.

    INIT -> SEND_1 -> WAIT_2 -> SEND_3 -> WAIT_4 -> CONFIRM -> ESTABLISHED
                                                          \\-> FAILED

Both roles walk the same node sequence; each node means "flight k handled"
(DECISIONS.md D6):

| state         | initiator            | responder                 |
|---------------|----------------------|---------------------------|
| SEND_1        | M1 sent              | M1 received + validated   |
| WAIT_2        | awaiting M2          | M2 sent                   |
| SEND_3        | M3 sent              | M3 received + parsed      |
| WAIT_4        | awaiting M4          | mac_I verified            |
| CONFIRM       | verifying mac_R      | M4 sent with mac_R        |
| ESTABLISHED   | session key ready    | session key ready         |

Any state can transition to FAILED, and FAILED is terminal.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional


class HandshakeState(Enum):
    INIT = "init"
    SEND_1 = "send_1"
    WAIT_2 = "wait_2"
    SEND_3 = "send_3"
    WAIT_4 = "wait_4"
    CONFIRM = "confirm"
    ESTABLISHED = "established"
    FAILED = "failed"


#: The single happy path. FAILED is reachable from everywhere and is terminal.
HAPPY_PATH: tuple[HandshakeState, ...] = (
    HandshakeState.INIT,
    HandshakeState.SEND_1,
    HandshakeState.WAIT_2,
    HandshakeState.SEND_3,
    HandshakeState.WAIT_4,
    HandshakeState.CONFIRM,
    HandshakeState.ESTABLISHED,
)

ALLOWED_TRANSITIONS: dict[HandshakeState, frozenset[HandshakeState]] = {
    state: frozenset({HAPPY_PATH[index + 1], HandshakeState.FAILED})
    for index, state in enumerate(HAPPY_PATH[:-1])
}
ALLOWED_TRANSITIONS[HandshakeState.ESTABLISHED] = frozenset()
ALLOWED_TRANSITIONS[HandshakeState.FAILED] = frozenset()

TERMINAL_STATES = frozenset({HandshakeState.ESTABLISHED, HandshakeState.FAILED})


class InvalidTransition(RuntimeError):
    """A handshake step was attempted from a state that does not allow it."""


class HandshakeFailed(RuntimeError):
    """The handshake reached FAILED. Carries the recorded reason."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class StateMachine:
    """Tracks one party's progress and refuses out-of-order steps."""

    def __init__(self, role: str) -> None:
        if role not in ("initiator", "responder"):
            raise ValueError(f"role must be 'initiator' or 'responder', got {role!r}")
        self.role = role
        self._state = HandshakeState.INIT
        self._history: list[HandshakeState] = [HandshakeState.INIT]
        self.failure_reason: Optional[str] = None

    @property
    def state(self) -> HandshakeState:
        return self._state

    @property
    def history(self) -> tuple[HandshakeState, ...]:
        return tuple(self._history)

    @property
    def is_established(self) -> bool:
        return self._state is HandshakeState.ESTABLISHED

    @property
    def is_failed(self) -> bool:
        return self._state is HandshakeState.FAILED

    def transition(self, target: HandshakeState) -> None:
        if target not in ALLOWED_TRANSITIONS[self._state]:
            raise InvalidTransition(
                f"{self.role} cannot go {self._state.value} -> {target.value}"
            )
        self._state = target
        self._history.append(target)

    def require(self, *states: HandshakeState) -> None:
        """Assert the current state before performing a step."""
        if self._state not in states:
            expected = " or ".join(state.value for state in states)
            raise InvalidTransition(
                f"{self.role} is in {self._state.value}, expected {expected}"
            )

    def fail(self, reason: str) -> HandshakeFailed:
        """Move to FAILED and return (not raise) the exception to throw."""
        if self._state is not HandshakeState.FAILED:
            self._state = HandshakeState.FAILED
            self._history.append(HandshakeState.FAILED)
        self.failure_reason = reason
        return HandshakeFailed(reason)

    def __repr__(self) -> str:
        return f"StateMachine(role={self.role!r}, state={self._state.value!r})"
