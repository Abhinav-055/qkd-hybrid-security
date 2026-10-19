"""Protocol: the state machine allows exactly one path."""
from __future__ import annotations

import pytest

from protocol.state_machine import (
    ALLOWED_TRANSITIONS,
    HAPPY_PATH,
    HandshakeFailed,
    HandshakeState,
    InvalidTransition,
    StateMachine,
)


@pytest.mark.parametrize("role", ["initiator", "responder"])
def test_happy_path_walks_end_to_end(role):
    machine = StateMachine(role)
    for state in HAPPY_PATH[1:]:
        machine.transition(state)

    assert machine.state is HandshakeState.ESTABLISHED
    assert machine.is_established and not machine.is_failed
    assert machine.history == HAPPY_PATH


def test_the_declared_chain_matches_the_brief():
    assert [state.value for state in HAPPY_PATH] == [
        "init",
        "send_1",
        "wait_2",
        "send_3",
        "wait_4",
        "confirm",
        "established",
    ]


def test_skipping_a_state_is_refused():
    machine = StateMachine("initiator")
    with pytest.raises(InvalidTransition, match="init -> wait_2"):
        machine.transition(HandshakeState.WAIT_2)


def test_every_non_terminal_state_can_fail():
    for state in HAPPY_PATH[:-1]:
        assert HandshakeState.FAILED in ALLOWED_TRANSITIONS[state]


def test_terminal_states_have_no_exits():
    assert ALLOWED_TRANSITIONS[HandshakeState.ESTABLISHED] == frozenset()
    assert ALLOWED_TRANSITIONS[HandshakeState.FAILED] == frozenset()


def test_fail_records_the_reason_and_returns_the_exception():
    machine = StateMachine("responder")
    machine.transition(HandshakeState.SEND_1)

    error = machine.fail("initiator MAC verification failed")
    assert isinstance(error, HandshakeFailed)
    assert error.reason == "initiator MAC verification failed"
    assert machine.state is HandshakeState.FAILED
    assert machine.failure_reason == "initiator MAC verification failed"
    assert machine.history[-1] is HandshakeState.FAILED


def test_failing_twice_does_not_duplicate_history():
    machine = StateMachine("initiator")
    machine.fail("first")
    machine.fail("second")
    assert machine.history.count(HandshakeState.FAILED) == 1
    assert machine.failure_reason == "second"


def test_no_transitions_out_of_established():
    machine = StateMachine("initiator")
    for state in HAPPY_PATH[1:]:
        machine.transition(state)
    with pytest.raises(InvalidTransition):
        machine.transition(HandshakeState.FAILED)


def test_require_asserts_the_current_state():
    machine = StateMachine("initiator")
    machine.require(HandshakeState.INIT)
    with pytest.raises(InvalidTransition, match="expected wait_2 or wait_4"):
        machine.require(HandshakeState.WAIT_2, HandshakeState.WAIT_4)


def test_unknown_role_is_rejected():
    with pytest.raises(ValueError):
        StateMachine("eavesdropper")
