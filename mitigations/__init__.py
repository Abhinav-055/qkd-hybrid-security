"""Three mitigations for QKD key starvation.

* `quota` -- per-peer token bucket, so one greedy peer cannot starve the rest.
* `admission_control` -- reject before any crypto work, so an accepted
  handshake never silently downgrades.
* `downgrade_signal` -- tell the application, so the risk is at least known.

None of them create key material: the aggregate hybrid ceiling stays at
`supply_bps / 256`. They change *who* is served, *how* the failure surfaces,
and *whether anyone is told*.
"""

from .admission_control import (
    AdmissionController,
    AdmissionPolicy,
    HandshakeRejected,
    Ticket,
)
from .downgrade_signal import SignalLog, demo, handshake_with_signal, make_explicit_clients
from .quota import PeerQuota, QuotaPolicy

__all__ = [
    "AdmissionController",
    "AdmissionPolicy",
    "HandshakeRejected",
    "PeerQuota",
    "QuotaPolicy",
    "SignalLog",
    "Ticket",
    "demo",
    "handshake_with_signal",
    "make_explicit_clients",
]
