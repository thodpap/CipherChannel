"""
ProvisioningGate — physical-presence-gated key provisioning state machine.

Imported by server/ble_server.py and tested by cipher_tests/test_provisioning.py.
No BLE, asyncio, GPIO, or bless dependencies — unit-testable in isolation.

Usage (production):
    gate = ProvisioningGate()
    gate.open('phone', duration_s=60)   # called from GPIO button callback
    if gate.try_provision('phone'):     # called from REQUEST_KEY handler
        # issue key material
    gate.close()                        # on STOP_SHARING / disconnect / shutdown

Usage (automated experiments only — MUST NOT be used in production):
    gate = BenchmarkProvisioningGate()  # enabled by BENCHMARK_PROVISIONING=1
"""

import threading
import time


class ProvisioningGate:
    """
    Physical-presence-gated provisioning state machine.

    Default state: CLOSED.  A physical hardware action (GPIO button press)
    opens a timed window for a specific endpoint.  The window accepts exactly
    one successful REQUEST_KEY; it closes immediately on success, timeout,
    STOP_SHARING, error, or disconnect.

    Thread-safe: all methods acquire self._lock before reading or writing state.
    """
    WINDOW_SECONDS = 60

    def __init__(self) -> None:
        self._lock     = threading.Lock()
        self._endpoint = ''
        self._expires  = 0.0
        self._used     = False

    def open(self, endpoint: str, duration_s: int = WINDOW_SECONDS) -> None:
        """Open a timed provisioning window for endpoint ('phone' or 'cane')."""
        with self._lock:
            self._endpoint = endpoint
            self._expires  = time.monotonic() + duration_s
            self._used     = False
        print(f'[gate] Provisioning window OPEN for {endpoint!r} ({duration_s} s)')

    def close(self) -> None:
        """
        Close the provisioning window immediately.

        Call on: STOP_SHARING, client disconnect, provisioning error, server shutdown.
        Safe to call when the gate is already closed.
        """
        with self._lock:
            if self._endpoint:
                print(f'[gate] Provisioning window CLOSED for {self._endpoint!r}')
            self._endpoint = ''
            self._expires  = 0.0
            self._used     = False

    def try_provision(self, endpoint: str) -> bool:
        """
        Consume the provisioning window for endpoint.

        Returns True and atomically closes the window on the first successful call.
        Returns False (no key material exposed) if:
          - the gate is closed
          - the window was opened for a different endpoint
          - the window has expired
          - the window has already been used in this cycle (second REQUEST_KEY)
        """
        with self._lock:
            if not self._endpoint or self._endpoint != endpoint:
                return False
            if time.monotonic() > self._expires:
                print(f'[gate] Provisioning window expired for {endpoint!r}')
                self._endpoint = ''
                self._expires  = 0.0
                return False
            if self._used:
                print(f'[gate] Second REQUEST_KEY in same window rejected for {endpoint!r}')
                return False
            self._used     = True
            self._endpoint = ''
            self._expires  = 0.0
            return True

    @property
    def is_open(self) -> bool:
        """True if a provisioning window is active, unexpired, and unused."""
        with self._lock:
            return (bool(self._endpoint) and
                    time.monotonic() <= self._expires and
                    not self._used)


class BenchmarkProvisioningGate(ProvisioningGate):
    """
    Test-only gate — always allows provisioning without a physical action.

    MUST NOT be used in production.
    Enable via:  BENCHMARK_PROVISIONING=1 python3 ble_server.py

    open() and close() are no-ops so that automated test loops are not blocked
    by gate lifetime constraints.  try_provision() always returns True regardless
    of the endpoint argument, since experiments cycle through both endpoints.
    """

    def try_provision(self, endpoint: str) -> bool:
        print(f'[gate] BENCHMARK MODE: provisioning bypass for {endpoint!r}')
        return True

    def open(self, endpoint: str, duration_s: int = ProvisioningGate.WINDOW_SECONDS) -> None:
        pass  # always open — open() is a no-op in benchmark mode

    def close(self) -> None:
        pass  # cannot be closed in benchmark mode
