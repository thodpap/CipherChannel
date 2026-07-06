from __future__ import annotations
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import threading
from typing import Union

# ── Protocol constants ─────────────────────────────────────────────────────────
PROTOCOL_VERSION     = 1
STATE_FORMAT_VERSION = 1

NONCE_LEN          = 12    # 96-bit IETF-standard AES-GCM nonce length
MAC_LEN            = 16    # GCM authentication tag
MAX_PLAINTEXT_SIZE = 400   # BLE limit validated experimentally (400B → 428B packet)
MAX_PACKET_SIZE    = NONCE_LEN + MAX_PLAINTEXT_SIZE + MAC_LEN  # 428 bytes

_COUNTER_BYTES = NONCE_LEN          # counter serialised to same width as nonce
_COUNTER_MAX   = (1 << 96) - 1      # exhaustion guard: never reuse nonce at 2^96

# Provisioning associated-data tags. The gateway's REQUEST_KEY response is
# encrypted under the shared transport key K_T, which both the phone and
# cane endpoints hold; without a bound tag, a response meant for one
# endpoint authenticates just as well if delivered to the other. Passing
# the endpoint's tag as associated_data to CipherChannel.send()/receive()
# on the transport channel binds the response to the endpoint it was
# actually issued for, without changing the wire packet at all.
PROVISION_TAG_PHONE = b'phone_provisioning'
PROVISION_TAG_CANE  = b'cane_provisioning'

# ── State-file binary layout (all little-endian) ───────────────────────────────
#  1B  STATE_FORMAT_VERSION
#  1B  PROTOCOL_VERSION
#  1B  endpoint_id length (N)
#  N B endpoint_id (UTF-8)
#  1B  role flags  (bit 0: 1 = initiator)
#  2B  key length  (K)
#  K B key bytes
# 12B  seqSend  (96-bit LE unsigned integer)
# 12B  seqRecv  (96-bit LE unsigned integer)


class ChannelException(Exception):
    pass


class CipherChannel:
    """
    AES-256-GCM channel with persistent monotonic counter nonces.

    Wire format:  nonce(12) || ciphertext(N) || tag(16)
    Fixed overhead: 28 bytes.  Ciphertext length == plaintext length (no padding).

    Direction parity:
      initiator  sends even counters (2, 4, 6, …)  and receives odd
      responder  sends odd  counters (3, 5, 7, …)  and receives even

    Thread safety:
      Each context carries its own lock. Concurrent send() and receive() on the
      same context are safe. The complete critical section (counter read,
      exhaustion check, increment, persist, nonce construction, encrypt/decrypt)
      is held under a single lock acquisition per call.

    Persistence guarantees (process-crash and power-loss):
      send()    — increments and fsyncs the send counter BEFORE returning the
                  packet. A crash after persist but before the BLE write loses
                  the packet but cannot cause nonce reuse.
      receive() — fsyncs the accepted receive counter BEFORE returning plaintext.
                  A crash after persist cannot cause replay acceptance.
      The write sequence is: write temp-file → fsync(fd) → os.replace() →
      fsync(parent-dir). This is durable on ext4 (ordered-data mode) and
      equivalent journalling filesystems. On FAT/exFAT, rename is not atomic;
      use ext4 or tmpfs for state files.
    """

    def __init__(self, key: bytes, file: str, seq_send: int, seq_recv: int,
                 endpoint_id: str = '', initiator: bool = True) -> None:
        self._key         = key
        self._file        = file
        self._seq_send    = seq_send
        self._seq_receive = seq_recv
        self._endpoint_id = endpoint_id
        self._initiator   = initiator
        self._lock        = threading.Lock()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _write_state(self) -> None:
        """
        Atomically and durably persist the full channel state.
        Raises ChannelException on any I/O error. Cleans up the temp file.
        Must be called while holding self._lock.
        """
        tmp = f'{self._file}.tmp'
        try:
            eid     = self._endpoint_id.encode('utf-8')
            role    = bytes([1 if self._initiator else 0])
            key_len = len(self._key).to_bytes(2, 'little')
            send    = self._seq_send.to_bytes(_COUNTER_BYTES, 'little')
            recv    = self._seq_receive.to_bytes(_COUNTER_BYTES, 'little')

            payload = (
                bytes([STATE_FORMAT_VERSION, PROTOCOL_VERSION]) +
                bytes([len(eid)]) + eid +
                role + key_len + self._key +
                send + recv
            )

            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, payload)
                os.fsync(fd)
            finally:
                os.close(fd)

            os.replace(tmp, self._file)

            dir_path = os.path.dirname(os.path.abspath(self._file))
            dirfd = os.open(dir_path, os.O_RDONLY)
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)

        except OSError as e:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise ChannelException(f'Failed to persist channel state: {e}')

    # ── Factory: create ───────────────────────────────────────────────────────

    @staticmethod
    def create(key: bytes, initiator: bool, file_path: str,
               endpoint_id: str = '') -> CipherChannel:
        """Create a new channel and durably write its initial state."""
        if len(key) != 32:
            raise ChannelException(f'Key must be 32 bytes, got {len(key)}')
        seq_send = 0 if initiator else 1
        seq_recv = 1 if initiator else 0
        c = CipherChannel(key, file_path, seq_send, seq_recv, endpoint_id, initiator)
        c._write_state()
        return c

    # ── Factory: load ─────────────────────────────────────────────────────────

    @staticmethod
    def load(file_path: str, endpoint_id: str = '') -> CipherChannel:
        """
        Load a channel from its persisted state file.

        Raises ChannelException (fails closed) on any format error, version
        mismatch, truncation, or endpoint_id conflict.
        If endpoint_id is provided it is validated against the stored value.
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
        except OSError as e:
            raise ChannelException(f'Cannot read state file: {e}')

        if len(data) < 2:
            raise ChannelException('State file too short')

        sfv, pv = data[0], data[1]
        if sfv != STATE_FORMAT_VERSION:
            raise ChannelException(
                f'Incompatible state format version {sfv} (expected {STATE_FORMAT_VERSION})')
        if pv != PROTOCOL_VERSION:
            raise ChannelException(
                f'Incompatible protocol version {pv} (expected {PROTOCOL_VERSION})')
        pos = 2

        if pos >= len(data):
            raise ChannelException('State file truncated at endpoint_id_len')
        eid_len = data[pos]; pos += 1
        if pos + eid_len > len(data):
            raise ChannelException('State file truncated at endpoint_id')
        stored_eid = data[pos:pos + eid_len].decode('utf-8', errors='replace')
        pos += eid_len

        if endpoint_id and stored_eid != endpoint_id:
            raise ChannelException(
                f'Endpoint ID mismatch: file has {stored_eid!r}, expected {endpoint_id!r}')

        if pos >= len(data):
            raise ChannelException('State file truncated at role')
        initiator = bool(data[pos] & 0x01); pos += 1

        if pos + 2 > len(data):
            raise ChannelException('State file truncated at key_length')
        key_len = int.from_bytes(data[pos:pos + 2], 'little'); pos += 2
        if key_len not in (16, 24, 32):
            raise ChannelException(f'Invalid key length {key_len}')
        if pos + key_len > len(data):
            raise ChannelException('State file truncated at key')
        key = data[pos:pos + key_len]; pos += key_len

        expected_tail = 2 * _COUNTER_BYTES
        if len(data) - pos != expected_tail:
            raise ChannelException(
                f'State file wrong length: expected {expected_tail} counter bytes, '
                f'got {len(data) - pos}')

        seq_send = int.from_bytes(data[pos:pos + _COUNTER_BYTES], 'little')
        seq_recv = int.from_bytes(data[pos + _COUNTER_BYTES:], 'little')

        return CipherChannel(key, file_path, seq_send, seq_recv, stored_eid, initiator)

    # ── send ──────────────────────────────────────────────────────────────────

    def send(self, data: bytes, associated_data: bytes = b'') -> bytes:
        """
        Encrypt data and return the wire packet: nonce(12) || ciphertext || tag(16).

        associated_data is authenticated (bound into the GCM tag) but not
        transmitted and not part of the returned packet: both ends must
        already agree on it out of band (e.g. a fixed per-endpoint context
        string), which is how the provisioning key exchange binds a key
        response to the endpoint it was issued for without adding wire
        overhead or changing MAX_PACKET_SIZE. Defaults to empty, which
        reproduces the original (unbound) wire behaviour for callers that
        do not pass it.

        Increments and durably persists the send counter BEFORE returning the
        packet. Raises ChannelException on oversized input, counter exhaustion,
        or persistence failure.
        """
        if len(data) > MAX_PLAINTEXT_SIZE:
            raise ChannelException(
                f'Plaintext too large: {len(data)} > MAX_PLAINTEXT_SIZE ({MAX_PLAINTEXT_SIZE})')

        with self._lock:
            next_seq = self._seq_send + 2
            if next_seq > _COUNTER_MAX:
                raise ChannelException('Counter exhausted — provision a new key')
            self._seq_send = next_seq
            self._write_state()

            nonce = self._seq_send.to_bytes(NONCE_LEN, 'little')
            cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce, mac_len=MAC_LEN)
            if associated_data:
                cipher.update(associated_data)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            return nonce + ciphertext + tag

    # ── receive ───────────────────────────────────────────────────────────────

    def receive(self, data: bytes, associated_data: bytes = b'') -> Union[bytes, None]:
        """
        Validate and decrypt a wire packet.

        associated_data must match the value the sender used in send() or
        authentication fails (see send() for why this is not carried on the
        wire). Defaults to empty, matching send()'s default.

        Returns plaintext on success, None on any authentication, replay, parity,
        or size failure. Raises ChannelException if persistence fails after
        successful authentication (plaintext is NOT returned in that case).

        Counter freshness and direction parity are checked BEFORE decryption.
        Plaintext is not returned until the updated receive counter is durable.
        """
        # Minimum valid packet: nonce(12) + empty ciphertext + tag(16) = 28 bytes
        if len(data) < NONCE_LEN + MAC_LEN:
            return None
        if len(data) > MAX_PACKET_SIZE:
            return None

        with self._lock:
            nonce    = data[:NONCE_LEN]
            sequence = int.from_bytes(nonce, 'little')

            # Counter freshness and direction-parity check BEFORE decryption
            if sequence <= self._seq_receive:
                return None
            if (sequence & 1) != (self._seq_receive & 1):
                return None

            ciphertext = data[NONCE_LEN:-MAC_LEN]
            tag        = data[-MAC_LEN:]

            try:
                cipher    = AES.new(self._key, AES.MODE_GCM, nonce=nonce, mac_len=MAC_LEN)
                if associated_data:
                    cipher.update(associated_data)
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            except ValueError:
                return None

            # Persist counter BEFORE releasing plaintext
            self._seq_receive = sequence
            self._write_state()  # raises ChannelException on failure — no plaintext returned

            return plaintext
