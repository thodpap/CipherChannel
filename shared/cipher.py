from __future__ import annotations
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding
from typing import Union
import base64
import os

class ChannelException(Exception):
	pass

class CipherChannel:
	"""
	This is not a thread safe implementation of the channel class (synchronization around the sequences and file writing).
	This is not a process parallel implementation (no two processes must simultaneously run on the same channel state).

	This implementation encodes message freshness into the nonce (possible because its strictly monotonically increasing, and does not need to be kept confidential).
	This ensures that each used nonce is definitely unique, and that no additional sequencing logic needs to be added.

	The sequence is stored in each direction. And each exchanged message must have a higher sequence number compared to the last received message.
	It is then promptly written to a file, to ensure consistency across reboots.
	This ensures that no timing synchronization or out-of-sync issues can ever occur.
	Futher, it ensures that each message is fresh and unique, as a received message must always be newer than already processed.

	To ensure that messages cannot be replayed against oneself, they are direction coded.
	The initiator always only produces even stamps, while the other party will always produce odd stamps.
	Important: Upon the initial key exchange, exactly one endpoint must have 'initiator' set to true, and one set to false.

	Note: the channel does not encode any form of acknowledgement of received messages.
	An attacker can still consume messages/prevent them from being delivered.
	The application layer needs to ensure that messages have been delivered/were not deliberately hidden.
	"""

	_nonce_length = 16
	_mac_length = 16
	_file_key_size = 2

	def _write_state(self):
		try:
			temp = f'{self._file}.tmp'

			# write the secret and initial sequences to the temporary file
			with open(temp, 'wb') as f:
				send = self._seq_send.to_bytes(CipherChannel._nonce_length, 'little')
				recv = self._seq_receive.to_bytes(CipherChannel._nonce_length, 'little')
				f.write(len(self._key).to_bytes(CipherChannel._file_key_size, 'little') +  self._key + send + recv)

			# replace the file to ensure it is atomically written/committed (i.e. no partial file writes)
			os.replace(temp, self._file)
		except OSError as e:
			raise ChannelException(f'Failed to write channel state: {e}')

	def __init__(self, key: bytes, file: str, seq_send: int, seq_recv: int) -> None:
		self._key = key
		self._file = file
		self._seq_send = seq_send
		self._seq_receive = seq_recv
		pass

	@staticmethod
	def create(key: bytes, initiator: bool, file_path: str) -> CipherChannel:
		""" Initialize a new cipher channel and write its first state to file (initiator gets the even stamps) """
		start = (0 if initiator else 1)
		c =  CipherChannel(key, file_path, start, 1 - start)
		c._write_state()
		return c

	@staticmethod
	def load(file_path: str) -> CipherChannel:
		""" load a cipher channel from file """
		try:
			data = b''
			with open(file_path, 'rb') as f:
				data = f.read()

			# read the key length and validate the overall state length
			key_length = 0
			if len(data) > CipherChannel._file_key_size:
				key_length = int.from_bytes(data[:CipherChannel._file_key_size], 'little')
				data = data[CipherChannel._file_key_size:]
			if key_length == 0 or len(data) != key_length + 2 * CipherChannel._nonce_length:
				raise ChannelException('Channel state corrupted')
			
			# read the key and the two sequence numbers
			send = int.from_bytes(data[key_length:-CipherChannel._nonce_length], 'little')
			recv = int.from_bytes(data[-CipherChannel._nonce_length:], 'little')
			return CipherChannel(data[0:key_length], file_path, send, recv)
		except OSError as e:
			raise ChannelException(f'Unable to load channel state: {e}')

	def receive(self, data: bytes) -> Union[bytes, None]:
		""" decrypt received data and validate them (returns None for bad/out-of-sequence data) """
	
		# validate the length to contain at least the nonce and integrity-token, and the remainder
		# being a multiple of the AES block-size, otherwise discard the data
		if len(data) < CipherChannel._nonce_length + CipherChannel._mac_length:
			return None
		if (len(data) - CipherChannel._nonce_length - CipherChannel._mac_length) % AES.block_size != 0:
			return None

		# extract the three components and construct the AES cipher object
		nonce = data[:CipherChannel._nonce_length]
		cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce, mac_len=CipherChannel._mac_length)
		cipher_text, int_token = data[CipherChannel._nonce_length:-CipherChannel._mac_length], data[-CipherChannel._mac_length:]
		
		# decrypt the data and verify the integrity and otherwise discard the data
		try:
			padded = cipher.decrypt_and_verify(cipher_text, int_token)
		except ValueError:
			return None

		# verify the padding and otherwise discard the message (no explicit returned warning to prevent padding-oracle-attacks)
		try:
			plain_text = Padding.unpad(padded, AES.block_size)
		except ValueError:
			return None
		
		# validate the sequence of the received number to be a definitely new value of the same parity and write the
		# new value back (before returning the encrypted data to prevent race-conditions on crashes before write-back)
		sequence = int.from_bytes(nonce, 'little')
		if sequence <= self._seq_receive or (sequence & 0x01) != (self._seq_receive & 0x01):
			return None
		self._seq_receive = sequence
		self._write_state()

		return plain_text

	def send(self, data: bytes) -> bytes:
		""" encrypt the data and prepare them to be sent """
	
		# update the send sequence counter and write it back (to ensure it will never be re-used again)
		self._seq_send += 2
		self._write_state()

		# construct the AES object in GCM-mode (ensures both encryption and integrity of the data)
		nonce = self._seq_send.to_bytes(CipherChannel._nonce_length, 'little')
		cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce, mac_len=CipherChannel._mac_length)

		# construct the padded data and encrypt them and return the combined data (nonce,ciphertext,int-token)
		padded = Padding.pad(data, AES.block_size)
		cipher_text, int_token = cipher.encrypt_and_digest(padded)
		return nonce + cipher_text + int_token


if __name__ == "__main__":
	msg = b'this is a test-message'

	# Example usage
	key = get_random_bytes(32)  # 16 bytes for AES-128, 32 bytes for AES-256
	server, client = CipherChannel.create(key, True, './.client0'), CipherChannel.create(key, False, './.client1')

	# this works (normal transfer)
	c = server.send(msg)
	r = client.receive(c)
	print(f'[s -> c] sent: {msg} [{base64.b64encode(c)}] | recv: {r}')

	# this fails (replay-attack by replaying against receiver)
	r = client.receive(c)
	print(f'[s -> c] replay: [{base64.b64encode(c)}] | recv: {r}')

	# this also fails (replay-attack by replaying against sender)
	r = server.receive(c)
	print(f'[s -> s] replay: [{base64.b64encode(c)}] | recv: {r}')

	# this works again (normal next transfer)
	c = server.send(msg)
	r = client.receive(c)
	print(f'[s -> c] sent: {msg} [{base64.b64encode(c)}] | recv: {r}')

	# this fails (modified-in-transit)
	c = server.send(msg)
	c = c[:20] + bytes([c[20] + 1]) + c[21:]
	r = client.receive(c)
	print(f'[s -> c] modified: {msg} [{base64.b64encode(c)}] | recv: {r}')