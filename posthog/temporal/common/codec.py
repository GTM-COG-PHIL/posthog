import os
import time
import base64
import struct
from collections.abc import Iterable

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from temporalio.api.common.v1 import Payload
from temporalio.converter import PayloadCodec

# Legacy Fernet uses version byte 0x80
_FERNET_VERSION = 0x80
# AES-256-GCM uses version byte 0x81
_GCM_VERSION = 0x81
_GCM_IV_SIZE = 12
_GCM_AUTH_TAG_SIZE = 16
_GCM_HEADER_SIZE = 1 + 8 + _GCM_IV_SIZE  # version + timestamp + IV


class EncryptionCodec(PayloadCodec):
    """A PayloadCodec that encrypts/decrypts all Payloads.

    Encrypts with AES-256-GCM (version 0x81) and decrypts both GCM tokens and
    legacy Fernet tokens (version 0x80) for backward compatibility.

    Args:
        settings: Django settings to obtain the SECRET_KEY to use for encryption.
    """

    def __init__(self, settings) -> None:
        super().__init__()

        # Pad or truncate the SECRET_KEY to exactly 32 bytes (matching Node.js side)
        padded_key = b"\0" * max(32 - len(settings.SECRET_KEY), 0) + settings.SECRET_KEY.encode()
        padded_key = padded_key[:32]

        # Legacy Fernet support for decrypting old tokens
        encoded_key = base64.urlsafe_b64encode(padded_key)
        self.fernet = Fernet(encoded_key)

        # AES-256-GCM key (full 32 bytes)
        self.gcm = AESGCM(padded_key)

    async def encode(self, payloads: Iterable[Payload]) -> list[Payload]:
        """Encrypt all payloads during encoding."""
        return [
            Payload(
                metadata={
                    "encoding": b"binary/encrypted",
                },
                data=self.encrypt(p.SerializeToString()),
            )
            for p in payloads
        ]

    async def decode(self, payloads: Iterable[Payload]) -> list[Payload]:
        """Decode all payloads decrypting those with expected encoding."""
        ret: list[Payload] = []
        for p in payloads:
            # Ignore ones without our expected encoding
            if p.metadata.get("encoding", b"").decode() != "binary/encrypted":
                ret.append(p)
                continue

            ret.append(Payload.FromString(self.decrypt(p.data)))
        return ret

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data using AES-256-GCM and return a base64url-encoded token."""
        iv = os.urandom(_GCM_IV_SIZE)
        timestamp = int(time.time())

        # AESGCM.encrypt returns ciphertext || auth_tag (tag is last 16 bytes)
        ct_with_tag = self.gcm.encrypt(iv, data, None)
        ciphertext = ct_with_tag[:-_GCM_AUTH_TAG_SIZE]
        auth_tag = ct_with_tag[-_GCM_AUTH_TAG_SIZE:]

        # GCM token: version(1) || timestamp(8) || IV(12) || authTag(16) || ciphertext
        header = struct.pack(">BQ", _GCM_VERSION, timestamp)
        token = header + iv + auth_tag + ciphertext

        return base64.urlsafe_b64encode(token)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data, auto-detecting GCM (0x81) vs legacy Fernet (0x80) format."""
        raw = base64.urlsafe_b64decode(data)

        if raw[0] == _GCM_VERSION:
            return self._decrypt_gcm(raw)
        return self.fernet.decrypt(data)

    def _decrypt_gcm(self, raw: bytes) -> bytes:
        if len(raw) < _GCM_HEADER_SIZE + _GCM_AUTH_TAG_SIZE:
            raise ValueError("GCM token too short")

        iv = raw[9 : 9 + _GCM_IV_SIZE]
        auth_tag = raw[_GCM_HEADER_SIZE : _GCM_HEADER_SIZE + _GCM_AUTH_TAG_SIZE]
        ciphertext = raw[_GCM_HEADER_SIZE + _GCM_AUTH_TAG_SIZE :]

        # AESGCM.decrypt expects nonce + ciphertext||tag
        return self.gcm.decrypt(iv, ciphertext + auth_tag, None)
