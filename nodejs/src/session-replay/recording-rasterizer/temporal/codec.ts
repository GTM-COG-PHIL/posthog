import { PayloadCodec } from '@temporalio/common'
import { Payload as PayloadProto } from '@temporalio/common/lib/interfaces'
import { temporal } from '@temporalio/proto'
import * as crypto from 'crypto'

const ENCODING_KEY = 'encoding'
const ENCRYPTED_ENCODING = 'binary/encrypted'

// Legacy Fernet format constants (kept for backward-compatible decryption)
const FERNET_VERSION = 0x80
const FERNET_HEADER_SIZE = 1 + 8 + 16 // version + timestamp + IV
const HMAC_SIZE = 32

// AES-256-GCM format constants
const GCM_VERSION = 0x81
const GCM_IV_SIZE = 12
const GCM_AUTH_TAG_SIZE = 16
const GCM_HEADER_SIZE = 1 + 8 + GCM_IV_SIZE // version + timestamp + IV

/**
 * Authenticated encryption codec for Temporal payload encryption.
 *
 * Encrypts with AES-256-GCM (version 0x81) and decrypts both GCM tokens and
 * legacy Fernet tokens (version 0x80, AES-128-CBC + HMAC-SHA256) for backward
 * compatibility with the Python EncryptionCodec (posthog/temporal/common/codec.py).
 *
 * Key derivation matches the Python side: the Django SECRET_KEY is zero-padded
 * (left) or truncated to 32 bytes.
 */
export class EncryptionCodec implements PayloadCodec {
    // Legacy Fernet keys (for backward-compatible decryption)
    private signingKey: Buffer
    private encryptionKey: Buffer
    // AES-256-GCM key (full 32 bytes)
    private gcmKey: Buffer

    constructor(secretKey: string) {
        // Match Python: pad with null bytes on the left, truncate to 32 bytes
        const padded = Buffer.alloc(32)
        const keyBytes = Buffer.from(secretKey, 'utf-8')
        if (keyBytes.length > 32) {
            console.warn(`EncryptionCodec: secret key is ${keyBytes.length} bytes, truncating to 32`)
        }
        const padLen = Math.max(32 - keyBytes.length, 0)
        keyBytes.copy(padded, padLen, 0, Math.min(keyBytes.length, 32))

        this.signingKey = padded.subarray(0, 16)
        this.encryptionKey = padded.subarray(16, 32)
        this.gcmKey = Buffer.from(padded)
    }

    // eslint-disable-next-line @typescript-eslint/require-await
    async encode(payloads: PayloadProto[]): Promise<PayloadProto[]> {
        return payloads.map((p) => ({
            metadata: { [ENCODING_KEY]: new TextEncoder().encode(ENCRYPTED_ENCODING) },
            data: this.encrypt(temporal.api.common.v1.Payload.encode(p).finish()),
        }))
    }

    // eslint-disable-next-line @typescript-eslint/require-await
    async decode(payloads: PayloadProto[]): Promise<PayloadProto[]> {
        return payloads.map((p) => {
            const encoding = p.metadata?.[ENCODING_KEY]
            if (!encoding || new TextDecoder().decode(encoding) !== ENCRYPTED_ENCODING) {
                return p
            }
            const decrypted = this.decrypt(p.data as Uint8Array)
            return temporal.api.common.v1.Payload.decode(decrypted)
        })
    }

    private encrypt(data: Uint8Array): Uint8Array {
        const iv = crypto.randomBytes(GCM_IV_SIZE)
        const timestamp = BigInt(Math.floor(Date.now() / 1000))

        const cipher = crypto.createCipheriv('aes-256-gcm', this.gcmKey, iv)
        const ciphertext = Buffer.concat([cipher.update(data), cipher.final()])
        const authTag = cipher.getAuthTag()

        // GCM token: version(1) || timestamp(8) || IV(12) || authTag(16) || ciphertext
        const token = Buffer.alloc(GCM_HEADER_SIZE + GCM_AUTH_TAG_SIZE + ciphertext.length)
        token[0] = GCM_VERSION
        token.writeBigUInt64BE(timestamp, 1)
        iv.copy(token, 9)
        authTag.copy(token, GCM_HEADER_SIZE)
        ciphertext.copy(token, GCM_HEADER_SIZE + GCM_AUTH_TAG_SIZE)

        return Buffer.from(token.toString('base64url'))
    }

    private decrypt(token: Uint8Array): Uint8Array {
        const buf = Buffer.from(Buffer.from(token).toString(), 'base64url')

        if (buf[0] === GCM_VERSION) {
            return this.decryptGcm(buf)
        }
        return this.decryptFernet(buf)
    }

    private decryptGcm(buf: Buffer): Uint8Array {
        if (buf.length < GCM_HEADER_SIZE + GCM_AUTH_TAG_SIZE) {
            throw new Error('GCM token too short')
        }

        const iv = buf.subarray(9, 9 + GCM_IV_SIZE)
        const authTag = buf.subarray(GCM_HEADER_SIZE, GCM_HEADER_SIZE + GCM_AUTH_TAG_SIZE)
        const ciphertext = buf.subarray(GCM_HEADER_SIZE + GCM_AUTH_TAG_SIZE)

        const decipher = crypto.createDecipheriv('aes-256-gcm', this.gcmKey, iv)
        decipher.setAuthTag(authTag)
        return Buffer.concat([decipher.update(ciphertext), decipher.final()])
    }

    private decryptFernet(buf: Buffer): Uint8Array {
        if (buf.length < FERNET_HEADER_SIZE + HMAC_SIZE) {
            throw new Error('Fernet token too short')
        }
        if (buf[0] !== FERNET_VERSION) {
            throw new Error(`Unexpected Fernet version: ${buf[0]}`)
        }

        const body = buf.subarray(0, buf.length - HMAC_SIZE)
        const providedHmac = buf.subarray(buf.length - HMAC_SIZE)
        const computedHmac = crypto.createHmac('sha256', this.signingKey).update(body).digest()

        if (!crypto.timingSafeEqual(providedHmac, computedHmac)) {
            throw new Error('Fernet HMAC verification failed')
        }

        const iv = buf.subarray(9, 25)
        const ciphertext = buf.subarray(FERNET_HEADER_SIZE, buf.length - HMAC_SIZE)

        const decipher = crypto.createDecipheriv('aes-128-cbc', this.encryptionKey, iv)
        return Buffer.concat([decipher.update(ciphertext), decipher.final()])
    }
}
