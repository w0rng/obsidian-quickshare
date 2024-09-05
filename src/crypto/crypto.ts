
/**
 * Generates a random 256-bit key using crypto.getRandomValues.
 */
export async function generateRandomKey(): Promise<{ key: ArrayBuffer, iv: ArrayBuffer }> {
    const seed = window.crypto.getRandomValues(new Uint8Array(64));
    const iv = window.crypto.getRandomValues(new Uint8Array(16));
    return {key: await _generateKey(seed), iv};
}

async function _generateKey(seed: ArrayBuffer): Promise<ArrayBuffer> {
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        seed,
        {name: "PBKDF2"},
        false,
        ["deriveBits"]
    );

    const masterKey = await window.crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: new Uint8Array(16),
            iterations: 100000,
            hash: "SHA-256",
        },
        keyMaterial,
        32
    );

    return new Uint8Array(masterKey);
}

export function masterKeyToString(key: { key: ArrayBuffer, iv: ArrayBuffer }): { key: string, iv: string } {
    return {key: arrayBufferToBase64(key.key).slice(0, 43), iv: arrayBufferToBase64(key.iv)};
}

export async function encryptString(
    md: string,
    secret: { key: ArrayBuffer, iv: ArrayBuffer }
): Promise<string> {
    const plaintext = new TextEncoder().encode(md);

    return encryptArrayBuffer(plaintext, secret);
}

export async function encryptArrayBuffer(
    data: ArrayBuffer,
    secret: { key: ArrayBuffer, iv: ArrayBuffer }
): Promise<string> {

    const buf_ciphertext: ArrayBuffer = await window.crypto.subtle.encrypt(
        {name: "AES-GCM", iv: secret.iv},
        await _getAesGcmKey(secret.key),
        data
    );

    return arrayBufferToBase64(buf_ciphertext);

}

export function arrayBufferToBase64(buffer: ArrayBuffer): string {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const chunkSize = 0x8000; // 32,768 bytes

    for (let i = 0; i < bytes.length; i += chunkSize) {
        const chunk = bytes.subarray(i, i + chunkSize);
        binary += String.fromCharCode(...chunk);
    }

    return window.btoa(binary);
}


function _getAesGcmKey(secret: ArrayBuffer): Promise<CryptoKey> {
    return window.crypto.subtle.importKey(
        "raw",
        secret,
        {name: "AES-GCM", length: 256},
        false,
        ["encrypt", "decrypt"]
    );
}
