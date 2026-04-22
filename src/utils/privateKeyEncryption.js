const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
* Convierte bytes a Base64.
*/
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";

    bytes.forEach((byte) => {
        binary += String.fromCharCode(byte);
    });

    return btoa(binary);
}

/**
* Convierte Base64 a bytes.
*/
function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes.buffer;
}

/**
* Importa la contraseña como material inicial para PBKDF2.
*/
async function getPasswordKey(password) {
    return await window.crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );
}

/**
* Deriva una clave AES-GCM usando PBKDF2.
*/
async function deriveAesKeyFromPassword(password, salt, iterations = 600000) {
    const passwordKey = await getPasswordKey(password);

    return await window.crypto.subtle.deriveKey(
    {
        name: "PBKDF2",
        salt,
        iterations,
        hash: "SHA-256",
        },
        passwordKey,
        {
        name: "AES-GCM",
        length: 256,
        },
        false,
        ["encrypt", "decrypt"]
    );
}

/**
* Cifra una llave privada PEM usando una contraseña.
*
* @param {string} privateKeyPem - Llave privada en formato PEM.
* @param {string} password - Contraseña original del usuario.
* @returns {object} Datos necesarios para guardar la llave cifrada.
*/
export async function encryptPrivateKey(privateKeyPem, password) {
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const iterations = 600000;

    const aesKey = await deriveAesKeyFromPassword(password, salt, iterations);

    const encryptedPrivateKey = await window.crypto.subtle.encrypt(
        {
        name: "AES-GCM",
        iv,
        },
        aesKey,
        encoder.encode(privateKeyPem)
    );

    return {
        algorithm: "AES-GCM",
        kdf: "PBKDF2",
        hash: "SHA-256",
        iterations,
        salt: arrayBufferToBase64(salt),
        iv: arrayBufferToBase64(iv),
        encryptedPrivateKey: arrayBufferToBase64(encryptedPrivateKey),
    };
}

/**
* Descifra una llave privada cifrada usando la contraseña correcta.
*
* @param {object} encryptedData - Objeto generado por encryptPrivateKey.
* @param {string} password - Contraseña original del usuario.
* @returns {string} Llave privada PEM original.
*/
export async function decryptPrivateKey(encryptedData, password) {
    const salt = new Uint8Array(base64ToArrayBuffer(encryptedData.salt));
    const iv = new Uint8Array(base64ToArrayBuffer(encryptedData.iv));

    const aesKey = await deriveAesKeyFromPassword(
        password,
        salt,
        encryptedData.iterations
    );

    const decryptedPrivateKey = await window.crypto.subtle.decrypt(
        {
        name: encryptedData.algorithm,
        iv,
        },
        aesKey,
        base64ToArrayBuffer(encryptedData.encryptedPrivateKey)
    );

    return decoder.decode(decryptedPrivateKey);
}