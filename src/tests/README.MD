# Pruebas Unitarias - Blu

Esta carpeta contiene las pruebas unitarias del proyecto **Blu**, enfocadas principalmente en validar que los módulos criptográficos funcionen correctamente antes de integrarlos con la interfaz y el backend.

El objetivo de estos tests es comprobar que el sistema pueda generar llaves, cifrar información, descifrar mensajes, validar tokens y manejar datos en Base64 de forma confiable.

---

## Archivos de prueba

### `jwt.test.js`

Este test valida el manejo de tokens JWT dentro del proyecto.

Prueba que el sistema pueda:

- Generar un JWT válido.
- Decodificar correctamente el payload del token.
- Verificar la firma del JWT usando la clave secreta correcta.
- Rechazar un JWT cuando se usa una clave incorrecta.
- Lanzar errores cuando falta el secret o cuando el formato de expiración no es válido.

En pocas palabras, este test confirma que la autenticación basada en tokens funcione de forma segura y no acepte tokens manipulados.

---

### `privateKeyEncryption.test.js`

Este test valida el cifrado de la llave privada del usuario.

Prueba que el sistema pueda:

- Generar una llave privada RSA.
- Cifrar esa llave privada usando una contraseña.
- Usar PBKDF2 para derivar una clave segura desde la contraseña.
- Usar AES-GCM para proteger la llave privada.
- Descifrar correctamente la llave cuando la contraseña es correcta.
- Rechazar el descifrado cuando se usa una contraseña incorrecta.

Este test es importante porque la llave privada no debería guardarse en texto plano. La idea es que, aunque alguien vea el archivo generado, no pueda usarlo sin la contraseña correcta.

---

### `rsaKeyPair.test.js`

Este test valida la generación de pares de llaves RSA.

Prueba que el sistema genere:

- Una llave pública en formato PEM.
- Una llave privada en formato PEM.
- Encabezados correctos como `-----BEGIN PUBLIC KEY-----`.
- Encabezados correctos como `-----BEGIN PRIVATE KEY-----`.

Este test confirma que el usuario tenga un par de llaves válido para poder usar cifrado asimétrico dentro del sistema.

---

### `messageCrypto.test.js`

Este test valida el flujo principal de cifrado de mensajes.

Prueba que el sistema pueda:

- Cifrar un mensaje usando AES-256-GCM.
- Separar correctamente el `ciphertext`, `nonce` y `auth tag`.
- Validar que el nonce tenga 12 bytes.
- Validar que el auth tag tenga 16 bytes.
- Cifrar un mensaje grupal para varios usuarios.
- Descifrar un mensaje grupal usando la llave privada correcta.

Este test representa bastante bien el flujo real del proyecto: escribir un mensaje, cifrarlo, guardar sus partes importantes y permitir que un miembro autorizado pueda recuperarlo.

---

### `aesGcm.test.js`

Este test se enfoca específicamente en AES-256-GCM.

Prueba que el sistema pueda:

- Cifrar y descifrar un mensaje correctamente.
- Generar un nonce diferente para cada mensaje.
- Detectar si el `auth tag` fue alterado.

Este test ayuda a comprobar la confidencialidad e integridad del mensaje. Es decir, no solo valida que el mensaje se esconda, sino también que cualquier modificación pueda ser detectada.

---

### `base64.test.js`

Este test valida las funciones auxiliares de Base64.

Prueba que el sistema pueda:

- Convertir un `ArrayBuffer` a Base64.
- Recuperar el `ArrayBuffer` original desde Base64.
- Concatenar varios buffers en el orden correcto.

Aunque parezca simple, este test es clave porque los mensajes cifrados, nonces, tags y llaves cifradas se almacenan en Base64 para poder enviarse y guardarse fácilmente.

---

### `hybridMessageCrypto.test.js`

Este test valida el cifrado híbrido del sistema.

Prueba que el sistema pueda:

- Cifrar un mensaje con AES.
- Proteger la clave AES usando RSA-OAEP.
- Descifrar el mensaje con la llave privada correcta.
- Cifrar la misma clave AES para varios miembros de un grupo.
- Rechazar el descifrado cuando se usa una llave privada incorrecta.

Este test es uno de los más importantes del módulo, porque valida el funcionamiento principal del cifrado híbrido usado en los chats grupales.

---

### `setupTests.js`

Este archivo no es un test como tal, sino una configuración para que las pruebas puedan correr en Node.

Se encarga de preparar:

- `crypto.subtle`
- `TextEncoder`
- `TextDecoder`
- `btoa`
- `atob`

Esto es necesario porque varias funciones fueron pensadas para correr en navegador, pero los tests se ejecutan en Node.

---

## Cómo correr las pruebas

Para ejecutar los tests una sola vez:

```bash
npm run test:run