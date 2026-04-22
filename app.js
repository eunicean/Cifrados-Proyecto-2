const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

// ============================================================
// 1) Base de datos en memoria
// ============================================================

const usersByEmail = new Map();
let nextUserId = 1;

// ============================================================
// 2) Utilidades para rutas y nombres de archivo
// ============================================================

function getNovaDesktopFolder() {

  return path.join(os.homedir(), "Desktop", "nova");
}

function sanitizeFileName(value) {

  return value.replace(/[^a-zA-Z0-9._-]/g, "_");
}


function generateRsaKeyPairPem() {

  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicExponent: 0x10001,
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
  });

  return {
    publicKeyPem: publicKey,
    privateKeyPem: privateKey,
  };
}

function savePrivateKeyToNovaFolder(email, privateKeyPem) {

  const novaFolder = getNovaDesktopFolder();
  fs.mkdirSync(novaFolder, { recursive: true });

  const safeEmail = sanitizeFileName(email);
  const privateKeyPath = path.join(novaFolder, `${safeEmail}_private_key.pem`);

  fs.writeFileSync(privateKeyPath, privateKeyPem, {
    encoding: "utf8",
    mode: 0o600,
  });

  return privateKeyPath;
}

// ============================================================
// 4) Registro de usuario
// ============================================================

function registerUser(name, email, password) {

  const normalizedEmail = email.trim().toLowerCase();

  if (usersByEmail.has(normalizedEmail)) {
    throw new Error("El correo ya esta registrado.");
  }

  const { publicKeyPem, privateKeyPem } = generateRsaKeyPairPem();
  const privateKeyPath = savePrivateKeyToNovaFolder(
    normalizedEmail,
    privateKeyPem
  );

  const user = {
    id: nextUserId,
    name: name.trim(),
    email: normalizedEmail,
    password, // TODO: reemplazar por hash seguro con bcrypt o Argon2id.
    publicKeyPem,
    privateKeyPath,
  };

  usersByEmail.set(normalizedEmail, user);
  nextUserId += 1;

  return user;
}

// ============================================================
// 5) Ejemplo de uso
// ============================================================

if (require.main === module) {
  try {
    const newUser = registerUser(
      "Ana Torres",
      "ana@example.com",
      "MiPasswordTemporal123"
    );

    console.log("=== Usuario registrado ===");
    console.log(`ID: ${newUser.id}`);
    console.log(`Nombre: ${newUser.name}`);
    console.log(`Email: ${newUser.email}`);

    console.log("\nLlave publica generada (inicio PEM):");
    console.log(newUser.publicKeyPem.split("\n")[0]);
    console.log(`${newUser.publicKeyPem.split("\n")[1].slice(0, 64)}...`);

    console.log("\nLlave privada guardada en:");
    console.log(newUser.privateKeyPath);

    console.log("\nUsuarios guardados en memoria:");
    console.log(`${usersByEmail.size} usuario(s)`);
  } catch (error) {
    console.error(`Error en registro: ${error.message}`);
  }
}

module.exports = {
  registerUser,
  generateRsaKeyPairPem,
  getNovaDesktopFolder,
};