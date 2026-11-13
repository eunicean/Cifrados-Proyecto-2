# Hito 2 · PoC del Red Team

**Aplicación:** Cifrados-Proyecto-2 · **Destino:** `http://localhost:8080` (WAF en `DetectionOnly`) · **Atacante:** Carol RT (usuario autenticado sin privilegios)
**Herramientas:** OWASP ZAP 2.17.0 (reconocimiento y escaneo) → Burp Suite Community 2026.10.1 (confirmación en Repeater e Intruder) → Postman (repetición para el Blue Team).
**Clasificación:** OWASP Top 10:2025, CWE y CVSS v3.1 (calculadora de FIRST). Horas en America/Guatemala (UTC-6). Detalle de cada envío en [`bitacora.md`](bitacora.md).

## Resumen

| PoC | Hallazgo | Ruta | OWASP 2025 | CWE | CVSS v3.1 | Amenaza H1 |
|---|---|---|---|---|---|---|
| 01 | Listado de todos los usuarios con su correo | `GET /api/users` | A01 Broken Access Control | CWE-359 | **4.3** Medium | T-15 |
| 02 | La búsqueda de grupos revela chats privados y acepta comodines | `GET /api/groups/search` | A01 Broken Access Control | CWE-200 (+ CWE-155) | **4.3** Medium | T-14 |
| 03 | Enumeración de usuarios por respuesta distinguible | `POST /api/direct-conversations` | A07 Authentication Failures | CWE-204 | **4.3** Medium | T-11 |
| 04 | Sin límite de intentos para el código de grupo | `POST /api/groups/:id/join` | A07 Authentication Failures | CWE-307 | **5.9** Medium | T-16 |
| 05 | DoS persistente por inundación de mensajes | `POST /api/messages` → `GET /api/messages/:userId` | A06 Insecure Design | CWE-770 (+ CWE-755) | **6.5** Medium | T-19 |

Los PoC 01 a 03 se **encadenan**. El PoC-01 traduce IDs a personas, el PoC-02 revela quién conversa con quién y el PoC-03 confirma correos concretos. El PoC-02 además entrega el ID del grupo privado que usa el PoC-04.

---

## PoC-01 · Exposición de todos los usuarios (T-15)

| Campo | Valor |
|---|---|
| Clasificación | **A01:2025 Broken Access Control** · **CWE-359** Exposure of Private Personal Information to an Unauthorized Actor |
| Dónde vive | `GET /api/users` en `app.js` (consulta `user` sin filtro por relación) |
| Herramienta | Burp Repeater (descubierto en ZAP y en la interfaz "Nuevo chat") |
| Vector | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` → **4.3** |

**Reproducción**
```http
GET /api/users HTTP/1.1
Host: localhost:8080
Authorization: Bearer <JWT de Carol>
```

**Resultado (10:40:15):** `200 OK`, 2259 bytes, con `id`, `name`, `email` y `key` (llave pública) de **los 4 usuarios** del sistema, incluidos `final@testemail.com`, Alice y Bob, con quienes Carol no comparte ningún canal.

**Impacto:** cualquier cuenta recién registrada obtiene el directorio completo de correos, que sirve para phishing dirigido y como diccionario de ID a persona para el PoC-02. Incumple **RS-06** y el objetivo de seguridad **OS-7**.

| Métrica | Valor | Justificación |
|---|---|---|
| AV | Network | Se explota por HTTP a través del WAF |
| AC | Low | Una sola petición GET, sin condiciones especiales |
| PR | Low | Requiere una cuenta cualquiera; el registro es libre |
| UI | None | No interviene ninguna víctima |
| S | Unchanged | El impacto queda en la propia aplicación |
| C | Low | Se filtran datos personales (nombre y correo) y llaves públicas, no mensajes ni secretos |
| I | None | Solo lectura |
| A | None | Sin efecto en disponibilidad |

**Evidencia:** `burp/poc-01a-users.png`, `burp/poc-01b-users.png`. Postman: _pendiente_.
**Corrección sugerida (H4):** devolver solo los usuarios con los que se comparte un canal, o buscar por correo exacto sin listar, y nunca exponer `email` de terceros.

---

## PoC-02 · La búsqueda de grupos revela chats privados (T-14)

| Campo | Valor |
|---|---|
| Clasificación | **A01:2025 Broken Access Control** · **CWE-200** Exposure of Sensitive Information to an Unauthorized Actor · secundario **CWE-155** Improper Neutralization of Wildcards or Matching Symbols |
| Dónde vive | `GET /api/groups/search` en `app.js`: `.ilike('name', \`%${name}%\`)` sin excluir canales `direct:` ni escapar `%` y `_` |
| Herramienta | Burp Repeater |
| Vector | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` → **4.3** |

**Reproducción**
```http
GET /api/groups/search?name=direct HTTP/1.1
GET /api/groups/search?name=%25 HTTP/1.1
Host: localhost:8080
Authorization: Bearer <JWT de Carol>
```

**Resultado**
- **10:59:42** `?name=direct` → `200 OK` con el canal `direct:01fe2959…:b516c022…`, `created_by: b516c022…`, `is_member: false`. Con el PoC-01, `01fe2959` es Bob y `b516c022` es Alice: **Carol sabe que Alice y Bob tienen un chat privado, que lo inició Alice y cuándo**.
- **11:00:05** `?name=%25` (`%`) → `200 OK` con **20 canales** (el límite de la consulta), incluido el grupo privado **RT-Grupo-G** (`53efc8a9…`, `is_member: false`).

**Impacto:** filtra metadatos de comunicación (quién habla con quién y desde cuándo) en una app cuyo objetivo es la privacidad (ON-1). Además entrega IDs de grupos privados. Es el caso de abuso **CA-07**, que el H1 anticipaba que fallaría, e incumple **RS-05**.

| Métrica | Valor | Justificación |
|---|---|---|
| AV | Network | Petición HTTP a través del WAF |
| AC | Low | Basta un parámetro de búsqueda |
| PR | Low | Cualquier usuario autenticado |
| UI | None | Sin interacción de la víctima |
| S | Unchanged | Afecta solo a datos de la app |
| C | Low | Metadatos (participantes, creador, fecha e IDs), no el contenido cifrado |
| I | None | Solo lectura |
| A | None | Sin efecto |

**Resultado negativo relacionado:** los grupos que creó el Active Scan se guardaron con nombres como `RT-Carol' UNION ALL select NULL --` de forma literal. El cliente de Supabase parametriza, **no hay SQLi** (CA-01 y RS-08 se cumplen).
**Evidencia:** `burp/poc-02a-search-direct.png`, `burp/poc-02b-search-wildcard.png`. Postman: _pendiente_.
**Corrección sugerida (H4):** excluir los canales `direct:` de la búsqueda, escapar `%`, `_` y `\`, exigir una longitud mínima y no devolver `created_by`.

---

## PoC-03 · Enumeración de usuarios (T-11)

| Campo | Valor |
|---|---|
| Clasificación | **A07:2025 Authentication Failures** · **CWE-204** Observable Response Discrepancy |
| Dónde vive | `POST /api/direct-conversations` en `app.js` (`throw new Error('Contacto no encontrado.')`) |
| Herramienta | Burp Repeater |
| Vector | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` → **4.3** |

**Reproducción**
```http
POST /api/direct-conversations HTTP/1.1
Host: localhost:8080
Authorization: Bearer <JWT de Carol>
Content-Type: application/json

{"recipient_email":"rt.alice@example.com"}
```
Se repite con `{"recipient_email":"noexiste@example.com"}`.

**Resultado**
| Hora | Correo | Respuesta |
|---|---|---|
| 11:07:32 | `rt.alice@example.com` (existe) | `200 OK` con `id`, `name`, `email`, `key` y `channel_id` |
| 11:08:05 | `noexiste@example.com` (no existe) | `400` `"Contacto no encontrado."` |

**Impacto:** la diferencia de código y de mensaje permite validar una lista de correos y saber quién usa la app. Si el correo existe y no había chat, **además se crea un canal directo con la víctima sin su consentimiento**; el PoC-05 aprovecha eso. No se probó con correos nuevos para no crear canales extra.

| Métrica | Valor | Justificación |
|---|---|---|
| AV | Network | HTTP a través del WAF |
| AC | Low | Una petición por correo, automatizable |
| PR | Low | Requiere una cuenta cualquiera |
| UI | None | La víctima no participa |
| S | Unchanged | Dentro de la aplicación |
| C | Low | Confirma la existencia de cuentas y entrega su ID y su llave pública |
| I | None | Se valora la enumeración (la creación del canal se trata en el PoC-05) |
| A | None | Sin efecto |

**Evidencia:** `burp/poc-03a-enum-existe.png`, `burp/poc-03b-enum-no-existe.png`. Postman: _pendiente_.
**Corrección sugerida (H4):** respuesta uniforme para correos existentes e inexistentes, rate limit por usuario y, si se quiere evitar el spam, que la víctima acepte el chat.

---

## PoC-04 · Sin límite de intentos para el código de grupo (T-16)

| Campo | Valor |
|---|---|
| Clasificación | **A07:2025 Authentication Failures** · **CWE-307** Improper Restriction of Excessive Authentication Attempts |
| Dónde vive | `POST /api/groups/:id/join` en `app.js`: no usa limitador, a diferencia de `/auth/login` (`loginLimiter`, 10 fallos cada 15 min) |
| Herramienta | Burp Intruder (Sniper, 30 payloads) |
| Vector | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N` → **5.9** |

**Reproducción:** `POST /api/groups/53efc8a9-c38c-4d96-b16a-64821531e185/join` con `{"code":"§AAAAAAA1§"}` y 30 códigos falsos. El ID del grupo privado se obtuvo en el PoC-02.

**Resultado (14:47:45 – 14:48:06):** **31 × `400` "Código de grupo incorrecto"** y **ningún `429`**. La API registró los 31 intentos, a ~1,5 por segundo; la velocidad la limitó Burp Community, no el servidor.

**Impacto:** el único factor que protege un grupo privado es su código, y se puede probar sin límite. Si se acierta, el atacante se une al grupo, ve la lista de miembros y sus llaves públicas, descifra **todos los mensajes que se envíen desde ese momento** (el cliente cifra la clave AES para cada miembro) y puede escribir en él. El historial anterior lo ve solo cifrado, porque no tiene `encrypted_key` para esos mensajes.

| Métrica | Valor | Justificación |
|---|---|---|
| AV | Network | HTTP a través del WAF |
| AC | **High** | El código tiene 8 caracteres de un alfabeto de 31 (~8,5 × 10¹¹ combinaciones): acertar depende del espacio de claves, fuera del control del atacante |
| PR | Low | Requiere cuenta |
| UI | None | Sin víctima |
| S | Unchanged | Dentro de la app |
| C | High | Con éxito, lectura de todos los mensajes futuros del grupo privado y de sus miembros |
| I | Low | Puede publicar mensajes en el grupo |
| A | None | Sin efecto |

**Evidencia:** `burp/poc-04-intruder-join.png`, logs de `cifrados-api` (31 entradas "Codigo de grupo incorrecto"). Postman: _pendiente_.
**Corrección sugerida (H4):** limitador por usuario y por grupo (como `loginLimiter`), bloqueo temporal tras N fallos y alerta en el SIEM.

---

## PoC-05 · DoS persistente por inundación de mensajes (T-19)

| Campo | Valor |
|---|---|
| Clasificación | **A06:2025 Insecure Design** · **CWE-770** Allocation of Resources Without Limits or Throttling · secundario **CWE-755** Improper Handling of Exceptional Conditions (A10:2025) |
| Dónde vive | `POST /api/messages` sin límite por miembro; `GET /api/messages/:userId` carga todos los mensajes y hace `.in('message_id', [todos los IDs])` sin paginación; el error de Supabase se devuelve como `403` |
| Herramienta | ZAP Active Scan (inundación) + Burp Repeater (confirmación) |
| Vector | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` → **6.5** |

**Reproducción**
1. Un miembro envía cientos de mensajes a un canal. Aquí lo hizo el Active Scan de ZAP sobre `RT-Carol`, el 12-nov entre 21:54 y 22:20.
2. Cualquier miembro de ese canal pide su bandeja:
```http
GET /api/messages/7515e782-e642-4914-8805-99e44ac6d331 HTTP/1.1
GET /api/groups/36d5ba34-84b6-462d-8fa3-032d65011c76/messages HTTP/1.1
```

**Resultado**
| Hora | Petición | Respuesta |
|---|---|---|
| 14:52:17 | Bandeja global `/api/messages/:userId` | `403` `"No se pudo completar la operacion."`; el log de la API muestra `detail: 'Bad Request'` de Supabase |
| 14:53:00 | Mensajes del canal `RT-Carol` | `200`, **1 277 390 bytes**, **1000 mensajes** (tope por defecto de Supabase) |

**Impacto:** la vista de mensajes directos (`DirectMessages.jsx` → `loadUserMessages()` → `/messages/:userId`) deja de cargar para **todos los miembros** del canal inundado, de forma persistente, hasta que alguien borre filas en la base de datos. Como el PoC-03 permite abrir un chat directo con cualquier usuario sin su consentimiento, el atacante podría inundar ese chat y **dejar sin bandeja a cualquier víctima**. Esa cadena se deduce del código y **no se ejecutó**, para no dañar las cuentas de Alice y Bob; aquí se demostró sobre la cuenta de Carol.

| Métrica | Valor | Justificación |
|---|---|---|
| AV | Network | HTTP a través del WAF |
| AC | Low | Basta enviar mensajes; no hay límite de cantidad ni de frecuencia |
| PR | Low | Una cuenta cualquiera |
| UI | None | La víctima no hace nada; el fallo aparece al abrir su bandeja |
| S | Unchanged | Afecta a la aplicación |
| C | None | No expone datos |
| I | None | No altera datos de terceros (los mensajes basura son del atacante) |
| A | **High** | Pérdida persistente de la bandeja de mensajes de las víctimas; no se recupera sin intervenir la base de datos |

**Evidencia:** `burp/poc-05a-messages-dos.png`, `burp/poc-05b-canal-1000-mensajes.png`, `zap-desktop/` (Active Scan). Postman: _pendiente_.
**Corrección sugerida (H4):** paginar `/messages/:userId` y `/groups/:id/messages` (`limit` y cursor), consultar `message_keys` por canal o por lotes, limitar la frecuencia y el tamaño de `POST /messages` por usuario y devolver `5xx` en lugar de `403` ante errores internos.

---

## Otros hallazgos (no convertidos en PoC)

| Hallazgo | Fuente | Clasificación | Nota |
|---|---|---|---|
| Campos del mensaje sin validar (`<script>` guardado en `ciphertext_base64`, `nonce_base64`, `signature_algorithm`…) | ZAP Active Scan, alerta Low "XSS Weakness (Persistent in JSON Response)" | A05:2025 Injection · CWE-20 | React escapa la salida, no se ejecutó XSS. Misma causa raíz que el PoC-05 (T-18) |
| CSP sin `form-action` y con `style-src 'unsafe-inline'` | ZAP (4 Medium) y pipeline | A02:2025 Security Misconfiguration · CWE-693 | Ajuste de encabezados en nginx y en `index.html` |
| CORS comodín en respuestas 403 del WAF | `docker exec cifrados-waf printenv` | A02:2025 · CWE-942 | Valores por defecto de la imagen `owasp/modsecurity-crs:nginx`; para el Blue Team (H3) |
| `body-parser` 2.3.0 (GHSA-27r3-jxmh-p828, DoS) | Pipeline, job SCA | A03:2025 Software Supply Chain Failures · CWE-400 | Único gate que falla; se propone corregir en el H4 |
| Sin bypass del WAF | curl a `localhost:3001` | — | La API y nginx no publican puertos; solo `:8080` es alcanzable |

## Uso de IA

Redacción preparados con apoyo de Claude (Anthropic) a partir de las peticiones y respuestas reales de Burp y de la lectura de `app.js`. El Red Team revisó cada métrica y la ejecución de cada PoC.