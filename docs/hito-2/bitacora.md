# Bitácora de ataques · Hito 2 (Red Team)

- **Destino único:** `http://localhost:8080` (WAF ModSecurity + OWASP CRS → nginx → API Express). No se atacó Render, Supabase directamente ni sistemas de terceros.
- **Modo del WAF:** `MODSEC_RULE_ENGINE=DetectionOnly` durante todas las pruebas.
- **Zona horaria:** America/Guatemala (UTC-6). Las horas de Burp en GMT se convirtieron restando 6 h.
- **Cuentas de prueba** (datos ficticios, dominio reservado `example.com`):

| Rol | Usuario | ID |
|---|---|---|
| Víctima 1 | Alice RT · `rt.alice@example.com` | `b516c022-26ac-468d-b16a-2530c02b909f` |
| Víctima 2 | Bob RT · `rt.bob@example.com` | `01fe2959-efe5-4cf8-afbf-bcedaee58ce1` |
| Atacante | Carol RT · `rt.carol@example.com` | `7515e782-e642-4914-8805-99e44ac6d331` |

- **Datos sembrados:** grupo privado `RT-Grupo-G` (`53efc8a9-c38c-4d96-b16a-64821531e185`, miembros Alice y Bob) y chat directo Alice ↔ Bob. Carol no pertenece a ninguno.

| Fecha y hora | Hallazgo | Herramienta | Destino | Resultado |
|---|---|---|---|---|
| 2026-11-12 19:38:00 | Verificación del WAF (DetectionOnly) | curl | `localhost:8080/?q=1' OR '1'='1` | 200; el WAF registra las reglas 942100 (SQLi) y 949110 (umbral de anomalía) sin bloquear |
| 2026-11-12 19:39:21 | Verificación de bypass | curl | `localhost:3001/groups` (puerto directo de la API) | 000, sin respuesta: la API no está publicada, sin bypass |
| 2026-11-12 19:39:21 | Verificación de la cadena | curl | `localhost:8080/login` y `/api/groups` | 200 y 401: app y API responden detrás del WAF |
| 2026-11-12 21:34:00 | Reconocimiento: Spider | ZAP 2.17.0 (Spider, Protected Mode, sesión de Carol) | `localhost:8080` | 49 URLs encontradas, 14 nodos; URLs de terceros fuera de contexto, no visitadas (fin ~21:35) |
| 2026-11-12 21:39:37 | Reconocimiento: AJAX Spider | ZAP 2.17.0 (AJAX Spider) | `localhost:8080` | 4 URLs (la SPA sin sesión redirige a /login); peticiones de terceros bloqueadas por Protected Mode; detenido 21:52 |
| 2026-11-12 21:54:00 | Escaneo activo | ZAP 2.17.0 (Active Scan, Default Policy, sesión de Carol) | `localhost:8080` (todo el sitio) | 6475 peticiones, fin 22:20; 0 High, 4 Medium, 1 Low, 5 Info. El WAF registró 3976 eventos 949110 (en modo On habrían sido 403) |
| 2026-11-12 22:44:00 | Verificación de autenticación del escaneo | docker logs | `cifrados-api` | 16 423 líneas de log con el ID de Carol entre 21:54 y 22:20: el Active Scan corrió autenticado |
| 2026-11-13 10:26:10 | Observación: GET /api/messages/:userId falla tras la inundación del escaneo | Navegador de Burp + docker logs | `localhost:8080/api/messages/7515e782…` | 403 genérico; log de la API: Supabase 'Bad Request' (consulta .in() con cientos de IDs, sin paginación). Origen del PoC-05 |
| 2026-11-13 10:34:00 | Observación para el Blue Team: CORS por defecto de la imagen del WAF | docker exec printenv | `cifrados-waf` | CORS_HEADER_403_ALLOW_ORIGIN=* y CORS_HEADER_ACCESS_CONTROL_ALLOW_HEADERS=* (valores por defecto de owasp/modsecurity-crs:nginx); a ajustar en H3 |
| 2026-11-13 10:40:15 | PoC-01 Exposición de usuarios (T-15) | Burp Repeater | `GET localhost:8080/api/users` (JWT de Carol) | 200 OK, 2259 bytes: id, nombre, correo y llave pública de los 4 usuarios, incluidos los que no comparten canal con Carol |
| 2026-11-13 10:59:42 | PoC-02 Búsqueda revela chats privados (T-14) | Burp Repeater | `GET localhost:8080/api/groups/search?name=direct` | 200 OK: canal direct:<Bob>:<Alice> con is_member=false; Carol descubre que Alice y Bob conversan |
| 2026-11-13 11:00:05 | PoC-02 Comodín en búsqueda (T-14) | Burp Repeater | `GET localhost:8080/api/groups/search?name=%25` | 200 OK: 20 canales (límite), incluido RT-Grupo-G (is_member=false); nombres con payloads SQLi guardados literalmente, sin inyección |
| 2026-11-13 11:01:46 | PoC-02 (reenvío para captura) | Burp Repeater | `GET localhost:8080/api/groups/search?name=direct` | 200 OK, mismo resultado (`poc-02a-search-direct.png`) |
| 2026-11-13 11:07:32 | PoC-03 Enumeración de usuarios (T-11) | Burp Repeater | `POST localhost:8080/api/direct-conversations` {recipient_email: rt.alice@example.com} | 200 OK: devuelve id, nombre, correo y llave pública (el usuario existe) |
| 2026-11-13 11:08:05 | PoC-03 Enumeración de usuarios (T-11) | Burp Repeater | `POST localhost:8080/api/direct-conversations` {recipient_email: noexiste@example.com} | 400 'Contacto no encontrado.' (el usuario no existe): respuesta distinguible |
| 2026-11-13 11:08:51 | PoC-03 (reenvío para captura) | Burp Repeater | `POST localhost:8080/api/direct-conversations` (rt.alice@example.com) | 200 OK, mismo resultado (`poc-03a-enum-existe.png`) |
| 2026-11-13 11:09:19 | PoC-03 (reenvío para captura) | Burp Repeater | `POST localhost:8080/api/direct-conversations` (noexiste@example.com) | 400 'Contacto no encontrado.' (`poc-03b-enum-no-existe.png`) |
| 2026-11-13 14:47:45 | PoC-04 Sin rate limit en código de grupo (T-16) | Burp Intruder (Sniper, 30 payloads) | `POST localhost:8080/api/groups/53efc8a9…/join` | 31 × 400 'Código de grupo incorrecto' en 21 s (fin 14:48:06), ningún 429; la API registró los 31 intentos |
| 2026-11-13 14:52:17 | PoC-05 DoS por inundación de mensajes (T-19) | Burp Repeater | `GET localhost:8080/api/messages/7515e782…` | 403 'No se pudo completar la operacion.'; log de la API: Supabase 'Bad Request' (.in() con ≥1000 IDs) |
| 2026-11-13 14:53:00 | PoC-05 DoS por inundación de mensajes (T-19) | Burp Repeater | `GET localhost:8080/api/groups/36d5ba34…/messages` | 200 OK, 1 277 390 bytes, 1000 mensajes (tope de Supabase) en un canal sin paginación ni límite por miembro |

<!-- Pendiente: filas de la repetición en Postman de cada PoC (hora exacta para el Blue Team). -->