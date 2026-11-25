# Hito 3 · Guion de la demo en vivo (detección y bloqueo)

**Proyecto final — Desarrollo Seguro, UVG, ciclo 2 2026** · Aplicación: Cifrados-Proyecto-2 (sustituye a OWASP Juice Shop, con aprobación del catedrático)

| Rol | Integrantes |
|---|---|
| Blue Team | Eunice Mata, Silvia Illescas |
| Red Team | Michelle Mejía, Esteban Zambrano |

La rúbrica del H3 pide: *«las reglas detectan los ataques reales del Red Team (evidencia con horas y payloads); WAF en bloqueo con falsos positivos analizados; demo en vivo funcional»*. Este guion deja listo ese paso: qué se lanza, en qué orden, quién hace cada cosa y qué se espera ver. La tabla de resultados (abajo) se llena **durante** la demo con las horas reales de Guatemala.

---

## 1. Reparto de roles

| Quién | Qué hace |
|---|---|
| **Red Team (Michelle / Esteban)** | Lanza cada ataque y dice en voz alta la **hora exacta** del envío. Herramientas: Postman (colección `docs/hito-2/postman/`), Burp para las ráfagas y ZAP para el escaneo. |
| **Blue Team (Eunice / Silvia)** | Con Kibana abierto en **Security → Alerts** y el dashboard «Cifrados · SIEM (Hito 3)». Por cada ataque muestra la alerta CIF-xx y, en modo On, el 403 del WAF. Completa la columna «Alerta SIEM» y «Respuesta». |
| **Todo el grupo** | Graba la pantalla (respaldo para la presentación final) y narra qué capa detecta cada ataque: WAF (firma) vs. API (lógica). |

---

## 2. Preparación (antes de empezar a grabar)

```powershell
# 1. Levantar el entorno con el SIEM, en DetectionOnly (valor por defecto del .env)
cd entorno-blue-team
docker compose --env-file ../.env --profile siem up -d --build

# 2. Verificar los 7 contenedores y que la app responde por el WAF
docker compose --env-file ../.env --profile siem ps
curl.exe -s -o NUL -w "%{http_code}`n" http://localhost:8080/            # 200
curl.exe -s -o NUL -w "%{http_code}`n" http://localhost:8080/api/groups  # 401
```

- En Kibana (`http://localhost:5601`): abrir **Security → Rules** y confirmar que las 11 reglas CIF están **enabled** (si no, correr `node scripts/blue-team/kibana-setup.mjs`). Bajar el intervalo de refresco de Alerts a 10 s.
- En Postman: seleccionar el environment **Cifrados-WAF**, poner `carol_password` (no se versiona) y correr **`1 · Sesión → Login Carol`** para cargar el `token`.
- **Datos previos que deben existir** (de la bitácora del H2, no borrarlos):
  - El canal **RT-Carol** (`group_flood_id`) inundado con ~1000 mensajes → evidencia del PoC-05.
  - El grupo privado **RT-Grupo-G** (`group_g_id`) → objetivo del PoC-04.

> Nota de tiempos: las reglas CIF miran una ventana corta (`now-2m` a `now-5m`). Dejar unos segundos entre un ataque y la captura de su alerta, y no mezclar las dos rondas: reiniciar el reloj mental al cambiar de modo.

---

## 3. Ronda 1 — WAF en DetectionOnly

Objetivo: demostrar **detección** (el SIEM ve todo aunque el WAF deje pasar). El WAF ya está en `DetectionOnly`.

Orden sugerido (de firma a lógica):

| # | Ataque | Cómo se lanza | Se espera (DetectionOnly) | Alerta SIEM |
|---|---|---|---|---|
| 1 | **CA-01 · SQLi en login** | Postman `3 · Demo H3 → CA-01` | `401` (credenciales inválidas), el WAF lo **registra** | CIF-01 |
| 2 | **CA-02 · XSS en nombre de grupo** | Postman `3 · Demo H3 → CA-02` | `400` (validación del nombre), el WAF lo **registra** | CIF-02 |
| 3 | **CA-08 · Escaneo** | ZAP Active Scan corto sobre `http://localhost:8080` (Protected Mode) | muchos `200/404`, el WAF registra 913xxx y 942xxx | CIF-03, CIF-04, CIF-11 |
| 4 | **PoC-01 · Directorio de usuarios** | Postman `2 · Ataques → PoC-01` | `200` con todos los correos | *(ninguna — ver nota)* |
| 5 | **PoC-02 · Comodín** | Postman `2 · Ataques → PoC-02b` (`name=%25`) | `200` con canales privados | CIF-05 (por la API) |
| 6 | **PoC-02 · Evasión** | Postman `3 · Demo H3 → PoC-02 evasion` (`name=irect`) | `200`, pasa sin firma | CIF-05 (por la API) |
| 7 | **PoC-03 · Enumeración** | Postman `2 · Ataques → PoC-03a/03b`, repetir 03b con el Runner (≥5 iteraciones) | `200` vs `400` distinguibles | CIF-07 (umbral ≥5) |
| 8 | **PoC-04 · Fuerza bruta de código** | Burp Intruder o Postman `PoC-04` con el Runner (≥6 iteraciones) | `400` y, desde el 7.º, `429` de nginx | CIF-06 y CIF-10 |
| 9 | **PoC-05 · Inundación** | Postman `2 · Ataques → PoC-05a/05b` (la inundación ya está hecha) | `403` en la bandeja, `200` con 1000 mensajes en el canal | CIF-08 |

**Nota PoC-01:** no tiene regla a propósito. El frontend llama a `GET /users` cada 30 s, así que el SIEM no puede distinguir el abuso del uso normal. Se documenta como hueco que **se corrige en el código en el H4**. Decirlo en voz alta: es un punto a favor, muestra criterio.

---

## 4. Cambio a modo On

```powershell
# En ../.env  ->  WAF_MODE=On   (paranoia se queda en 1, el nivel elegido en el H3)
cd entorno-blue-team
docker compose --env-file ../.env up -d waf   # recrea solo el WAF
```

Verificación rápida del bloqueo:

```powershell
curl.exe -s -o NUL -w "%{http_code}`n" "http://localhost:8080/?q=1' OR '1'='1"   # 403
```

---

## 5. Ronda 2 — WAF en On

Objetivo: demostrar **bloqueo** de lo que tiene firma y **detección** de lo que no.

| # | Ataque | Se espera (On) | Regla WAF | Alerta SIEM |
|---|---|---|---|---|
| 1 | CA-01 · SQLi | **403** | 942100 (CRS) | CIF-01 |
| 2 | CA-02 · XSS | **403** | 941xxx (CRS) | CIF-02 |
| 3 | PoC-02 · comodín `%25` | **403** | 10010 (parche virtual) | CIF-05 |
| 4 | PoC-02 · evasión `irect` | **200** (pasa el WAF) | — | CIF-05 (por la API) |
| 5 | PoC-04 · fuerza bruta | `400` y `429` desde el 7.º intento | — (contención en nginx) | CIF-06, CIF-10 |
| 6 | PoC-05 · inundación | `429` al pasar de 60/min POST | — (contención en nginx) | CIF-08 (enviar a ~1/seg) |

**⚠ Cuidado con el PoC-05 en la demo.** `nginx.conf` limita `/api/messages` a **60/min con burst 20**. Si se mandan mensajes de golpe, desde el ~21 llega `429` y no se alcanzan los **30** `message_created` que dispara CIF-08. Para la demo, enviar a **~1 por segundo** (Runner con *delay* de 1000 ms) para que CIF-08 dispare; los `429` extra alimentan CIF-10. Mejor aún: mostrar la evidencia ya registrada del H2 y lanzar solo una ráfaga corta.

**Prueba de uso legítimo en On** (responde la pregunta abierta del PDF): en el navegador, con el WAF en On, hacer el flujo completo —registro con contraseña `Prueba'2026--ok`, login, búsqueda de un grupo por su nombre normal, enviar un mensaje de grupo y uno directo— y confirmar que **todo funciona sin 403** (las exclusiones 10110/10120 ya están cargadas). Es la prueba de que el bloqueo no rompe la app.

---

## 6. Tabla de resultados (llenar en vivo, horas de Guatemala)

| Hora | Ataque | Payload | Modo WAF | Respuesta | Regla WAF | Alerta SIEM |
|---|---|---|---|---|---|---|
|  | CA-01 · SQLi en login | `email: admin@x.com' OR '1'='1` | On |  |  | CIF-01 |
|  | CA-02 · XSS en nombre de grupo | `name: <img src=x onerror=…>` | On |  |  | CIF-02 |
|  | CA-08 · escaneo | ZAP Active Scan | On |  |  | CIF-03, CIF-04, CIF-11 |
|  | PoC-01 · directorio de usuarios | `GET /api/users` | On |  | — | — |
|  | PoC-02 · comodín | `?name=%25` | On |  | 10010 | CIF-05 |
|  | PoC-02 · evasión | `?name=irect` | On |  | — | CIF-05 |
|  | PoC-03 · enumeración | ≥5 correos inexistentes | On |  | — | CIF-07 |
|  | PoC-04 · código de grupo | ≥7 códigos seguidos | On |  | — (429 nginx) | CIF-06, CIF-10 |
|  | PoC-05 · inundación | ráfaga de mensajes | On |  | — (429 nginx) | CIF-08 |
|  | Uso legítimo | login + búsqueda + msg grupo + msg directo | On | 200 (sin 403) | — | — |

Guardar junto a esta tabla las capturas de Security → Alerts y del dashboard para cada fila. Estas horas y respuestas alimentan después las columnas «¿Lo detectó el SIEM?» y «¿Lo bloqueó el WAF?» de la matriz de trazabilidad del informe final, y son el estado **«antes»** de la re-prueba del H4.

---

## 7. Resumen de mapeo ataque → detección → bloqueo

| Capa que lo frena | Ataques |
|---|---|
| **WAF bloquea (firma CRS)** | CA-01 (SQLi), CA-02 (XSS) |
| **WAF bloquea (parche virtual)** | PoC-02 con `%` (regla 10010) |
| **nginx contiene (rate limit)** | PoC-04 (429 en join), PoC-05 (429 en messages) |
| **Solo el SIEM detecta (lógica, sin firma)** | PoC-02 evasión, PoC-03, y las ráfagas por umbral |
| **Ni WAF ni SIEM — se corrige en el código (H4)** | PoC-01 |

Esa última fila es el puente natural hacia el H4: lo que ni el WAF ni el SIEM pueden resolver se arregla en el código.

---

## Uso de IA

Guion preparado con apoyo de Claude (Anthropic) a partir de los entregables del H2 y H3 del repositorio. El Red Team ejecuta cada ataque contra `localhost:8080` y el grupo valida cada detección y bloqueo en vivo.
