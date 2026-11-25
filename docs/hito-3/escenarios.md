# Escenarios de prueba — Hito 3 y Hito 4

Guía de referencia para la demo. Mapa de todos los escenarios que repite el Red Team.

- **Dónde se ven las alertas:** Kibana → **Security → Alerts** (no en "Rules", que solo muestra las reglas).
- **Ritmo:** atacar → esperar ~1 min (las reglas corren cada minuto) → refrescar Alerts. Filtro de tiempo en "Today".
- **Dashboard:** Kibana → Dashboards → "Cifrados · SIEM (Hito 3)".

---

## H3 — cada ataque en DOS modos del WAF (código actual, sin arreglos)

Cambiar de modo: editar `WAF_MODE` en `.env` y correr
`docker compose --env-file ../.env up -d waf` desde `entorno-blue-team/`.

| # | Ataque | Herramienta | DetectionOnly (detección) | On (bloqueo) | Alerta SIEM |
|---|---|---|---|---|---|
| 1 | CA-01 · SQLi en login | Postman `3 · Demo H3` | 401 (pasa, se registra) | **403** (bloquea) | CIF-01 |
| 2 | CA-02 · XSS en nombre de grupo | Postman `3 · Demo H3` | 400 (validación) | **403** (bloquea) | CIF-02 |
| 3 | CA-08 · escaneo | ZAP (Active Scan corto) | pasa, se registra | 403s | CIF-03, CIF-04, CIF-11 |
| 4 | PoC-01 · `GET /api/users` | Postman `2 · Ataques` | 200 (pasa) | **200 (pasa igual)** | — (sin regla) |
| 5 | PoC-02 · `%` y `direct` | Postman `2 · Ataques` | 200 (revela chats) | **403** (parche virtual 10010) | CIF-05 |
| 6 | PoC-02 · evasión `irect` | Postman `3 · Demo H3` | 200 (revela) | **200 (pasa el WAF)** | CIF-05 (por la API) |
| 7 | PoC-03 · enumeración (×5) | Postman + Runner | 200 vs 400 distinguibles | igual (sin firma) | CIF-07 |
| 8 | PoC-04 · códigos (×8) | Postman + Runner | 400 y 429 | igual | CIF-06, CIF-10 |
| 9 | PoC-05 · inundación | evidencia del H2 | 403 (bandeja rota) | igual | CIF-08 |

**La historia:** el WAF bloquea lo que tiene *firma* (1, 2, 5). Las fallas de *lógica* (4, 6, 7, 8, 9) pasan igual en On; solo el SIEM las detecta. Por eso hace falta el H4.

---

## H4 — cada PoC en DOS estados del código (solo PoC-02 y PoC-04)

Comparar `main` (antes) vs rama `hito-4` (después).

| PoC | Antes (main) | Después (rama hito-4) | Mejor evidencia |
|---|---|---|---|
| **PoC-02** búsqueda | `?name=%25` → 200 lista todo; `?name=direct` → 200 revela chat privado | `%25` → **400** (rechaza comodines); `direct` → **200 pero SIN canales `direct:`** | Postman (muy visual por HTTP) |
| **PoC-04** código de grupo | la API acepta intentos sin límite | la API corta con un **limitador por usuario** (10/15 min) | prueba `src/tests/poc04GroupJoin.test.js` + diff del código |

**Nota PoC-04:** nginx ya tira 429 desde el H3, así que por HTTP el "antes" y el "después" se ven parecidos (429 en ambos). La diferencia real del arreglo está en el **código de la API**; por eso la evidencia clara del "después" es la prueba automatizada, no solo el 429 del navegador.

**No se arreglaron (riesgo residual, y está bien — el mínimo son 2):** PoC-01, PoC-03 y PoC-05.

---

## Orden práctico de grabación

1. **DetectionOnly** → cubre la columna "detección" del H3 **y** el "antes" del H4 en una sola vuelta (mismo estado: el ataque funciona).
2. **On** → cubre la columna "bloqueo" del H3.
3. Otro día, con la rama `hito-4` → el "después" del H4.
