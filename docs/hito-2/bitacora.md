# Bitácora de ataques · Hito 2 (Red Team)

WAF: `MODSEC_RULE_ENGINE=DetectionOnly` · Destino: `http://localhost:8080` · Zona horaria: America/Guatemala (UTC-6)

| Fecha y hora | Hallazgo | Herramienta | Destino | Resultado |
|---|---|---|---|---|
| 2026-11-12 19:39:21 | Verificación de bypass | curl | `localhost:3001/groups` (puerto directo de la API) | 000, sin respuesta: la API no está publicada, sin bypass |
| 2026-11-12 19:39:21 | Verificación de la cadena | curl | `localhost:8080/login` y `/api/groups` | 200 y 401: app y API responden detrás del WAF |
| 2026-11-12 19:38:00 | Verificación del WAF (DetectionOnly) | curl | `localhost:8080/?q=1' OR '1'='1` | 200; el WAF registra las reglas 942100 (SQLi) y 949110 (umbral de anomalía) sin bloquear |
| 2026-11-12 21:34:00 | Reconocimiento: Spider | ZAP 2.17.0 (Spider, Protected Mode, JWT de Carol) | `localhost:8080` | 49 URLs encontradas, 14 nodos; URLs de terceros fuera de contexto, no visitadas (fin ~21:35) |
| 2026-11-12 21:39:37 | Reconocimiento: AJAX Spider | ZAP 2.17.0 (AJAX Spider) | `localhost:8080` | 4 URLs (SPA sin sesión redirige a /login); peticiones de terceros bloqueadas por Protected Mode; detenido 21:52 |
| 2026-11-12 21:54:00 | Escaneo activo | ZAP 2.17.0 (Active Scan, Default Policy, JWT de Carol) | `localhost:8080` (todo el sitio) | 6475 peticiones, fin 22:20; 0 High, 4 Medium, 1 Low, 5 Info |
| 2026-11-12 22:44:00 | Verificación de autenticación del escaneo | docker logs | `cifrados-api` | 16 423 líneas de log con el ID de Carol (7515e782…) entre 21:54 y 22:20: el Active Scan corrió autenticado |
