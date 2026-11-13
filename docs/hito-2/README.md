# Hito 2 · Pipeline DevSecOps y ataque del Red Team

**Proyecto final — Desarrollo Seguro, UVG, ciclo 2 2026** · Aplicación: Cifrados-Proyecto-2 (sustituye a OWASP Juice Shop, con aprobación del catedrático)

| Rol | Integrantes |
|---|---|
| Blue Team | Eunice Mata, Silvia Illescas |
| Red Team | Michelle Mejía, Esteban Zambrano |

El pipeline es responsabilidad de todo el grupo; el ataque, del Red Team.

## Contenido de esta carpeta

| Entregable | Ubicación |
|---|---|
| Workflow de GitHub Actions | [`/.github/workflows/devsecops.yml`](../../.github/workflows/devsecops.yml) |
| SBOM (CycloneDX, Syft) | [`sbom.cdx.json`](sbom.cdx.json) (también como artefacto `sbom.cdx.json` de cada corrida) |
| Reportes del pipeline | [`pipeline/`](pipeline/): `semgrep/` (SARIF y JSON), `sca/` (npm audit), `zap/` (ZAP baseline y log del WAF) |
| Reporte de ZAP de escritorio | [`zap-desktop/`](zap-desktop/): HTML y JSON |
| Capturas de Burp por PoC | [`burp/`](burp/) |
| Fichas de los PoC clasificados | [`pocs.md`](pocs.md) |
| Bitácora de ataques (fecha, hora, herramienta, destino, resultado) | [`bitacora.md`](bitacora.md) |
| Colección y environment de Postman | [`postman/`](postman/) |

---

## 1. Pipeline DevSecOps

Basado en la plantilla del curso (`plantilla-pipeline/devsecops.yml`) y en el workflow adaptado de Secure CRM. Se ajustó a este repositorio: lockfile **npm** y la app levantada con `entorno-blue-team/docker-compose.yml`. Corre en cada `push`, `pull_request` y a mano (`workflow_dispatch`), con cuatro jobs en paralelo:

| Job | Control | Herramienta | Alcance | Umbral del gate |
|---|---|---|---|---|
| `sast` | SAST | Semgrep (`p/default`, `p/owasp-top-ten`, `p/javascript`, `p/nodejs`, `p/secrets`) | Código fuente, sin `docs/`, `src/tests/` ni `dist/` | Hallazgos de severidad **ERROR** |
| `sca` | SCA | `npm audit` (reporte completo y de producción) | Dependencias de `package-lock.json` | **High o critical en dependencias de producción** |
| `sbom` | SBOM | Syft (`anchore/sbom-action`), CycloneDX JSON | Repositorio completo | — (se publica como artefacto) |
| `dast` | DAST | ZAP baseline (`zap-baseline.py`) | `http://localhost:8080/login` **a través del WAF** (DetectionOnly) | Alertas de riesgo **High** |

### Decisiones de diseño

- **DAST a través del WAF.** El job levanta `api`, `web` y `waf` con el mismo compose del entorno Blue Team y escanea `:8080`, el camino real de producción. Se escanea `/login` porque `/` redirige con JavaScript.
- **Sin secretos en CI.** El job crea un `.env` efímero con valores ficticios de Supabase y un `JWT_SECRET` aleatorio por corrida (`openssl rand`). La API arranca, pero no toca la base de datos real. El baseline es pasivo, así que no necesita datos.
- **Cadena de suministro.** Todas las *actions* están fijadas a su **SHA de commit** (con la versión en comentario). El propio Semgrep lo exigía: la regla `github-actions-mutable-action-tag` bajó de 9 hallazgos a 0 (commit `ci: pin GitHub Actions to commit SHAs…`).
- **Permisos mínimos:** `permissions: contents: read`.

### Security gate

El workflow arranca en **`SECURITY_GATE: "reporte"`**: corre todos los controles y publica los reportes, pero los pasos de gate usan `continue-on-error`. Pasar a `"bloqueo"` solo exige cambiar esa variable.

**Justificación de los umbrales** (propuesta del Red Team, pendiente de confirmación del Blue Team):

- **SAST, ERROR:** las reglas `ERROR` de Semgrep son de alta confianza (inyección, secretos, criptografía rota). Los `WARNING` actuales incluyen falsos positivos comprobados (CORS con lista blanca), así que bloquear por ellos frenaría el pipeline sin aportar seguridad. Se revisan a mano.
- **SCA, high/critical en producción:** solo las dependencias de producción viajan en la imagen `api` y son alcanzables por un atacante. Las de desarrollo (Vite, Vitest) se usan en build y pruebas, quedan en el reporte completo y no bloquean.
- **DAST, High:** las alertas Medium y Low del baseline son de encabezados (CSP, COOP, COEP). Se corrigen en configuración y van a la matriz, pero no justifican detener un despliegue.

### Resultados (corrida 43090297012, rama `hito-2`)

| Control | Resultado | Gate |
|---|---|---|
| SAST | 0 ERROR · 2 WARNING (`cors-misconfiguration` en `app.js:92`, **falso positivo**: solo refleja orígenes de la lista blanca; `request-host-used` en `nginx.conf:26`, riesgo bajo detrás del WAF) · 4 INFO (`unsafe-formatstring` en `console.log` con valores internos, falsos positivos) | ✅ pasa |
| SCA | Producción: **1 high** (`body-parser` 2.3.0, GHSA-27r3-jxmh-p828, DoS por bytes tras un cuerpo comprimido, `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`) y 1 moderate (`ip-address`). Completo: 2 high, 4 moderate | ❌ falla (en modo reporte) |
| SBOM | `sbom.cdx.json` generado | — |
| DAST | 0 High · 1 Medium (`CSP: style-src 'unsafe-inline'`) · 3 Low (faltan COEP, COOP y Permissions-Policy) · Info | ✅ pasa |

El fallo de SCA queda como **fila de la matriz de trazabilidad** (detectado por el pipeline) y se corrige en el H4, actualizando `body-parser` a través de Express. Con eso el gate puede pasar a `bloqueo`.

---

## 2. Ataque del Red Team

### Reglas de enfrentamiento cumplidas

- Destino único: `http://localhost:8080`, con el WAF en **DetectionOnly**. No se atacó el despliegue de Render, Supabase directamente ni sistemas de terceros. ZAP trabajó en **Protected Mode**, con el contexto limitado a `http://localhost:8080.*`, y bloqueó el tráfico propio del navegador hacia dominios de Microsoft.
- Solo cuentas de prueba (`rt.*@example.com`); las capturas tienen el JWT tapado.
- Cada envío está en [`bitacora.md`](bitacora.md) con fecha, hora, herramienta, destino y resultado.
- **Bypass:** la API (`:3001`) y nginx (`:80`) no publican puertos. `curl` y Postman contra `localhost:3001` no obtienen respuesta. **No hay forma de saltarse el WAF.**

### Método

1. **ZAP de escritorio** (12-nov, 21:34–22:20), autenticado como Carol: Spider (49 URLs), AJAX Spider (4 URLs; la SPA sin sesión redirige a `/login`) y **Active Scan** (6475 peticiones). Resultado: 0 High, 4 Medium (CSP), 1 Low (*XSS Weakness in JSON*: campos del mensaje sin validar) y 5 Info. El WAF registró 3976 eventos `949110`, que en modo On habrían sido `403`.
2. **Burp Suite** (13-nov): confirmación manual en Repeater y en Intruder de las amenazas del H1 que ZAP no puede ver, porque son fallas de lógica y de autorización.
3. **Postman** (13-nov, 15:40:56–15:41:01): repetición de cada PoC con la colección [`postman/`](postman/), **9/9 tests aprobados**. Las horas son las que el Blue Team busca en Kibana.

### PoC confirmados

Detalle, reproducción y justificación del CVSS métrica por métrica en [`pocs.md`](pocs.md).

| PoC | Hallazgo | OWASP 2025 | CWE | CVSS v3.1 |
|---|---|---|---|---|
| 01 | `GET /api/users` lista nombre, correo y llave de todos los usuarios | A01 Broken Access Control | CWE-359 | 4.3 |
| 02 | La búsqueda de grupos revela chats privados (`direct:`) y acepta el comodín `%` | A01 Broken Access Control | CWE-200 / CWE-155 | 4.3 |
| 03 | Enumeración de usuarios por respuesta distinguible en `/direct-conversations` | A07 Authentication Failures | CWE-204 | 4.3 |
| 04 | Sin límite de intentos para el código de `/groups/:id/join` | A07 Authentication Failures | CWE-307 | 5.9 |
| 05 | DoS persistente: inundar un canal rompe `GET /messages/:userId` de sus miembros | A06 Insecure Design | CWE-770 / CWE-755 | 6.5 |

**Resultados negativos** (los controles funcionan): no hubo SQLi (los payloads se guardaron como texto literal), no hubo XSS ejecutable (React escapa la salida) y no hay bypass del WAF.

### Notas para el Blue Team (Hito 3)

- Los PoC 01 a 05 son **fallas de lógica sin firma de ataque**: el CRS no las marcará. Las reglas de Kibana tienen que apoyarse en los **logs de la API** (`app_component: api`): búsquedas con `%` o `direct`, ráfagas de "Codigo de grupo incorrecto" por usuario o IP, y volumen de `POST /messages` por usuario.
- El escaneo de ZAP sí deja firmas del CRS (942xxx SQLi, 932xxx RCE, 930120 LFI y 913xxx escáner), útiles para la regla de escaneo por IP.
- La imagen del WAF trae `CORS_HEADER_403_ALLOW_ORIGIN=*` y `CORS_HEADER_ACCESS_CONTROL_ALLOW_HEADERS=*` por defecto. Conviene ajustarlas al pasar a modo On.
- El canal `RT-Carol` quedó inundado con al menos 1000 mensajes del Active Scan. Es la evidencia del PoC-05; no borrarlo hasta la re-prueba del H4.

---

## 3. Uso de IA

Según la guía de la UVG: se usó **Claude (Anthropic)** como asistente para guiar los pasos del pipeline y del ataque, apoyar la redacción de la documentación y preparar la evidencia (por ejemplo, ocultar el JWT en las capturas). Las pruebas las ejecutó el Red Team contra `localhost:8080`, y el grupo revisó y validó el workflow, los resultados y la clasificación de cada PoC.