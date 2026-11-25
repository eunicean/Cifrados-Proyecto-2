# Cifrados-Proyecto-2 — Proyecto Final de Desarrollo Seguro (SSDLC)

Aplicación de mensajería cifrada trabajada a lo largo de todo el ciclo de vida de desarrollo seguro: modelado de amenazas, pipeline DevSecOps, ataque del Red Team, detección y defensa del Blue Team, y remediación asistida por IA.

> **Universidad del Valle de Guatemala · Desarrollo Seguro · Ciclo 2, 2026.**
> Esta aplicación (Cifrados-Proyecto-2) sustituye a OWASP Juice Shop del enunciado, con aprobación del catedrático.

## Equipo y roles

| Rol | Integrantes |
|---|---|
| Blue Team | Eunice Mata, Silvia Illescas |
| Red Team | Michelle Mejía, Esteban Zambrano |

El pipeline, la auditoría de IA y el informe son responsabilidad de todo el grupo.

## La aplicación

Cifrados es una app web de mensajería grupal y directa con **cifrado de extremo a extremo**:

- El navegador cifra cada mensaje con **AES-256-GCM**; la clave AES se cifra para cada destinatario con **RSA-OAEP**.
- El servidor solo almacena **texto cifrado**: ni la API ni la base de datos pueden leer los mensajes.
- Cada mensaje se registra en una **cadena de bloques** encadenada por hash SHA-256 para detectar alteraciones.

**Tecnologías:** React 19 + Vite 8 (frontend), Node 22 + Express 5 (API), Supabase/PostgreSQL (datos), JWT HS256 y bcrypt (autenticación). El entorno de laboratorio corre detrás de **ModSecurity + OWASP CRS** (WAF) con **Elasticsearch, Kibana y Filebeat** (SIEM) vía Docker Compose.

## El ciclo de trabajo (los hitos)

| Hito | Contenido | Entregable |
|---|---|---|
| **H1 · Diseño seguro** | Modelado de amenazas con PASTA (etapas 1–4) y STRIDE; DFD con límites de confianza; requisitos y casos de abuso | [`docs/hito-1/HITO1.md`](docs/hito-1/HITO1.md) |
| **H2 · Pipeline y ataque** | Pipeline DevSecOps (SAST, SCA, SBOM, DAST) y 5 PoC del Red Team clasificados (OWASP 2025 / CWE / CVSS) | [`docs/hito-2/`](docs/hito-2/) · [`pocs.md`](docs/hito-2/pocs.md) · [workflow](.github/workflows/devsecops.yml) |
| **H3 · Detección y respuesta** | WAF (DetectionOnly → On), SIEM con 11 reglas y dashboard, falsos positivos documentados | [`docs/hito-3/`](docs/hito-3/) · [`entorno-blue-team/`](entorno-blue-team/) |
| **H4 · Remediación con IA** | 3 vulnerabilidades corregidas en el código (PoC-01, PoC-02, PoC-04), con pruebas de regresión y auditoría de lo generado por IA | [`docs/hito-4/`](docs/hito-4/) |
| **Informe final** | Consolida H1–H4, con la matriz de trazabilidad y el riesgo residual (PASTA etapa 7) | `Proyecto final.pdf` · [`docs/matriz-trazabilidad.md`](docs/matriz-trazabilidad.md) |

## Cómo levantar el entorno

Requisitos: Docker Desktop (con WSL2 en Windows) y un `.env` en la raíz (copiar de [`.env.example`](.env.example) y completar con las credenciales de Supabase del equipo). Para el SIEM: al menos 4 GB de RAM para Docker.

```bash
# App + WAF + SIEM
cd entorno-blue-team
docker compose --env-file ../.env --profile siem up -d --build
```

- App a través del WAF: http://localhost:8080
- Kibana (perfil `siem`): http://localhost:5601
- Cargar reglas y dashboard del SIEM: `node scripts/blue-team/kibana-setup.mjs`

Detalle en [`entorno-blue-team/README.md`](entorno-blue-team/README.md).

## Pipeline DevSecOps

GitHub Actions ([`.github/workflows/devsecops.yml`](.github/workflows/devsecops.yml)) corre en cada push con cuatro controles:

| Control | Herramienta | Umbral del gate |
|---|---|---|
| SAST | Semgrep | Hallazgos de severidad ERROR |
| SCA | `npm audit` | High/critical en dependencias de producción |
| SBOM | Syft (CycloneDX) | — (artefacto) |
| DAST | ZAP baseline (a través del WAF) | Alertas de riesgo High |

Arranca en modo `reporte` (publica todo sin frenar) y puede pasar a `bloqueo` cambiando la variable `SECURITY_GATE`.

## Pruebas

```bash
npm install
npm run test:run                 # suite completa (Vitest)
npm run test:run -- poc01Users   # re-prueba PoC-01
npm run test:run -- poc02GroupSearch
npm run test:run -- poc04GroupJoin
```

## Estructura del repositorio

```
app.js                    API Express
src/                      frontend (React) + criptografía + pruebas
entorno-blue-team/        Docker Compose: WAF + nginx + API + SIEM
scripts/blue-team/        carga de reglas/dashboard de Kibana y análisis de falsos positivos
.github/workflows/        pipeline DevSecOps
docs/hito-1..hito-4/      entregables por hito
docs/matriz-trazabilidad.md
```

## Uso de IA

Según la guía de la UVG, se usó **Claude (Anthropic)** como asistente para el análisis del código, el diseño del pipeline, la redacción de la documentación, la clasificación de los hallazgos y las correcciones del Hito 4. El equipo revisó y validó cada amenaza, PoC, regla y corrección contra el código fuente.
