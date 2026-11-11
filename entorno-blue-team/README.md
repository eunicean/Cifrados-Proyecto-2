# Entorno Blue Team

Cifrados-Proyecto-2 detrás de ModSecurity + OWASP CRS, con Elasticsearch, Kibana y Filebeat (Docker Compose).
Reemplaza a OWASP Juice Shop del enunciado (aprobado por el catedrático).

```
Navegador ─► waf :8080 (ModSecurity + CRS) ─► web (nginx: frontend + /api) ─► api (Express :3001) ─► Supabase
               └─ audit log JSON (stdout) ─► filebeat ─► elasticsearch ─► kibana :5601
```

| Servicio | Publicado en | Función |
|---|---|---|
| `waf` | `localhost:8080` | Único punto de entrada. `WAF_MODE=DetectionOnly` u `On` |
| `web` | interno | Sirve el build de Vite y reenvía `/api/*` a la API |
| `api` | interno | `node app.js` |
| `elasticsearch` | `127.0.0.1:9200` | Perfil `siem` |
| `kibana` | `127.0.0.1:5601` | Perfil `siem` (usuario `elastic`) |
| `filebeat` | — | Perfil `siem`; lee los logs de `cifrados-waf` y `cifrados-api` |

## Requisitos

- Docker Desktop encendido (en Windows, con WSL2). Para el perfil `siem`: al menos 4 GB de RAM libres para Docker.
- `.env` en la **raíz del repo** (copiar `.env.example` y completar). Las credenciales de Supabase las tiene el equipo; nunca se suben al repo.

## Levantar

Desde esta carpeta:

```bash
# Hito de Configuración: app + WAF
docker compose --env-file ../.env up -d --build

# Hito 3: app + WAF + SIEM
docker compose --env-file ../.env --profile siem up -d --build
```

## Verificar (criterio del hito de Configuración)

```bash
# 1. La app responde a través del WAF
curl -i http://localhost:8080/            # 200 y el HTML de la app
curl -i http://localhost:8080/api/groups  # 401 (requiere JWT): la API responde detrás del WAF

# 2. El WAF ve un ataque (en DetectionOnly responde igual, pero lo registra)
curl -i "http://localhost:8080/?q=1'%20OR%20'1'='1"
docker logs cifrados-waf 2>&1 | grep -i '"ruleId"' | tail -n 3

# 3. Con WAF_MODE=On en ../.env y `docker compose --env-file ../.env up -d waf`, el paso 2 devuelve 403
```

Abrir `http://localhost:8080` en el navegador, registrarse e iniciar sesión para confirmar que el flujo completo funciona.

## Notas

- Todo el tráfico del navegador pasa por la API (`src/utils/api.js` y `src/auth/registerUser.js` usan Supabase directo, pero no se importan en ningún lado). Aun así, verificar que RLS esté activo en Supabase (ver amenaza T-24 en `docs/hito-1`).
- Si Elastic no corre en la laptop: usar Elastic Cloud y cambiar `output.elasticsearch` en `filebeat/filebeat.yml` por `cloud.id` y `cloud.auth`.
- Falsos positivos del WAF: agregar exclusiones mínimas en `waf/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf` y documentarlas en `docs/hito-3`.
- Reglas de enfrentamiento: solo se ataca `localhost:8080`. No atacar el despliegue en Render ni el proyecto de Supabase directamente.
