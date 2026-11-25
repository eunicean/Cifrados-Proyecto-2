# Comandos para la demo (a la mano)

RAIZ = `C:\Users\Michelle Mejia\Desktop\U\Desarrollo Seguro\Cifrados-Proyecto-2`

## Qué es cada rama
- **`main`**  = código viejo (vulnerable) = **ANTES**
- **`hito-4`** = código corregido = **DESPUÉS** (incluye arreglos de PoC-01, 02 y 04)

> Regla de oro: **cada vez que cambies de rama, recompilá** (paso 2) para que el
> contenedor tome el código nuevo. El `.env` no se toca al cambiar de rama.

---

## 1A · Cambiar al código VIEJO (ANTES → rama main)
```powershell
cd "C:\Users\Michelle Mejia\Desktop\U\Desarrollo Seguro\Cifrados-Proyecto-2"; git switch main
```

## 1B · Cambiar al código NUEVO (DESPUÉS → rama hito-4)
```powershell
cd "C:\Users\Michelle Mejia\Desktop\U\Desarrollo Seguro\Cifrados-Proyecto-2"; git switch hito-4
```

## Ver en qué rama estoy
```powershell
cd "C:\Users\Michelle Mejia\Desktop\U\Desarrollo Seguro\Cifrados-Proyecto-2"; git branch --show-current
```

---

## 2 · Recompilar y levantar TODO (hacer SIEMPRE después de cambiar de rama)
```powershell
cd "C:\Users\Michelle Mejia\Desktop\U\Desarrollo Seguro\Cifrados-Proyecto-2\entorno-blue-team"; docker compose --env-file ../.env --profile siem up -d --build
```

## 3 · Verificar que arrancó
```powershell
docker ps --format "table {{.Names}}`t{{.Status}}"
```
```powershell
curl.exe -s -o NUL -w "%{http_code}`n" http://localhost:8080/api/groups
```
`cifrados-api` en `Up` y el curl en `401` = listo.

---

## 4 · Cambiar el modo del WAF
En el `.env`, editá la línea `WAF_MODE`:
- `WAF_MODE=DetectionOnly` → el WAF solo registra (para mostrar DETECCIÓN y el "antes")
- `WAF_MODE=On` → el WAF bloquea con 403 (para mostrar BLOQUEO)

Después de cambiarla, recreá solo el WAF:
```powershell
cd "C:\Users\Michelle Mejia\Desktop\U\Desarrollo Seguro\Cifrados-Proyecto-2\entorno-blue-team"; docker compose --env-file ../.env up -d waf
```

Prueba rápida de bloqueo (en On debería dar 403):
```powershell
curl.exe -s -o NUL -w "%{http_code}`n" "http://localhost:8080/?q=1' OR '1'='1"
```

---

## 5 · Logs en vivo (para que se vea el ataque llegar)
```powershell
docker logs -f cifrados-waf
```
```powershell
docker logs -f cifrados-api
```

## 6 · Recargar reglas y dashboard de Kibana (solo si hiciera falta)
Reemplazá el valor por la `ELASTIC_PASSWORD` del `.env`:
```powershell
cd "C:\Users\Michelle Mejia\Desktop\U\Desarrollo Seguro\Cifrados-Proyecto-2"; $env:ELASTIC_PASSWORD="pegá-aquí-el-valor"; node scripts/blue-team/kibana-setup.mjs
```
Kibana: http://localhost:5601 (usuario `elastic`). Alertas en **Security → Alerts**.

---

## Guion de grabación (orden sugerido)
1. Rama **main** + recompilar + WAF **DetectionOnly** → grabar "ANTES": los ataques funcionan, Kibana detecta.
2. Mismo estado, WAF **On** → grabar "BLOQUEO": las firmas (SQLi, XSS, `%`) dan 403.
3. Rama **hito-4** + recompilar + WAF **DetectionOnly** → grabar "DESPUÉS": PoC-01, 02 y 04 ya no funcionan.

Detalle de qué esperar en cada paso: ver `docs/hito-3/escenarios.md`.
