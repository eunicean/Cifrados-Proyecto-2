# Matriz de trazabilidad — Proyecto Final

**Aplicación:** Cifrados-Proyecto-2 · **Desarrollo Seguro, UVG, ciclo 2 2026**

Una fila por vulnerabilidad encontrada por el Red Team. Une todas las piezas del proyecto: el hallazgo y su clasificación (OWASP 2025 / CWE / CVSS v3.1), quién lo detecta (pipeline del Hito 2 y SIEM del Hito 3), si el WAF lo bloquea, la corrección en el código (Hito 4) y la re-prueba.

| Hallazgo | OWASP / CWE | CVSS v3.1 | ¿Lo detectó el pipeline? | ¿Lo detectó el SIEM? | ¿Lo bloqueó el WAF? | Corrección (Hito 4) | Re-prueba |
|---|---|---|---|---|---|---|---|
| **PoC-01** · `GET /api/users` expone el correo de todas las cuentas | A01 / CWE-359 | 4.3 | No (falla de lógica) | No (sin regla; el uso normal es indistinguible) | No | **Sí, código:** solo devuelve usuarios con un canal compartido | PoC falla · `poc01Users.test.js` 3/3 |
| **PoC-02** · La búsqueda de grupos revela chats privados | A01 / CWE-200 (+CWE-155) | 4.3 | No | **Sí, CIF-05** | **Sí, regla 10010 (modo On)** | **Sí, código:** lista blanca, escape de comodines y exclusión de `direct:` | PoC falla · `poc02GroupSearch.test.js` 9/9 |
| **PoC-03** · Enumeración de usuarios por correo | A07 / CWE-204 | 4.3 | No | **Sí, CIF-07** | No | No — **riesgo residual** | — |
| **PoC-04** · Sin límite de intentos para el código de grupo | A07 / CWE-307 | 5.9 | No | **Sí, CIF-06** | nginx 429 (contención) | **Sí, código:** limitador por usuario (10 fallos / 15 min) | PoC falla · `poc04GroupJoin.test.js` 4/4 |
| **PoC-05** · DoS persistente por inundación de mensajes | A06 / CWE-770 (+CWE-755) | 6.5 | No | **Sí, CIF-08** | nginx 429 (parcial) | No — **riesgo residual** | — |
| **`body-parser` vulnerable** (dependencia) | A03 / CWE-400 | — | **Sí, `npm audit` (SCA)** | No | No | Propuesta: actualizar vía Express | — |

## Cómo leer la matriz

- **El WAF bloquea lo que tiene *firma*** (SQLi, XSS) y lo que cubre un parche virtual propio (PoC-02, regla 10010).
- **El SIEM detecta las fallas de *lógica*** por comportamiento (PoC-02 a PoC-05), porque el CRS no tiene firma para ellas.
- **Lo que ni el WAF ni el SIEM resuelven se corrige en el *código*** (PoC-01, PoC-02 y PoC-04), que es la corrección de fondo del Hito 4.

## Riesgo residual (PASTA · etapa 7)

Qué sigue expuesto y por qué se aceptó:

- **PoC-03 (enumeración)** y **PoC-05 (DoS)**: el SIEM los detecta pero no se corrigieron en el código; se documentan como riesgo residual porque el mínimo del hito eran 2 correcciones y se priorizaron las de mayor impacto en privacidad (PoC-01, PoC-02) y autenticación (PoC-04).
- **Acceso directo a Supabase (amenaza T-24, RLS en `blockchain_blocks`)**: queda fuera del alcance por las reglas de enfrentamiento (solo se ataca `localhost:8080`, no la base de datos directamente).
- **`body-parser`**: detectado por el pipeline; la corrección (actualizar la dependencia) permite pasar el *security gate* de "reporte" a "bloqueo".
