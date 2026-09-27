# OWASP API Security Top 10 (2023) — detección y payloads

Catálogo de referencia para profundizar en cada categoría al construir la matriz de casos de prueba. Cada sección tiene: cómo detectar que la categoría aplica, payloads/manipulaciones concretas, y qué respuesta cuenta como "seguro" vs. "vulnerable".

## API1:2023 — Broken Object Level Authorization (BOLA / IDOR)

**Aplica cuando:** el endpoint recibe un identificador de objeto (numérico, UUID, slug) en la ruta, query string o body, y ese objeto pertenece a un usuario/tenant específico.

**Cómo probar:**
- Autenticarse como usuario A, obtener el ID de un recurso propio, luego solicitar el mismo recurso reemplazando el ID por el de usuario B.
- Probar IDs secuenciales cercanos (`id-1`, `id+1`) si son numéricos.
- Probar el mismo ataque en verbos de escritura (PUT/PATCH/DELETE), no solo GET — es común proteger la lectura y olvidar la escritura.
- Si el ID es un UUID, no asumas que es "impredecible por diseño" — igual pruébalo con un UUID real de otro usuario obtenido lícitamente (p. ej. de una respuesta de listado).

**Vulnerable si:** devuelve 200 con los datos de otro usuario, o permite modificar/borrar el recurso ajeno.
**Seguro si:** 403 (preferible) o 404 (aceptable si no se quiere confirmar existencia) sin filtrar datos del recurso.

## API2:2023 — Broken Authentication

**Aplica cuando:** el endpoint requiere autenticación vía JWT, sesión o API key.

**Payloads / manipulaciones:**
- JWT con `"alg": "none"` y firma vacía.
- JWT con `alg` cambiado de `RS256` a `HS256`, firmando con la clave pública como secreto (confusión de algoritmo).
- Token expirado (`exp` en el pasado) reenviado tal cual.
- Token con `exp` eliminado del payload.
- Reintentar login con credenciales incorrectas 20-50 veces seguidas para verificar lockout/rate-limit.
- API key en query string en vez de header (verificar si el servidor la acepta igual — indica logging inseguro de credenciales).

**Vulnerable si:** el token manipulado es aceptado, o no hay lockout tras múltiples intentos fallidos.
**Seguro si:** 401 en todos los casos anteriores; lockout o captcha tras N intentos fallidos.

## API3:2023 — Broken Object Property Level Authorization

Incluye **Mass Assignment** y **Excessive Data Exposure**.

**Mass Assignment — cómo probar:**
- Tomar el body legítimo de un request de creación/actualización y añadir campos que el usuario no debería poder setear: `role`, `isAdmin`, `verified`, `balance`, `price`, `ownerId`.
- Ejemplo: `PATCH /users/me` con body `{"name": "Ana", "role": "admin"}`.

**Excessive Data Exposure — cómo probar:**
- Comparar el JSON completo de la respuesta contra lo que el frontend realmente muestra. Buscar campos como `passwordHash`, `internalNotes`, `ssn`, `creditCardLast4` que vienen en la respuesta pero no se renderizan (el filtrado se hizo en el frontend, no en el backend).

**Vulnerable si:** el campo inyectado se persiste, o la respuesta incluye campos sensibles no destinados al cliente.
**Seguro si:** el campo extra se ignora silenciosamente (o el request se rechaza con 422), y la respuesta solo incluye los campos que el rol del usuario debe ver.

## API4:2023 — Unrestricted Resource Consumption

**Aplica cuando:** el endpoint no limita explícitamente tamaño de página, tamaño de payload, tasa de requests o costo computacional (búsquedas, generación de reportes, uploads).

**Cómo probar:**
- `?limit=999999` o `?page_size=100000` en endpoints de listado.
- Body de request anormalmente grande (varios MB) en un endpoint que no lo espera.
- Ráfaga de requests concurrentes al mismo endpoint (10-100 en paralelo) para verificar rate-limiting.
- Subir un archivo sin límite de tamaño declarado, o con un content-type que dispare procesamiento costoso (imagen gigante, PDF con muchas páginas).

**Vulnerable si:** el servidor procesa la request sin límite, degradando performance o devolviendo un dataset completo sin paginar.
**Seguro si:** 400/413/429 según el caso, o la respuesta se trunca a un máximo razonable.

## API5:2023 — Broken Function Level Authorization (BFLA)

**Aplica cuando:** existe una jerarquía de roles (user/moderator/admin/service-account) y rutas o acciones reservadas a roles superiores.

**Cómo probar:**
- Con un token de rol `user`, llamar directamente rutas documentadas como `/admin/*` o acciones administrativas (`DELETE /users/{id}`, `POST /admin/broadcast`).
- Probar cambiar solo el verbo HTTP en un endpoint que el usuario normal sí puede leer (GET permitido, pero DELETE no debería estarlo).
- Probar rutas no documentadas pero adivinables por convención (si existe `/api/v1/admin/users`, probar `/api/v1/admin/settings`).

**Vulnerable si:** la acción se ejecuta con un rol insuficiente.
**Seguro si:** 403 consistente, sin importar si la ruta "no debería ser conocida" (seguridad por oscuridad no cuenta).

## API6:2023 — Unrestricted Access to Sensitive Business Flows

**Aplica cuando:** el flujo de negocio asume un ritmo humano o un orden de pasos (compra, registro, votación, reserva de inventario).

**Cómo probar:**
- Automatizar la repetición rápida de una acción de un solo uso por usuario (aplicar un cupón, votar, reclamar una recompensa) para ver si hay control de "una vez por usuario" a nivel de servidor.
- Saltar pasos intermedios de un flujo multi-step llamando directamente al endpoint final con datos fabricados.

**Vulnerable si:** la acción se puede repetir o el flujo se puede saltar sin validación server-side.
**Seguro si:** hay idempotencia/control transaccional que rechaza la repetición o el salto de paso.

## API7:2023 — Server Side Request Forgery (SSRF)

**Aplica cuando:** el endpoint acepta una URL, webhook, callback, o referencia a un recurso remoto como input.

**Payloads:**
- `http://169.254.169.254/latest/meta-data/` (metadata de cloud — AWS/GCP/Azure)
- `http://localhost:PUERTO_INTERNO/`
- `file:///etc/passwd`
- Un dominio propio controlado por el tester, para confirmar la callback y capturar headers/IP de origen.

**Vulnerable si:** el servidor realiza la request y filtra la respuesta o el estado (aunque sea indirectamente, p. ej. tiempos de respuesta distintos según si el puerto interno existe).
**Seguro si:** la URL se valida contra una allowlist, o se rechaza cualquier destino no público/no permitido.

## API8:2023 — Security Misconfiguration

**Cómo probar:**
- Revisar headers de respuesta: `Access-Control-Allow-Origin: *` combinado con `Access-Control-Allow-Credentials: true` (combinación insegura), ausencia de `Content-Security-Policy`, `X-Content-Type-Options`.
- Forzar un error (input malformado, tipo de dato incorrecto) y revisar si la respuesta expone stack trace, versión de framework, o rutas del sistema de archivos.
- Probar métodos HTTP no esperados (`OPTIONS`, `TRACE`) para ver si exponen información de más.

**Vulnerable si:** headers de seguridad ausentes/mal configurados, o los errores filtran detalles internos.

## API9:2023 — Improper Inventory Management

**Cómo probar:**
- Buscar versiones anteriores de la API (`/v1/` cuando el frontend usa `/v2/`) y verificar si siguen activas con protecciones más débiles.
- Buscar endpoints de documentación/debug expuestos (`/swagger`, `/api-docs`, `/actuator`, `/.well-known`) en el mismo dominio de producción.

**Vulnerable si:** una versión vieja o un endpoint de debug sigue accesible y con menos controles que la versión "oficial" actual.

## API10:2023 — Unsafe Consumption of APIs

**Aplica cuando:** el backend bajo prueba llama a su vez a APIs de terceros y usa esa respuesta sin validarla/sanitizarla (para poblar una base de datos, renderizar HTML, construir un comando).

**Cómo probar:**
- Si es posible controlar o mockear la respuesta del servicio upstream (en un entorno de staging), inyectar payloads de XSS/inyección en esa respuesta y verificar si el backend los propaga sin sanitizar.

**Vulnerable si:** el dato de la API externa llega sin sanitizar al usuario final o a una query.

---

## Inyecciones clásicas (transversales, no exclusivas del Top 10 pero centrales en cualquier auditoría de API)

### SQL Injection

**Aplica cuando:** cualquier parámetro llega a una consulta SQL, incluso indirectamente vía ORM (raw queries, `filter(f"... {var}")`, concatenación de strings).

**Payloads:**
```
' OR '1'='1
' OR '1'='1' --
admin'--
' UNION SELECT NULL,NULL,NULL--
'; DROP TABLE users;--
1' AND SLEEP(5)--        (blind, basado en tiempo)
```

**Vulnerable si:** cambia el comportamiento de la query (devuelve más filas de las esperadas, error de sintaxis SQL en la respuesta, delay medible con el payload de `SLEEP`).
**Seguro si:** 400/422 consistente, o el input se trata como literal sin afectar la query (parametrización correcta).

### NoSQL Injection (MongoDB y similares)

**Payloads (en el body JSON, no en query string):**
```json
{"username": "admin", "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"$where": "this.password.length > 0"}
```

**Vulnerable si:** el login o filtro tiene éxito sin credenciales válidas.
**Seguro si:** se valida el tipo de dato esperado (rechaza objetos donde se espera un string) antes de pasar el input al driver de la DB.

### Command Injection

**Aplica cuando:** el endpoint dispara un proceso del sistema (conversión de archivos, ping/DNS lookup, generación de PDF/imagen vía herramienta externa).

**Payloads:**
```
; whoami
| whoami
$(whoami)
`whoami`
test.jpg; rm -rf /tmp/x
```

**Vulnerable si:** el output del comando inyectado aparece en la respuesta, o hay un delay/efecto observable (usar `sleep 5` en vez de comandos destructivos en el payload de prueba).
**Seguro si:** el input se sanitiza o el proceso se invoca sin pasar por un shell (arrays de argumentos, no concatenación de strings).

### XSS (Reflejado y Almacenado)

**Aplica cuando:** el input del usuario se refleja en una respuesta HTML (aunque sea vía un endpoint de API consumido después por un frontend que renderiza sin escapar) o se almacena para mostrarse a otros usuarios.

**Payloads:**
```html
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
"><svg onload=alert(1)>
```

**Vulnerable si:** el payload se devuelve sin escapar en el `Content-Type: text/html`, o se almacena tal cual y se sabe que un frontend lo renderiza sin sanitizar.
**Seguro si:** el output está HTML-escapado, o la API fuerza `Content-Type: application/json` (mitiga pero no elimina el riesgo si un consumidor downstream lo renderiza igual).
