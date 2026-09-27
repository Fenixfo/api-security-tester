---
name: api-security-tester
description: Analiza endpoints de APIs, especificaciones OpenAPI o código de backend para identificar posibles vulnerabilidades de seguridad y generar suites de pruebas automatizadas basadas en el OWASP API Security Top 10. Actívala cuando el usuario pida auditar un endpoint, probar seguridad en una API o generar pruebas de penetración/fuzzing.
---

# API Security Tester

Convierte la definición de un endpoint, una especificación OpenAPI/Swagger o código fuente de backend en un plan de pruebas de seguridad ofensivo y ejecutable, mapeado al OWASP API Security Top 10 (2023).

**Alcance:** esta skill asume que el usuario tiene autorización para probar el sistema objetivo (su propio código, un entorno de staging, o un engagement de pentesting/CTF autorizado). Si el input parece ser una API de terceros sin evidencia de autorización, pregunta antes de generar payloads activos. Genera siempre el análisis y la matriz de casos; para el código ejecutable, deja explícito que debe correr solo contra objetivos autorizados (usa variables de entorno para la URL base, nunca hardcodees dominios de producción ajenos).

## Flujo de análisis

Ejecuta estos cuatro pasos en orden. No saltes al código sin completar el mapeo de vulnerabilidades — el código sale directamente de la matriz, no al revés.

### 1. Extraer el modelo del endpoint

De lo que te pase el usuario (spec OpenAPI, snippet de ruta, controlador de backend, captura de una request), extrae y tabula:

| Campo | Qué buscar |
|---|---|
| Método HTTP | GET/POST/PUT/PATCH/DELETE |
| Ruta y parámetros de path | especialmente IDs (`/users/{id}`, `/orders/{orderId}`) |
| Query params | filtros, paginación (`page`, `limit`, `offset`) |
| Body schema | campos requeridos vs. opcionales, tipos, campos sensibles (`role`, `isAdmin`, `price`, `balance`) |
| Headers de auth | `Authorization: Bearer`, API key, cookie de sesión — y si el endpoint declara que NO requiere auth |
| Rol/privilegio esperado | ¿es un endpoint de usuario normal, admin, service-to-service? |
| Respuestas documentadas | códigos 2xx/4xx que ya declara la spec — te dicen qué "debería" pasar |

Si falta información (p. ej. no se sabe qué rol requiere), no la inventes: márcala como "a confirmar" en la matriz en vez de asumir.

### 2. Mapear contra OWASP API Security Top 10

Para cada endpoint, evalúa sistemáticamente contra las categorías de la tabla siguiente. La lógica de detección y los payloads detallados de cada categoría están en `references/owasp-api-top10.md` — cárgalo cuando necesites payloads específicos o quieras justificar por qué una categoría no aplica.

| Categoría | Se activa cuando el endpoint... | Vector típico |
|---|---|---|
| **API1 – BOLA/IDOR** | Recibe un ID de objeto en path/query/body | Cambiar el ID por el de otro usuario/tenant |
| **API2 – Broken Authentication** | Requiere o emite tokens (JWT, sesión, API key) | Tokens expirados, `alg: none`, firma débil/reusada, brute-force sin lockout |
| **API3 – Broken Object Property Level Auth** | Devuelve o acepta objetos con campos internos | Mass assignment (`role`, `isAdmin`), excessive data exposure en la respuesta |
| **API4 – Unrestricted Resource Consumption** | No pagina, no limita tamaño de respuesta/request, no rate-limitea | `limit=999999`, requests en paralelo, payloads grandes |
| **API5 – BFLA** | Existe una jerarquía de roles (user/admin/service) | Usuario normal llamando rutas o verbos de admin |
| **API6 – Unrestricted Business Flow Access** | El flujo de negocio asume orden/humano (checkout, votación) | Saltar pasos, repetir una acción de un solo uso |
| **API7 – SSRF** | Acepta una URL/callback/webhook como input | URL apuntando a `169.254.169.254`, `localhost`, servicios internos |
| **API8 – Security Misconfiguration** | Headers de seguridad, CORS, verbosidad de errores | `Access-Control-Allow-Origin: *`, stack traces, métodos HTTP no deshabilitados |
| **API9 – Improper Inventory Management** | Existen versiones viejas o entornos de staging expuestos | `/v1/` vs `/v2/`, endpoints de debug/swagger expuestos |
| **API10 – Unsafe Consumption of 3rd-Party APIs** | El backend consume datos de APIs externas sin sanitizar | Inyección vía respuesta de un servicio upstream no confiable |

Añade explícitamente las inyecciones clásicas cuando el endpoint toca una capa de datos o de sistema:

| Vector | Se activa cuando... |
|---|---|
| **SQL Injection** | Params/body van a una query SQL (incluso vía ORM con raw queries) |
| **NoSQL Injection** | Backend usa Mongo/similar y acepta operadores (`$gt`, `$where`) en el body |
| **Command Injection** | El endpoint dispara un proceso del sistema, genera PDFs/imágenes, hace ping/DNS lookup |
| **XSS (reflejado/almacenado)** | El input se refleja en una respuesta HTML o se almacena para ser mostrado a otro usuario |

Descarta explícitamente las categorías que no aplican y di por qué (p. ej. "API7 SSRF no aplica: el endpoint no acepta URLs como input"). Un análisis que dice "no aplica" con justificación vale más que uno que ignora la categoría en silencio.

### 3. Construir la matriz de casos de prueba

Una fila por caso de prueba, con payload concreto y resultado esperado — no descripciones vagas. Usa esta plantilla (ver `references/test-matrix-template.md` para más ejemplos completos):

| ID | Vulnerabilidad | Endpoint | Método | Manipulación / Payload | Resultado esperado | Código esperado |
|---|---|---|---|---|---|---|
| TC-01 | BOLA | `/orders/{id}` | GET | Autenticarse como user A, pedir `id` de user B | Acceso denegado | 403 (o 404 si no se debe confirmar existencia) |
| TC-02 | Mass Assignment | `/users/me` | PATCH | Body con `{"role": "admin"}` inyectado junto a campos legítimos | El campo `role` se ignora silenciosamente | 200 sin cambio de rol |
| TC-03 | Broken Auth | `/api/*` | * | JWT con `alg` cambiado a `none` y firma vacía | Token rechazado | 401 |
| TC-04 | BFLA | `/admin/users` | GET | Token válido de rol `user` normal | Acceso denegado | 403 |
| TC-05 | Resource Consumption | `/search` | GET | `?limit=100000` o 500 requests concurrentes | Rate-limit o cap de paginación | 429 o límite aplicado |
| TC-06 | SQLi | `/products?category=` | GET | `' OR '1'='1` / `'; DROP TABLE--` | Query rechazada o tratada como literal | 400/422, sin filtrado de datos |
| TC-07 | NoSQLi | `/login` | POST | `{"password": {"$ne": null}}` | Login falla igual que credencial incorrecta | 401 |
| TC-08 | XSS | `/comments` | POST | `<script>alert(1)</script>` en un campo de texto | El payload se sanitiza/escapa al renderizarse | 200 con output escapado |

Cada fila necesita **ambos lados**: el caso que debe fallar (ataque bloqueado → 401/403/422/429) y, cuando aplique, el caso positivo que confirma que la funcionalidad legítima sigue funcionando (para evitar falsos positivos de "está roto" cuando en realidad rechaza todo).

### 4. Generar el código ejecutable

Con la matriz ya construida, genera **una** de estas dos salidas (pregunta cuál prefiere el usuario si no lo dijo; por defecto usa pytest si el backend es Python/desconocido, o Postman si el usuario ya trabaja con colecciones):

- **pytest + requests**: parte de `assets/pytest_template.py`. Cada fila de la matriz se convierte en un test parametrizado o una función `test_<id>_<vulnerabilidad>`. Usa fixtures para los tokens de los distintos roles (`user_token`, `admin_token`, `other_user_token`) en vez de hardcodear credenciales.
- **Postman/Newman**: parte de `assets/postman_collection_template.json`. Cada fila de la matriz es un request dentro de una carpeta con el nombre de la categoría OWASP, con un test script (`pm.test(...)`) que verifica el código de estado y, cuando aplique, que el body no filtre campos sensibles.

Reglas para el código generado:
- La URL base y las credenciales salen de variables de entorno (`API_BASE_URL`, `USER_TOKEN`, etc.), nunca hardcodeadas.
- Cada test verifica explícitamente el código de estado HTTP esperado (no solo "no crashea").
- Cuando el payload es potencialmente destructivo (DROP TABLE, comandos del sistema), el test verifica la *ausencia* de efecto (p. ej. la tabla sigue existiendo) en vez de ejecutarlo a ciegas contra datos reales — usa un entorno de staging/sandbox.
- Nombra los tests con el ID de la matriz (`TC-01`) para poder trazar resultado → fila → categoría OWASP.

## Estilo de salida

- Responde en el idioma en que te habla el usuario.
- Sin introducciones teóricas sobre "qué es OWASP" salvo que te lo pidan explícitamente — ve directo al análisis del endpoint concreto.
- Entrega siempre, en este orden: (1) tabla del modelo del endpoint, (2) tabla de mapeo OWASP con las categorías descartadas justificadas, (3) matriz de casos de prueba, (4) código ejecutable.
- Si el input es incompleto (falta la spec de auth, no se sabe el rol requerido), dilo en una línea y marca esos casos como "a confirmar" en vez de detener todo el análisis.
- El código debe poder copiarse y ejecutarse tal cual (con las variables de entorno correspondientes seteadas) — no pseudocódigo.

## Recursos de la skill

- `references/owasp-api-top10.md` — detección detallada y catálogo de payloads por categoría OWASP e inyecciones clásicas. Cárgalo para profundizar en una categoría específica.
- `references/test-matrix-template.md` — plantilla ampliada de la matriz de casos con más ejemplos por categoría.
- `assets/pytest_template.py` — esqueleto de suite pytest + requests con fixtures de auth multi-rol.
- `assets/postman_collection_template.json` — esqueleto de colección Postman organizada por categoría OWASP, ejecutable con Newman.
