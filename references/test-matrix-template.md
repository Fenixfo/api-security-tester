# Plantilla ampliada de matriz de casos de prueba

Usa esta plantilla como base al construir la matriz para un endpoint concreto. Incluye, por cada categoría, un caso negativo (el ataque debe fallar) y, cuando aplique, un caso positivo (la funcionalidad legítima sigue funcionando) para detectar falsos positivos de "todo bloqueado a lo bruto".

| ID | Vulnerabilidad | Endpoint | Método | Rol usado | Manipulación / Payload | Resultado esperado | Código esperado |
|---|---|---|---|---|---|---|---|
| TC-01 | BOLA (negativo) | `/orders/{id}` | GET | user A | Pedir `id` de un pedido de user B | Acceso denegado, sin datos filtrados | 403/404 |
| TC-02 | BOLA (positivo) | `/orders/{id}` | GET | user A | Pedir `id` de un pedido propio | Acceso permitido | 200 |
| TC-03 | BOLA (negativo, escritura) | `/orders/{id}` | DELETE | user A | Borrar pedido de user B | Rechazado | 403 |
| TC-04 | Mass Assignment | `/users/me` | PATCH | user | `{"name": "Ana", "role": "admin"}` | Campo `role` ignorado, resto aplicado | 200 sin cambio de rol |
| TC-05 | Excessive Data Exposure | `/users/{id}` | GET | user | — | La respuesta no incluye `passwordHash`/campos internos | 200 con body filtrado |
| TC-06 | Broken Auth (JWT alg none) | cualquiera protegida | * | — | JWT con `alg: none`, firma vacía | Token rechazado | 401 |
| TC-07 | Broken Auth (token expirado) | cualquiera protegida | * | user | Token con `exp` en el pasado | Token rechazado | 401 |
| TC-08 | Broken Auth (brute force) | `/login` | POST | — | 30 intentos con password incorrecta | Lockout o rate-limit tras N intentos | 429 (o bloqueo de cuenta) |
| TC-09 | BFLA | `/admin/users` | GET | user normal | Llamar la ruta de admin directamente | Rechazado | 403 |
| TC-10 | BFLA (verbo) | `/products/{id}` | DELETE | user normal | Verbo de escritura reservado a admin | Rechazado | 403 |
| TC-11 | Resource Consumption | `/search` | GET | user | `?limit=999999` | Límite aplicado por el servidor | 400 o resultados truncados |
| TC-12 | Resource Consumption (rate) | cualquiera | * | user | 100 requests concurrentes | Rate-limit aplicado | 429 en exceso |
| TC-13 | SQLi | `/products` | GET | — | `?category=' OR '1'='1` | Sin filtrado de datos ajenos a la query original | 400/422 o resultado sin alterar |
| TC-14 | NoSQLi | `/login` | POST | — | `{"password": {"$ne": null}}` | Login falla | 401 |
| TC-15 | Command Injection | `/reports/generate` | POST | user | Nombre de archivo `report.pdf; sleep 5` | Sin delay anómalo ni output de comando | 200/400 en tiempo normal |
| TC-16 | XSS almacenado | `/comments` | POST | user | `<script>alert(1)</script>` | Output escapado al leerse de vuelta | 200 con contenido escapado |
| TC-17 | SSRF | `/webhooks` | POST | user | URL `http://169.254.169.254/latest/meta-data/` | Request rechazada o URL no resuelta | 400/422 |
| TC-18 | Security Misconfiguration (CORS) | cualquiera | OPTIONS | — | Header `Origin` arbitrario | No refleja `*` junto con credentials | Headers CORS correctos |
| TC-19 | Inventory Management | — | GET | — | Probar `/v1/` si el frontend usa `/v2/` | Versión vieja deshabilitada o con mismos controles | 404 o paridad de seguridad |

## Notas de uso

- No todas las filas aplican a todos los endpoints — genera solo las que correspondan según el modelo del endpoint (paso 1 del flujo de la skill).
- Para endpoints de solo lectura sin IDs de objeto, BOLA no aplica; para endpoints sin roles diferenciados, BFLA no aplica.
- Cuando un endpoint maneje dinero, inventario o cualquier recurso limitado, prioriza siempre Mass Assignment y Resource Consumption — son los vectores con mayor impacto de negocio.
