# api-security-tester

Skill para [Claude Code](https://claude.com/claude-code) que audita endpoints de APIs, especificaciones OpenAPI/Swagger o código de backend, y genera un plan de pruebas de seguridad ejecutable mapeado al **OWASP API Security Top 10**.

Dale a Claude una ruta, un spec o un repo, y en vez de una explicación teórica obtienes:

1. La tabla del endpoint (método, params, headers de auth, rol requerido).
2. El mapeo contra OWASP API Top 10 + inyecciones clásicas (BOLA/IDOR, Broken Auth, BFLA, Mass Assignment, Resource Consumption, SQLi/NoSQLi/XSS...), con las categorías que **no** aplican justificadas, no ignoradas.
3. Una matriz de casos de prueba con payloads concretos y el código HTTP esperado (401/403/422/429).
4. Código ejecutable — pytest + requests o una colección Postman/Newman — listo para copiar y correr.

> **Alcance:** pensada para pruebas autorizadas — tu propio código, un entorno de staging, o un engagement de pentesting/CTF donde tienes permiso. La skill lo asume y lo deja explícito en las instrucciones; no genera ataques contra sistemas de terceros sin evidencia de autorización.

## Instalación

Copia esta carpeta dentro de tu directorio de skills de Claude Code:

```bash
# Skill disponible en todos tus proyectos
git clone https://github.com/Fenixfo/api-security-tester.git ~/.claude/skills/api-security-tester

# o, si solo la quieres en un proyecto puntual
git clone https://github.com/Fenixfo/api-security-tester.git <tu-proyecto>/.claude/skills/api-security-tester
```

En Windows, `~/.claude/skills/` es `%USERPROFILE%\.claude\skills\`.

Claude Code detecta la skill automáticamente en la próxima sesión — no hace falta reiniciar nada ni instalar dependencias adicionales (los templates de `assets/` sí asumen `pytest` + `requests`, o Newman, según cuál generes).

Para actualizarla más adelante: `git pull` dentro de esa misma carpeta.

## Uso

Se activa sola cuando le pides a Claude Code cosas como:

- "Audita este endpoint: `POST /api/usuarios/permisos`, ¿qué vulnerabilidades debería probar?"
- "Aquí está mi spec OpenAPI, genérame un plan de pentesting para la API."
- "Revisa este controlador de backend en busca de BOLA o mass assignment."
- "Necesito una suite de fuzzing para esta colección de Postman."

También puedes invocarla explícitamente pasándole un endpoint, un archivo `openapi.json` o una ruta a código fuente de backend.

## Qué contiene

```
api-security-tester/
├── SKILL.md                              # Instrucciones: el flujo de análisis de 4 pasos
├── references/
│   ├── owasp-api-top10.md                # Detección y payloads por categoría OWASP + inyecciones
│   └── test-matrix-template.md           # Plantilla ampliada de la matriz de casos (19 ejemplos)
└── assets/
    ├── pytest_template.py                # Esqueleto pytest + requests, fixtures multi-rol
    └── postman_collection_template.json  # Colección Postman organizada por categoría OWASP
```

## Ejemplo real

Esta skill se usó para auditar una API multi-tenant de inventario/facturación (Next.js + Prisma + Supabase) y encontró una escalación de privilegios real: un endpoint de gestión de usuarios permitía que cualquier cuenta con el permiso `usuarios.gestionar` se auto-concediera permisos financieros/de auditoría que nunca le habían sido otorgados. El fix consistió en una sola comprobación (`no se puede otorgar un permiso que uno mismo no tiene`), verificada con un test de regresión que corre en cada push.

## Licencia / contribuciones

Sin licencia formal todavía — trátalo como código de referencia. Si le agregas payloads, categorías OWASP nuevas, o soporte para otro framework de tests, un PR es bienvenido.
