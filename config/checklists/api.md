# Checklist — API (OWASP API Security Top 10, priorizado por ROI)

Leída por `attack_planner_agent` (`core.planner`). Columnas fijas:
`id, nombre, categoria, tiempo_estimado (min), herramienta, criterio_exito,
prioridad_base (1–5, 5 = mayor ROI)`. No uses el carácter `|` dentro de una celda.

| id | nombre | categoria | tiempo_estimado | herramienta | criterio_exito | prioridad_base |
|----|--------|-----------|-----------------|-------------|----------------|----------------|
| api1-bola | BOLA / broken object level authorization | authz | 45 | manual, Burp | Acceso a un objeto de otro usuario cambiando su id | 5 |
| api2-authn | Broken authentication | authn | 45 | manual, Burp | Bypass de login, tokens débiles o sin expiración | 5 |
| api5-bfla | Broken function level authorization | authz | 40 | manual, Burp | Invocación de función de admin como usuario normal | 5 |
| api7-ssrf | Server-Side Request Forgery | injection | 45 | manual, Burp Collaborator | La API solicita un recurso interno controlado | 5 |
| api-jwt | Fallos en JWT | authn | 30 | manual, jwt_tool | alg=none, firma débil o inyección de kid | 4 |
| api3-bopla | Broken object property level authz | authz | 40 | manual, Burp | Lectura o escritura de propiedades no autorizadas | 4 |
| api6-flows | Acceso irrestricto a flujos de negocio | business | 45 | manual | Abuso de un flujo de negocio sin límites | 3 |
| api9-inventory | Gestión de inventario deficiente | recon | 25 | manual, httpx | Endpoints v1, debug o staging expuestos | 3 |
| api-graphql | Introspección y abuso de GraphQL | recon | 25 | manual | Introspección habilitada o batching abusable | 3 |
| api10-consumption | Consumo inseguro de APIs de terceros | injection | 30 | manual | Inyección a través de datos de una API de tercero | 3 |
| api4-resource | Consumo de recursos sin restricción | business | 30 | manual | Ausencia de límites con impacto demostrable (no DoS) | 2 |
| api8-misconfig | Security misconfiguration | config | 20 | manual, httpx | Config insegura, errores verbose con impacto o CORS | 2 |
