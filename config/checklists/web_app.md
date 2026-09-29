# Checklist — Web application (OWASP WSTG, priorizado por ROI)

Leída por `attack_planner_agent` (`core.planner`). Columnas fijas:
`id, nombre, categoria, tiempo_estimado (min), herramienta, criterio_exito,
prioridad_base (1–5, 5 = mayor ROI)`. No uses el carácter `|` dentro de una celda.

| id | nombre | categoria | tiempo_estimado | herramienta | criterio_exito | prioridad_base |
|----|--------|-----------|-----------------|-------------|----------------|----------------|
| wstg-info-map | Fingerprint y mapeo de tecnología | recon | 10 | httpx, whatweb | Se identifican stack, versiones y superficies expuestas | 3 |
| wstg-authn-bypass | Bypass de autenticación | authn | 60 | manual, Burp Repeater | Acceso a recurso protegido sin credenciales válidas | 5 |
| wstg-idor | IDOR / broken object access | authz | 45 | manual, Burp | Acceso a datos de otro usuario cambiando un identificador | 5 |
| wstg-sqli | Inyección SQL | injection | 40 | manual, Burp | Extracción o alteración de datos vía payload SQL | 5 |
| wstg-xss | XSS reflejado o almacenado | injection | 30 | manual, Burp | Ejecución de JS arbitrario en contexto de la víctima | 5 |
| wstg-ssrf | Server-Side Request Forgery | injection | 45 | manual, Burp Collaborator | El servidor realiza peticiones a un destino controlado | 5 |
| wstg-access-control | Escalada vertical de privilegios | authz | 45 | manual, Burp | Un usuario estándar accede a funciones de administración | 5 |
| wstg-file-upload | Subida de archivos sin restricción | business | 40 | manual, Burp | Subida y ejecución de un archivo no permitido | 4 |
| wstg-secrets | Secretos expuestos, .git, backups | recon | 20 | manual, httpx | Descarga de credenciales o código fuente | 4 |
| wstg-session | Gestión de sesión defectuosa | session | 30 | manual, Burp | Fijación, no expiración o cookie sin flags con impacto | 3 |
| wstg-csrf | CSRF en acción sensible | session | 25 | manual, Burp | Acción con estado ejecutada sin token anti-CSRF | 3 |
| wstg-cors | Mala configuración CORS | config | 20 | manual, curl | Lectura de datos autenticados desde un origen no confiable | 3 |
| wstg-open-redirect | Open redirect con impacto | config | 15 | manual | Redirección a dominio externo controlado con impacto real | 2 |
| wstg-headers | Revisión de security headers | config | 10 | httpx, manual | Falta de header con impacto demostrable | 1 |
| wstg-clickjacking | Clickjacking | config | 10 | manual | Acción sensible enmarcable sin protección de framing | 1 |
