# Checklist — Cloud (misconfiguraciones típicas AWS/GCP/Azure, priorizado por ROI)

Leída por `attack_planner_agent` (`core.planner`). Columnas fijas:
`id, nombre, categoria, tiempo_estimado (min), herramienta, criterio_exito,
prioridad_base (1–5, 5 = mayor ROI)`. No uses el carácter `|` dentro de una celda.

| id | nombre | categoria | tiempo_estimado | herramienta | criterio_exito | prioridad_base |
|----|--------|-----------|-----------------|-------------|----------------|----------------|
| cloud-storage-public | Bucket / blob de objetos público | storage | 15 | manual, awscli | Lectura o escritura de almacenamiento con datos sensibles | 5 |
| cloud-metadata-ssrf | Robo de credenciales por metadata SSRF | compute | 40 | manual, Burp | Robo de credenciales IMDS a través de un SSRF | 5 |
| cloud-iam-privesc | IAM excesivo / escalada de privilegios | iam | 60 | manual, awscli | Escalada por una política IAM demasiado permisiva | 5 |
| cloud-exposed-keys | Claves de cloud expuestas en activos | recon | 20 | manual, trufflehog | Claves válidas encontradas y verificadas | 4 |
| cloud-open-db | Base de datos o cache gestionada expuesta | data | 20 | manual | Acceso a una base de datos o cache sin autenticación | 4 |
| cloud-subdomain-takeover | DNS colgante / subdomain takeover | recon | 25 | manual, dnsx | Reclamo de un recurso apuntado por un CNAME colgante | 4 |
| cloud-storage-acl | ACL de almacenamiento con escritura | storage | 20 | manual | Escritura no autorizada en el almacenamiento | 4 |
| cloud-func-misconfig | Función serverless mal configurada | compute | 30 | manual | Función invocable o con permisos excesivos | 3 |
| cloud-public-snapshot | Snapshot, AMI o imagen de disco pública | data | 20 | manual, awscli | Snapshot o imagen pública con datos sensibles | 3 |
| cloud-logging | Logging deshabilitado o config débil | config | 15 | manual | Configuración observada sin impacto directo (informativo) | 1 |
