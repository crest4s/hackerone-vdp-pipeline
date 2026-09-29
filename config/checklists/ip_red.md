# Checklist — IP / red (checks a nivel de red y servicio, priorizado por ROI)

Leída por `attack_planner_agent` (`core.planner`). Columnas fijas:
`id, nombre, categoria, tiempo_estimado (min), herramienta, criterio_exito,
prioridad_base (1–5, 5 = mayor ROI)`. No uses el carácter `|` dentro de una celda.
Todos los checks son NO destructivos y respetan `nmap_timing: T2` y los límites
de `config.yaml`. Nada de brute-force ni DoS.

| id | nombre | categoria | tiempo_estimado | herramienta | criterio_exito | prioridad_base |
|----|--------|-----------|-----------------|-------------|----------------|----------------|
| net-unauth-service | Servicio sensible sin autenticación | authz | 30 | manual | Un servicio expone datos o funciones sin autenticación | 5 |
| net-known-cve | CVE conocido en versión expuesta | injection | 40 | manual | Confirmación NO destructiva de un CVE explotable | 5 |
| net-exposed-admin | Interfaces de administración expuestas | config | 20 | manual, httpx | Panel de administración accesible sin restricción | 4 |
| net-default-creds | Credenciales por defecto (una sola prueba) | authn | 30 | manual | Login con credenciales por defecto, sin fuerza bruta | 4 |
| net-file-shares | Comparticiones abiertas SMB/NFS/FTP | data | 25 | manual | Acceso de lectura o escritura a comparticiones | 4 |
| net-portmap | Descubrimiento de servicios (ligero) | recon | 20 | nmap -T2 | Inventario de servicios y versiones expuestos | 3 |
| net-snmp | SNMP con community public | recon | 15 | manual, snmpwalk | Lectura de información vía community public | 3 |
| net-dns-axfr | Transferencia de zona DNS | recon | 15 | manual, dig | Transferencia de zona AXFR permitida | 3 |
| net-remote-access | VPN/RDP expuesto y mal configurado | config | 20 | manual | Servicio de acceso remoto mal configurado con impacto | 3 |
| net-tls-config | Revisión de configuración TLS/SSL | crypto | 15 | manual, testssl | Config TLS débil con impacto (no solo el grado) | 2 |
