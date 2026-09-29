# Checklist — Mobile (OWASP MASVS, priorizado por ROI)

Leída por `attack_planner_agent` (`core.planner`). Columnas fijas:
`id, nombre, categoria, tiempo_estimado (min), herramienta, criterio_exito,
prioridad_base (1–5, 5 = mayor ROI)`. No uses el carácter `|` dentro de una celda.

| id | nombre | categoria | tiempo_estimado | herramienta | criterio_exito | prioridad_base |
|----|--------|-----------|-----------------|-------------|----------------|----------------|
| masvs-storage | Almacenamiento inseguro de datos | storage | 40 | manual, adb, objection | Datos sensibles en claro en el dispositivo | 4 |
| masvs-authn | Bypass de autenticación local | authn | 45 | manual, Frida | Bypass de biometría o PIN local | 4 |
| masvs-code | Secretos hardcodeados en el binario | code | 25 | manual, jadx, apktool | Extracción de secretos válidos del binario | 4 |
| masvs-platform | Componentes exportados inseguros | platform | 35 | manual, drozer | Componente exportado invocable con impacto | 4 |
| masvs-crypto | Criptografía débil | crypto | 30 | manual | Uso de cifrado débil o claves embebidas | 4 |
| masvs-network | Red insegura, sin TLS pinning | network | 30 | manual, mitmproxy | Interceptación de tráfico sensible sin pinning | 3 |
| masvs-webview | WebView mal configurada | platform | 25 | manual | JS bridge o file access explotable | 3 |
| masvs-deeplink | Manejo inseguro de deep links | platform | 25 | manual, adb | Acción sensible vía deep link no validado | 3 |
| masvs-resilience | Anti-tampering y detección de root | resilience | 30 | manual, Frida | Bypass de controles con impacto real | 2 |
| masvs-backup | Backup permite extraer datos | storage | 15 | manual, adb | allowBackup expone datos sensibles del usuario | 2 |
