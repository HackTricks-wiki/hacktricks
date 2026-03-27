# Monitoreo de Integridad de Archivos

{{#include ../../banners/hacktricks-training.md}}

## Línea base

Una línea base consiste en tomar una instantánea de ciertas partes de un sistema para **compararla con un estado futuro y resaltar cambios**.

Por ejemplo, puedes calcular y almacenar el hash de cada archivo del filesystem para poder averiguar qué archivos fueron modificados.\
Esto también puede hacerse con las cuentas de usuario creadas, procesos en ejecución, servicios en ejecución y cualquier otra cosa que no debería cambiar mucho, o en absoluto.

Una **línea base útil** suele almacenar más que un simple digest: permisos, propietario, grupo, marcas de tiempo, inode, destino del symlink, ACLs y atributos extendidos seleccionados también merecen ser rastreados. Desde la perspectiva de threat hunting, esto ayuda a detectar **manipulación solo de permisos**, **reemplazo atómico de archivos** y **persistencia mediante archivos de servicio/unidad modificados** incluso cuando el hash del contenido no es lo primero que cambia.

### File Integrity Monitoring

File Integrity Monitoring (FIM) es una técnica de seguridad crítica que protege entornos TI y datos rastreando cambios en archivos. Normalmente combina:

1. **Comparación con línea base:** Almacenar metadatos y sumas de comprobación criptográficas (preferir `SHA-256` o mejor) para comparaciones futuras.
2. **Notificaciones en tiempo real:** Suscribirse a eventos de archivos nativos del SO para saber **qué archivo cambió, cuándo y, idealmente, qué proceso/usuario lo tocó**.
3. **Reescan periódico:** Reconstruir la confianza después de reinicios, eventos perdidos, fallos del agente o actividad anti-forense deliberada.

Para threat hunting, FIM suele ser más útil cuando se enfoca en **rutas de alto valor** como:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron locations, SSH material, PAM modules, web roots
- Windows persistence locations, service binaries, scheduled task files, startup folders
- Container writable layers and bind-mounted secrets/configuration

## Real-Time Backends & Blind Spots

### Linux

El backend de recolección importa:

- **`inotify` / `fsnotify`**: fácil y común, pero los límites de watch pueden agotarse y se pierden algunos casos límite.
- **`auditd` / audit framework**: mejor cuando necesitas **quién cambió el archivo** (`auid`, process, pid, executable).
- **`eBPF` / `kprobes`**: opciones más nuevas usadas por stacks FIM modernos para enriquecer eventos y reducir parte del dolor operacional de despliegues simples con `inotify`.

Algunas advertencias prácticas:

- Si un programa **reemplaza** un archivo con `write temp -> rename`, vigilar solo el archivo puede dejar de ser útil. **Vigila el directorio padre**, no solo el archivo.
- Los colectores basados en `inotify` pueden perder eventos o degradarse con **árboles de directorio enormes**, **actividad de hard-links**, o después de que un **archivo observado sea eliminado**.
- Conjuntos de watch recursivos muy grandes pueden fallar silenciosamente si `fs.inotify.max_user_watches`, `max_user_instances`, o `max_queued_events` son demasiado bajos.
- Los sistemas de archivos en red suelen ser malos objetivos para FIM cuando se busca monitorización de bajo ruido.

Example baseline + verification with AIDE:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Ejemplo de configuración FIM de `osquery` enfocada en rutas de persistencia del atacante:
```json
{
"schedule": {
"fim": {
"query": "SELECT * FROM file_events;",
"interval": 300,
"removed": false
}
},
"file_paths": {
"etc": ["/etc/%%"],
"systemd": ["/etc/systemd/system/%%", "/usr/lib/systemd/system/%%"],
"ssh": ["/root/.ssh/%%", "/home/%/.ssh/%%"]
}
}
```
Si necesitas **process attribution** en lugar de solo cambios a nivel de ruta, prefiere telemetría respaldada por auditoría como `osquery` `process_file_events` o el modo `whodata` de Wazuh.

### Windows

En Windows, FIM es más fuerte cuando combinas **change journals** con **high-signal process/file telemetry**:

- **NTFS USN Journal** proporciona un registro persistente por volumen de los cambios en archivos.
- **Sysmon Event ID 11** es útil para la creación/sobrescritura de archivos.
- **Sysmon Event ID 2** ayuda a detectar **timestomping**.
- **Sysmon Event ID 15** es útil para **named alternate data streams (ADS)** como `Zone.Identifier` o flujos ocultos de payload.

Ejemplos rápidos de triage USN:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Para ideas anti-forenses más profundas sobre **timestamp manipulation**, **ADS abuse**, y **USN tampering**, consulta [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Contenedores

El FIM de contenedores con frecuencia pasa por alto la ruta real de escritura. Con Docker `overlay2`, los cambios se escriben en la **writable upper layer** del contenedor (`upperdir`/`diff`), no en las capas de imagen de solo lectura. Por lo tanto:

- Monitorizar solo las rutas desde **dentro** de un contenedor de corta duración puede pasar por alto cambios después de que el contenedor se recree.
- Monitorizar la **host path** que respalda la writable layer o el volumen bind-mounted relevante suele ser más útil.
- El FIM en las capas de imagen difiere del FIM en el sistema de archivos del contenedor en ejecución.

## Notas de hunting orientadas al atacante

- Supervisa **service definitions** y **task schedulers** con la misma atención que los binarios. Los atacantes a menudo obtienen persistencia modificando un unit file, una entrada de cron o un task XML en lugar de parchear `/bin/sshd`.
- Un hash de contenido por sí solo es insuficiente. Muchas intrusiones se manifiestan primero como **owner/mode/xattr/ACL drift**.
- Si sospechas una intrusión madura, haz ambas cosas: **real-time FIM** para actividad reciente y una **cold baseline comparison** desde medios de confianza.
- Si el atacante tiene ejecución a nivel root o kernel, asume que el agente FIM, su base de datos e incluso la fuente de eventos pueden ser manipulados. Almacena logs y baselines de forma remota o en medios de solo lectura siempre que sea posible.

## Herramientas

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## Referencias

- [https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)

{{#include ../../banners/hacktricks-training.md}}
