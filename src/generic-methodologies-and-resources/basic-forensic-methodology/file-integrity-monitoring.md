# Monitorización de la integridad de archivos

{{#include ../../banners/hacktricks-training.md}}

## Línea base

Una línea base consiste en tomar una instantánea de ciertas partes de un sistema para **compararla con un estado futuro y resaltar los cambios**.

Por ejemplo, puedes calcular y almacenar el hash de cada archivo del sistema de archivos para saber qué archivos fueron modificados.\
Esto también puede hacerse con las cuentas de usuario creadas, los procesos en ejecución, los servicios activos y cualquier otro elemento que no debería cambiar mucho o nada.

Una **línea base útil** normalmente almacena más que un simple digest: también vale la pena realizar un seguimiento de los permisos, propietario, grupo, marcas de tiempo, inode, destino de los symlinks, ACLs y atributos extendidos seleccionados.<sup>[[4]](#references)</sup> Desde la perspectiva de la búsqueda de atacantes, esto ayuda a detectar **manipulación exclusiva de permisos**, **reemplazo atómico de archivos** y **persistencia mediante archivos de servicio/unit modificados**, incluso cuando el hash del contenido no es lo primero que cambia.

### Monitorización de la integridad de archivos

La monitorización de la integridad de archivos (FIM) es una técnica de seguridad crítica que protege los entornos de IT y los datos mediante el seguimiento de los cambios en los archivos. Normalmente combina:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Comparación con la línea base:** Almacenar metadatos y checksums criptográficos (preferiblemente `SHA-256` o superior) para comparaciones futuras.
2. **Notificaciones en tiempo real:** Suscribirse a los eventos de archivos nativos del sistema operativo para saber **qué archivo cambió, cuándo y, preferiblemente, qué proceso/usuario lo modificó**.
3. **Nuevo escaneo periódico:** Recuperar la confianza después de reinicios, pérdida de eventos, interrupciones del agente o actividad anti-forense deliberada.

Para threat hunting, la FIM suele ser más útil cuando se centra en **rutas de alto valor**, como:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- Unidades de `systemd`, ubicaciones de cron, material de SSH, módulos PAM, raíces web
- Ubicaciones de persistencia de Windows, binarios de servicios, archivos de tareas programadas, carpetas de inicio
- Capas escribibles de contenedores y secretos/configuración montados mediante bind

## Backends en tiempo real y puntos ciegos

### Linux

El backend de recopilación es importante:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: fáciles y comunes, pero los límites de monitorización pueden agotarse y algunos casos especiales pueden pasar desapercibidos.
- **`auditd` / audit framework**: mejor cuando necesitas saber **quién modificó el archivo** (UID de inicio de sesión, ID del proceso y nombre del proceso).
- **`eBPF` / `kprobes`**: opciones más recientes utilizadas por los stacks modernos de FIM para enriquecer los eventos y reducir algunos problemas operativos de las implementaciones basadas únicamente en `inotify`.

Algunos problemas prácticos:<sup>[[1]](#references)[[5]](#references)</sup>

- Si un programa **reemplaza** un archivo mediante `write temp -> rename`, monitorizar el archivo en sí puede dejar de ser útil. **Monitoriza el directorio padre**, no solo el archivo.
- Los recopiladores basados en `inotify` pueden perder eventos o degradarse en **árboles de directorios enormes**, con **actividad sobre hard links** o después de que se elimine un **archivo monitorizado**.
- Los conjuntos de monitorización recursiva muy grandes pueden fallar silenciosamente si `fs.inotify.max_user_watches`, `max_user_instances` o `max_queued_events` son demasiado bajos.
- En la monitorización basada en `inotify`, los sistemas de archivos de red son un punto ciego porque los cambios remotos no se notifican.

Ejemplo de línea base + verificación con AIDE:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Ejemplo de configuración de FIM de `osquery` centrada en las rutas de persistencia de atacantes:<sup>[[1]](#references)</sup>
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
Si necesitas **atribución del proceso** en lugar de solo cambios a nivel de ruta, prefiere telemetría respaldada por auditoría, como `osquery` `process_file_events` o el modo `whodata` de Wazuh.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

### Windows

En Windows, FIM es más eficaz cuando combinas **diarios de cambios** con **telemetría de procesos/archivos de alta señal**:<sup>[[6]](#references)[[7]](#references)</sup>

- **NTFS USN Journal** proporciona un registro persistente por volumen de los cambios en los archivos.
- **Sysmon Event ID 11** es útil para detectar la creación o sobrescritura de archivos.
- **Sysmon Event ID 2** ayuda a detectar **timestomping**.
- **Sysmon Event ID 15** es útil para detectar **named alternate data streams (ADS)**, como `Zone.Identifier` o streams de payload ocultos.

Ejemplos rápidos de triage de USN:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Para profundizar en ideas anti-forensic relacionadas con **timestamp manipulation**, **ADS abuse** y **USN tampering**, consulta [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Contenedores

El FIM de contenedores frecuentemente no detecta la ruta de escritura real. Con Docker `overlay2`, el sistema de archivos del contenedor combina capas `lowerdir` de imagen de solo lectura con una **upper layer** escribible (`upperdir`/`diff`), y las escrituras en archivos de imagen se copian a esa upper layer.<sup>[[8]](#references)</sup> Por lo tanto:

- Monitorizar únicamente las rutas desde **dentro** de un contenedor de corta duración puede no detectar cambios después de que el contenedor se recree.
- Monitorizar la **ruta del host** que respalda la capa escribible o el volumen relevante montado mediante bind suele ser más útil.
- El FIM en las capas de imagen es diferente del FIM en el sistema de archivos del contenedor en ejecución.

## Notas de Hunting Orientadas al Atacante

- Rastrea las **definiciones de servicios** y los **task schedulers** con el mismo cuidado que los binarios. Los atacantes suelen conseguir persistencia modificando un archivo de unidad, una entrada de cron o un XML de tarea en lugar de parchear `/bin/sshd`.
- Un hash de contenido por sí solo es insuficiente. Muchos compromisos aparecen primero como **desviaciones de owner/mode/xattr/ACL**.
- Si sospechas de una intrusión madura, haz ambas cosas: **FIM en tiempo real** para detectar actividad reciente y una **comparación con una baseline offline** desde un medio de confianza.
- Si el atacante tiene ejecución como root o a nivel de kernel, considera que el agente de FIM y su base de datos no son confiables. Almacena los logs y las baselines de forma remota o en medios de solo lectura siempre que sea posible.<sup>[[4]](#references)</sup>

## Herramientas

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [Monitorización de la integridad de archivos con osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux: un caso de uso de monitorización de la integridad de archivos (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Monitorización de la integridad de archivos de Wazuh (modo Syscheck y whodata)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [Manual de AIDE versión 0.16.2](https://aide.github.io/doc/)
- [5] [Página del manual de Linux para inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [Controlador de almacenamiento OverlayFS](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Configuración avanzada de Wazuh FIM](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
{{#include ../../banners/hacktricks-training.md}}
