# Monitorización de la integridad de archivos

{{#include ../../banners/hacktricks-training.md}}

## Línea base

Una línea base consiste en tomar una instantánea de ciertas partes de un sistema para **compararla con un estado futuro y resaltar los cambios**.

Por ejemplo, puedes calcular y almacenar el hash de cada archivo del sistema de archivos para poder averiguar qué archivos fueron modificados.\
Esto también puede hacerse con las cuentas de usuario creadas, los procesos en ejecución, los servicios en ejecución y cualquier otro elemento que no debería cambiar mucho, o no debería cambiar en absoluto.

Una **línea base útil** normalmente almacena más que un simple digest: también vale la pena rastrear los permisos, el propietario, el grupo, las marcas de tiempo, el inode, el destino de los symlinks, las ACL y los atributos extendidos seleccionados. Desde la perspectiva de la búsqueda de atacantes, esto ayuda a detectar **manipulaciones que solo afectan a los permisos**, **reemplazos atómicos de archivos** y **persistencia mediante archivos de servicio/unit modificados**, incluso cuando el hash del contenido no es lo primero que cambia.

### Monitorización de la integridad de archivos

File Integrity Monitoring (FIM) es una técnica de seguridad crítica que protege los entornos de TI y los datos mediante el seguimiento de los cambios en los archivos. Normalmente combina:

1. **Comparación con la línea base:** Almacenar metadatos y checksums criptográficos (preferiblemente `SHA-256` o superior) para comparaciones futuras.
2. **Notificaciones en tiempo real:** Suscribirse a los eventos de archivos nativos del sistema operativo para saber **qué archivo cambió, cuándo y, preferiblemente, qué proceso/usuario lo modificó**.
3. **Reescaneo periódico:** Recuperar la confianza después de reinicios, eventos descartados, interrupciones de los agents o actividad anti-forense deliberada.

Para threat hunting, FIM suele ser más útil cuando se centra en **rutas de alto valor**, como:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- Unidades de `systemd`, ubicaciones de cron, material de SSH, módulos PAM, web roots
- Ubicaciones de persistencia de Windows, binarios de servicios, archivos de tareas programadas, carpetas de inicio
- Capas de escritura de containers y secrets/configuration montados mediante bind mounts

## Backends en tiempo real y puntos ciegos

### Linux

El backend de recolección es importante:<sup>[[2]](#references)</sup>

- **`inotify` / `fsnotify`**: fáciles y comunes, pero los límites de watch pueden agotarse y algunos casos límite no se detectan.
- **`auditd` / audit framework**: mejor cuando necesitas saber **quién cambió el archivo** (`auid`, proceso, pid, ejecutable).
- **`eBPF` / `kprobes`**: opciones más recientes utilizadas por los stacks modernos de FIM para enriquecer los eventos y reducir parte de los problemas operativos de las implementaciones basadas únicamente en `inotify`.

Algunos problemas prácticos:<sup>[[1]](#references)</sup>

- Si un programa **reemplaza** un archivo mediante `write temp -> rename`, observar el archivo en sí puede dejar de ser útil. **Observa el directorio padre**, no solo el archivo.
- Los recolectores basados en `inotify` pueden omitir eventos o degradarse en **árboles de directorios enormes**, **actividad con hard links** o después de que se elimine un **archivo observado**.
- Los conjuntos de watches recursivos muy grandes pueden fallar silenciosamente si `fs.inotify.max_user_watches`, `max_user_instances` o `max_queued_events` son demasiado bajos.
- Los sistemas de archivos de red suelen ser objetivos deficientes para una monitorización FIM con poco ruido.

Ejemplo de línea base + verificación con AIDE:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Ejemplo de configuración de FIM de `osquery` centrada en rutas de persistencia de atacantes:<sup>[[1]](#references)</sup>
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
Si necesitas **atribución de procesos** en lugar de solo cambios a nivel de ruta, prefiere telemetría respaldada por auditoría, como `osquery` `process_file_events` o el modo `whodata` de Wazuh.<sup>[[1]](#references)[[3]](#references)</sup>

### Windows

En Windows, FIM es más eficaz cuando combinas **change journals** con **telemetría de procesos/archivos de alta señal**:

- **NTFS USN Journal** proporciona un registro persistente por volumen de los cambios en los archivos.
- **Sysmon Event ID 11** es útil para detectar la creación/sobrescritura de archivos.
- **Sysmon Event ID 2** ayuda a detectar **timestomping**.
- **Sysmon Event ID 15** es útil para detectar **named alternate data streams (ADS)**, como `Zone.Identifier` o streams de payload ocultos.

Ejemplos rápidos de triage de USN:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Para consultar ideas más profundas de **timestamp manipulation**, **ADS abuse** y **USN tampering** relacionadas con anti-forensics, revisa [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Contenedores

El FIM de contenedores con frecuencia no detecta la ruta de escritura real. Con Docker `overlay2`, los cambios se confirman en la **capa superior escribible** del contenedor (`upperdir`/`diff`), no en las capas de imagen de solo lectura. Por lo tanto:

- Monitorizar únicamente las rutas desde **dentro** de un contenedor de corta duración puede hacer que se pierdan cambios después de recrear el contenedor.
- Monitorizar la **ruta del host** que respalda la capa escribible o el volumen bind-mounted relevante suele ser más útil.
- El FIM de las capas de imagen es diferente del FIM del sistema de archivos del contenedor en ejecución.

## Notas de hunting orientadas al atacante

- Rastrea las **definiciones de servicios** y los **task schedulers** con el mismo cuidado que los binarios. Los atacantes suelen obtener persistence modificando un archivo de unidad, una entrada de cron o un XML de tareas, en lugar de parchear `/bin/sshd`.
- Un hash de contenido por sí solo es insuficiente. Muchas intrusiones aparecen primero como **owner/mode/xattr/ACL drift**.
- Si sospechas de una intrusión madura, haz ambas cosas: **FIM en tiempo real** para detectar actividad reciente y una **comparación de baseline en frío** desde medios confiables.
- Si el atacante tiene root o ejecución en kernel, asume que el agente de FIM, su base de datos e incluso la fuente de eventos pueden haber sido manipulados. Almacena los logs y las baselines de forma remota o en medios de solo lectura siempre que sea posible.

## Herramientas

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## Referencias

- [1] [File Integrity Monitoring with osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux: A file integrity monitoring use case (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring (Syscheck and whodata mode)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

{{#include ../../banners/hacktricks-training.md}}
