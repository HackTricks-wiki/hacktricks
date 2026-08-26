# Monitorización de la integridad de archivos

{{#include ../../banners/hacktricks-training.md}}

## Línea base

Una línea base consiste en tomar una instantánea de ciertas partes de un sistema para **compararla con un estado futuro y resaltar los cambios**.

Por ejemplo, puedes calcular y almacenar el hash de cada archivo del filesystem para averiguar qué archivos fueron modificados.\
Esto también puede hacerse con las cuentas de usuario creadas, los procesos en ejecución, los servicios activos y cualquier otro elemento que no debería cambiar mucho o no debería cambiar en absoluto.

Una **línea base útil** normalmente almacena más que un simple digest: también vale la pena realizar un seguimiento de los permisos, propietario, grupo, marcas de tiempo, inode, objetivo del symlink, ACLs y atributos extendidos seleccionados.<sup>[[4]](#references)</sup> Desde la perspectiva de la búsqueda de atacantes, esto ayuda a detectar **manipulación limitada a permisos**, **reemplazo atómico de archivos** y **persistencia mediante archivos de servicio/unidad modificados**, incluso cuando el hash del contenido no es lo primero que cambia.

### File Integrity Monitoring

File Integrity Monitoring (FIM) es una técnica de seguridad crítica que protege los entornos de IT y los datos mediante el seguimiento de los cambios en los archivos. Normalmente combina:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Comparación con la línea base:** Almacenar metadatos y checksums criptográficos (preferiblemente `SHA-256` o superior) para comparaciones futuras.
2. **Notificaciones en tiempo real:** Suscribirse a los eventos de archivos nativos del sistema operativo para saber **qué archivo cambió, cuándo y, preferiblemente, qué proceso/usuario lo modificó**.
3. **Re-escaneo periódico:** Recuperar la confianza después de reinicios, eventos descartados, interrupciones del agent o actividad anti-forense deliberada.

Para threat hunting, FIM suele ser más útil cuando se centra en **rutas de alto valor**, como:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- Unidades de `systemd`, ubicaciones de cron, material de SSH, módulos PAM, raíces web
- Ubicaciones de persistencia de Windows, binarios de servicios, archivos de tareas programadas, carpetas de inicio
- Capas escribibles de los contenedores y secrets/configuration montados mediante bind

## Backends en tiempo real y puntos ciegos

### Linux

El backend de recopilación es importante:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: fáciles y comunes, pero los límites de watch pueden agotarse y algunos casos extremos no se detectan.
- **`auditd` / audit framework**: mejor cuando necesitas saber **quién modificó el archivo** (UID de login, ID del proceso y nombre del proceso).
- **`eBPF` / `kprobes`**: opciones más recientes utilizadas por los stacks modernos de FIM para enriquecer los eventos y reducir algunos problemas operativos de las implementaciones basadas únicamente en `inotify`.

Algunos problemas prácticos:<sup>[[1]](#references)[[5]](#references)</sup>

- Si un programa **reemplaza** un archivo mediante `write temp -> rename`, observar el archivo en sí puede dejar de ser útil. **Observa el directorio padre**, no solo el archivo.
- Los collectors basados en `inotify` pueden omitir eventos o degradarse en **árboles de directorios enormes**, durante **actividad con hard links** o después de que se elimine un **archivo observado**.
- Los conjuntos de watch recursivos muy grandes pueden fallar silenciosamente si `fs.inotify.max_user_watches`, `max_user_instances` o `max_queued_events` son demasiado bajos.
- En la monitorización basada en `inotify`, los filesystems de red son un punto ciego porque los cambios remotos no se notifican.

Ejemplo de línea base + verificación con AIDE:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Ejemplo de configuración de FIM de `osquery` centrada en rutas de persistencia del atacante:<sup>[[1]](#references)</sup>
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
Si necesitas **atribución de procesos** en lugar de solo cambios a nivel de ruta, prefiere telemetría respaldada por auditoría, como `osquery` `process_file_events` o el modo `whodata` de Wazuh.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

#### `io_uring`: la telemetría de syscalls no es FIM

En Linux moderno, observar `openat(2)`, `write(2)` u otros puntos de entrada de syscalls **no equivale a monitorizar la operación resultante del sistema de archivos**. La prueba de concepto **Curing** de 2025 puso en cola solicitudes de archivos y red mediante `io_uring`, por lo que los productos o las políticas asociadas únicamente a las entradas de syscall correspondientes por operación perdieron la telemetría del proceso. En las mismas pruebas, un componente FIM con alcance sobre rutas siguió observando las modificaciones de archivos, lo que demuestra que se trata de un **punto ciego en la ubicación del hook**, no de un bypass de permisos ni de una forma de evadir todos los backends de FIM.<sup>[[10]](#references)</sup>

Al validar un sensor, modifica el mismo canary mediante varias rutas: `write` normal, `mmap` + `msync`, `truncate`, `sendfile`/`copy_file_range`, reemplazo atómico e `io_uring`. Comprueba no solo que se detecte el cambio del hash final, sino también si el evento conserva el proceso responsable, el contenedor/cgroup, la ruta visible para el namespace, el inode y el par de renombrado. Un evento en tiempo real ausente seguido de una discrepancia en un escaneo periódico debe tratarse como **pérdida de telemetría**, no como un cambio rutinario sin explicación.<sup>[[10]](#references)[[11]](#references)</sup>

Para la monitorización basada en eBPF, prefiere puntos de enforcement comunes del kernel en lugar de una lista de probes de entrada de syscalls. Por ejemplo, la política de acceso a archivos de Tetragon usa `security_file_permission` para cubrir I/O ordinario, `sendfile`, `copy_file_range`, AIO e `io_uring`; cubre por separado los mapeos de memoria con `security_mmap_file` y los cambios de tamaño con `security_path_truncate`. Esto también ilustra por qué un único hook rara vez ofrece una cobertura completa.<sup>[[11]](#references)</sup>

### Windows

En Windows, FIM es más sólido cuando combinas **change journals** con **telemetría de procesos/archivos de alta señal**:<sup>[[6]](#references)[[7]](#references)</sup>

- **NTFS USN Journal** proporciona un registro persistente por volumen de los cambios en archivos.
- **Sysmon Event ID 11** es útil para detectar la creación/sobrescritura de archivos.
- **Sysmon Event ID 2** ayuda a detectar **timestomping**.
- **Sysmon Event ID 15** es útil para detectar **named alternate data streams (ADS)**, como `Zone.Identifier` o streams de payload ocultos.

Ejemplos rápidos de triaje de USN:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Para consultar ideas más profundas de **Anti-Forensic Techniques** relacionadas con la **manipulación de timestamps**, el **abuso de ADS** y la **manipulación de USN**, revisa [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Contenedores

El FIM de contenedores suele pasar por alto la ruta de escritura real. Con Docker `overlay2`, el sistema de archivos del contenedor combina capas `lowerdir` de imagen de solo lectura con una **capa superior** (`upperdir`/`diff`) editable, y las escrituras en archivos de imagen se copian a esa capa superior.<sup>[[8]](#references)</sup> Por lo tanto:

- Monitorizar únicamente las rutas desde **dentro** de un contenedor de corta duración puede hacer que se pasen por alto los cambios después de recrear el contenedor.
- Monitorizar la **ruta del host** que respalda la capa editable o el volumen relevante montado mediante bind suele ser más útil.
- El FIM en las capas de imagen es diferente del FIM en el sistema de archivos del contenedor en ejecución.

## Notas de Hunting Orientadas al Atacante

- Supervisa las **definiciones de servicios** y los **task schedulers** con el mismo cuidado que los binarios. Los atacantes suelen obtener persistencia modificando un archivo de unidad, una entrada de cron o un XML de tarea, en lugar de parchear `/bin/sshd`.
- Un hash de contenido por sí solo es insuficiente. Muchos compromisos se manifiestan primero como **cambios en propietario/modo/xattr/ACL**.
- Si sospechas de una intrusión avanzada, haz ambas cosas: **FIM en tiempo real** para detectar actividad reciente y una **comparación con una baseline en frío** desde medios de confianza.
- Si el atacante tiene ejecución como root o a nivel de kernel, considera que el agente de FIM y su base de datos no son de confianza. Almacena los logs y las baselines de forma remota o en medios de solo lectura siempre que sea posible.<sup>[[4]](#references)</sup>

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
- [4] [Manual de AIDE, versión 0.16.2](https://aide.github.io/doc/)
- [5] [Página del manual de Linux inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [Controlador de almacenamiento OverlayFS](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Configuración avanzada del FIM de Wazuh](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
- [10] [Bypasses de io_uring Rootkit para herramientas de seguridad de Linux (ARMO)](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/)
- [11] [Acceso a nombres de archivo: rutas síncronas, asíncronas, mapeadas y de truncamiento (Tetragon)](https://tetragon.io/docs/use-cases/filename-access/)
{{#include ../../banners/hacktricks-training.md}}
