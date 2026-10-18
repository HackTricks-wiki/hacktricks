# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux es un sistema de **control de acceso obligatorio (MAC) basado en etiquetas**. En la práctica, esto significa que, aunque los permisos DAC, los grupos o las capacidades de Linux parezcan suficientes para realizar una acción, el kernel aún puede denegarla porque el **contexto de origen** no tiene permitido acceder al **contexto de destino** con la clase o el permiso solicitados.<sup>[[1]](#references)</sup>

Un contexto suele tener este aspecto:<sup>[[1]](#references)</sup>

```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

Desde la perspectiva de privesc, `type` (dominio para los procesos, tipo para los objetos) suele ser el campo más importante:<sup>[[1]](#references)</sup>

- Un proceso se ejecuta en un **dominio** como `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Los archivos y sockets tienen un **tipo** como `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- La policy determina si un dominio puede leer, escribir, ejecutar o hacer una transición al otro

## Enumeración rápida

Si SELinux está habilitado, enuméralo pronto, ya que puede explicar por qué fallan las rutas habituales de privesc en Linux o por qué un wrapper privilegiado alrededor de una herramienta SELinux «inofensiva» es en realidad crítico:<sup>[[1]](#references)</sup>

```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```

Comprobaciones útiles de seguimiento:<sup>[[1]](#references)[[3]](#references)[[4]](#references)[[7]](#references)[[12]](#references)</sup>

```bash
# Installed policy modules and local customizations
semodule -lfull 2>/dev/null
semanage fcontext -C -l 2>/dev/null
semanage permissive -l 2>/dev/null
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null

# Labels that frequently reveal mistakes or unusual paths
find / -context '*:default_t:*' -o -context '*:file_t:*' 2>/dev/null

# Compare current label vs policy default for a path
matchpathcon -V /path/of/interest 2>/dev/null
restorecon -n -v /path/of/interest 2>/dev/null
```

Hallazgos interesantes:<sup>[[1]](#references)[[3]](#references)[[7]](#references)[[19]](#references)</sup>

- El modo `Disabled` o `Permissive` elimina gran parte del valor de SELinux como límite.
- `unconfined_t` suele indicar que SELinux está presente, pero que no restringe de forma significativa ese proceso.
- `default_t`, `file_t` o etiquetas claramente incorrectas en rutas personalizadas suelen indicar etiquetas incorrectas o una implementación incompleta.
- Las anulaciones locales en `file_contexts.local` tienen prioridad sobre los valores predeterminados de la policy, así que revísalas cuidadosamente.

## Análisis de la policy

SELinux es mucho más fácil de atacar o evadir cuando puedes responder dos preguntas:

1. **¿A qué puede acceder mi dominio actual?**
2. **¿A qué dominios puedo cambiar?**

Las herramientas más útiles para esto son `sepolicy` y **SETools** (`seinfo`, `sesearch`, `sedta`):<sup>[[2]](#references)[[9]](#references)</sup>

```bash
# Transition graph from the current domain
sepolicy transition -s "$(id -Z | awk -F: '{print $3}')" 2>/dev/null

# Search allow and type_transition rules
sesearch -A -s staff_t 2>/dev/null | head
sesearch --type_transition -s staff_t 2>/dev/null | head

# Inspect policy components
seinfo -t 2>/dev/null | head
seinfo -r 2>/dev/null | head
```

Esto resulta especialmente útil cuando un host usa **usuarios confinados** en lugar de asignar a todos `unconfined_u`. En ese caso, busca:<sup>[[3]](#references)</sup>

- asignaciones de usuarios mediante `semanage login -l`
- roles permitidos mediante `semanage user -l`
- dominios de administración accesibles, como `sysadm_t`, `secadm_t`, `webadm_t`
- entradas de `sudoers` que usan `ROLE=` o `TYPE=`

Si `sudo -l` contiene entradas como esta, SELinux forma parte del límite de privilegios:<sup>[[3]](#references)</sup>

```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```

Comprueba también si `newrole` está disponible:<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
sudo -l
which newrole runcon
newrole -V 2>/dev/null
```

`runcon` y `newrole` no son explotables automáticamente, pero si un wrapper privilegiado o una regla de `sudoers` te permite seleccionar un role/type más útil, se convierten en primitivas de escalada de alto valor.<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

### Auditar los puntos de entrada de transición con permisos de escritura

Un grafo de transiciones es solo una pista sobre la policy. Para convertirlo en una ruta de ataque, identifica el tipo de ejecutable que permite entrar en un domain más útil y, a continuación, comprueba si puedes modificar un ejecutable con esa etiqueta o sustituirlo a través de su directorio padre.<sup>[[9]](#references)[[20]](#references)</sup> Una transición `execve` automática requiere una regla `type_transition` aplicable, acceso de ejecución desde el source domain, acceso `entrypoint` al target domain y permiso para realizar la transición entre los domains.<sup>[[20]](#references)</sup> El target domain puede obtener acceso de SELinux, pero la ejecución no cambia por sí sola el UID de Linux; comprueba [SUID/SGID y ACLs](suid-sgid-and-acl-triage.md) por separado.<sup>[[20]](#references)[[21]](#references)</sup>

Usa el tipo de entrypoint indicado para comprobar las reglas subyacentes y, luego, inspecciona la ruta y su directorio padre para verificar si tienen permisos de escritura.<sup>[[9]](#references)[[20]](#references)[[22]](#references)</sup>

```bash
src=$(id -Z | cut -d: -f3)
sepolicy transition -s "$src"                 # Note target domain and entrypoint type
dst=target_t                                   # Substitute a domain from the report
entry=target_exec_t                            # Substitute its entrypoint type
sesearch -T -s "$src" -t "$entry" -c process
sesearch --allow -s "$src" -t "$dst" -c process -p transition
sesearch --allow -s "$src" -t "$entry" -c file -p execute
sesearch --allow -s "$dst" -t "$entry" -c file -p entrypoint
sesearch --allow -s "$src" -t "$entry" -c file -p write
ls -lZ /path/to/entrypoint
namei -l /path/to/entrypoint
getfacl -p /path/to/entrypoint
getfacl -p /path/to
```

Correlaciona el tipo de entrypoint con una ruta ejecutable real. Inspecciona DAC, las ACL, los permisos de escritura de SELinux sobre el archivo o el directorio padre, la etiqueta del archivo y cualquier booleano condicional antes de considerar alcanzable una arista de la política.<sup>[[20]](#references)[[22]](#references)</sup> Si se reemplaza una ruta en lugar de editarla en el mismo lugar, verifica el contexto del nuevo inode: las etiquetas del sistema de archivos se almacenan como atributos extendidos, y es posible que el reemplazo no conserve el tipo de entrypoint.<sup>[[21]](#references)</sup> Los programas compatibles con SELinux pueden solicitar una transición con `setexeccon`, por lo que la ausencia de una regla automática `type_transition` no descarta todas las transiciones.<sup>[[20]](#references)</sup>

## Archivos, cambio de etiquetas y configuraciones incorrectas de alto valor

La diferencia operativa más importante entre las herramientas comunes de SELinux es:<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`: cambio temporal de etiqueta en una ruta específica
- `semanage fcontext`: regla persistente de ruta a etiqueta
- `restorecon` / `setfiles`: vuelve a aplicar la etiqueta predeterminada/de la política

Esto importa mucho durante el privesc porque **cambiar etiquetas no es solo algo cosmético**. Puede convertir un archivo de «bloqueado por la política» en «legible/ejecutable por un servicio confinado con privilegios».<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Busca reglas locales de cambio de etiquetas y desviaciones de etiquetado:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```

Un detalle sutil pero útil: `restorecon` sin opciones **no siempre revierte por completo una etiqueta sospechosa**. Si el tipo de destino está en `customizable_types`, quizá necesites `-F` para forzar un restablecimiento completo. Desde una perspectiva ofensiva, esto explica por qué un `chcon` inusual a veces puede persistir tras una limpieza superficial de «ya ejecutamos restorecon».<sup>[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```

Comandos de alto valor que buscar en `sudo -l`, wrappers de root, scripts de automatización o capacidades de archivo:<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```

Si aparece cualquiera de las capacidades MAC, consulta también la [página de capacidades de Linux](linux-capabilities.md); la documentación de capacidades de Linux describe `cap_mac_admin` y `cap_mac_override` como específicas de Smack, así que no des por hecho que sus nombres bastan para eludir SELinux.<sup>[[5]](#references)</sup>

Especialmente interesantes:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`: cambia de forma persistente la etiqueta que debe recibir una ruta
- `restorecon` / `setfiles`: vuelve a aplicar esos cambios a gran escala
- `semodule -i`: carga un módulo de policy personalizado
- `semanage permissive -a <domain_t>`: pone un domain en modo permisivo sin cambiar todo el host
- `setsebool -P`: cambia de forma permanente los booleanos de policy
- `load_policy`: vuelve a cargar la policy activa

A menudo son **primitivas auxiliares**, no exploits de root independientes. Su utilidad consiste en permitirte:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- poner un domain objetivo en modo permisivo
- ampliar el acceso entre tu domain y un tipo protegido
- cambiar las etiquetas de archivos controlados por el atacante para que un servicio privilegiado pueda leerlos o ejecutarlos
- debilitar un servicio confinado lo suficiente como para que un bug local existente pueda explotarse

Comprobaciones de ejemplo:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```

Si puedes cargar un módulo de políticas como root, normalmente controlas el límite de SELinux:<sup>[[1]](#references)[[4]](#references)[[14]](#references)</sup>

```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```

Por eso, `audit2allow`, `semodule` y `semanage permissive` deben tratarse como superficies administrativas sensibles durante el post-exploitation. Pueden convertir silenciosamente una cadena bloqueada en una funcional sin cambiar los permisos UNIX clásicos.<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## Denegaciones ocultas y extracción de módulos

Una frustración ofensiva muy común es que una cadena falle con un `EACCES` genérico mientras que la denegación AVC esperada nunca aparece. Las reglas `dontaudit` pueden estar ocultando el permiso exacto que necesitas. Si puedes ejecutar `semodule` mediante `sudo` u otro wrapper privilegiado, deshabilitar temporalmente `dontaudit` puede convertir un fallo silencioso en una pista precisa sobre la política:<sup>[[4]](#references)[[15]](#references)</sup>

```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```

Esto también resulta útil para revisar qué han cambiado ya los administradores locales. Un pequeño módulo personalizado o una regla permisiva para un solo dominio suele ser la razón por la que un servicio objetivo se comporta de forma mucho más permisiva de lo que sugeriría la política base.<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Pistas de auditoría

Las denegaciones AVC suelen ser una señal ofensiva, no solo ruido defensivo. Te indican:<sup>[[1]](#references)[[15]](#references)</sup>

- a qué objeto/tipo objetivo has accedido
- qué permiso se ha denegado
- qué dominio controlas actualmente
- si un pequeño cambio en la política permitiría que la cadena funcionara

```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```

Si un exploit local o un intento de persistencia sigue fallando con `EACCES` o errores extraños de «permiso denegado» a pesar de tener permisos DAC que parecen de root, suele valer la pena comprobar SELinux antes de descartar el vector.<sup>[[1]](#references)</sup>

## Usuarios de SELinux

Además de los usuarios habituales de Linux, existen usuarios de SELinux. Cada usuario de Linux se asigna a un usuario de SELinux como parte de la política, lo que permite al sistema imponer distintos roles y dominios permitidos para cada cuenta.<sup>[[3]](#references)</sup>

Comprobaciones rápidas:<sup>[[3]](#references)</sup>

```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```

En muchos sistemas convencionales, los usuarios se asignan a `unconfined_u`, lo que reduce el impacto práctico del confinamiento de usuarios. Sin embargo, en implementaciones reforzadas, los usuarios confinados pueden hacer que `sudo`, `su`, `newrole` y `runcon` sean mucho más interesantes, porque **la ruta de escalada puede depender de entrar en un rol/tipo de SELinux con más privilegios, no solo de convertirse en UID 0**. También recuerda que algunos usuarios confinados no pueden ejecutar `sudo`/`su` a menos que la política permita explícitamente la transición subyacente de setuid, por lo que un host que use `staff_u` + `sysadm_r` puede convertir una regla aparentemente menor de `sudo ROLE=` / `TYPE=` en el verdadero límite de privilegios.<sup>[[3]](#references)</sup>

## SELinux en contenedores

Los runtimes de contenedores suelen iniciar cargas de trabajo en un dominio confinado como `container_t` y etiquetar el contenido del contenedor como `container_file_t`. Si un proceso del contenedor escapa, pero sigue ejecutándose con la etiqueta del contenedor, las escrituras en el host pueden seguir fallando porque el límite de etiquetas se mantuvo intacto.<sup>[[1]](#references)[[17]](#references)</sup>

Ejemplo rápido:<sup>[[16]](#references)[[18]](#references)</sup>

```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```

La parte `c647,c780` no es decorativa. En muchos despliegues de contenedores, los runtimes asignan dinámicamente categorías MCS para que dos procesos que se ejecutan como `container_t` sigan estando separados entre sí. Si un escape te lleva a un namespace del host, pero conserva el conjunto de categorías original, las discrepancias entre categorías aún pueden explicar por qué algunas rutas del host siguen siendo ilegibles o no se pueden modificar.<sup>[[17]](#references)</sup>

Operaciones modernas con contenedores que conviene tener en cuenta:<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable` desactiva la separación de etiquetas SELinux para el contenedor
- Los bind mounts con `:z` / `:Z` activan el cambio de etiquetas de la ruta del host para el uso compartido o privado con contenedores
- El cambio amplio de etiquetas del contenido del host puede convertirse en un problema de seguridad por sí solo

Esta página mantiene breve el contenido sobre contenedores para evitar duplicaciones. Para consultar los casos de abuso específicos de contenedores y ejemplos de runtimes, revisa:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}



## References

- [1] [Documentación de Red Hat: Uso de SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: Herramientas de análisis de políticas para SELinux](https://github.com/SELinuxProject/setools)
- [3] [Gestión de usuarios confinados y no confinados: documentación de RHEL 9](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - página del manual de Linux](https://man7.org/linux/man-pages/man8/semodule.8.html)
- [5] [capabilities(7) - página del manual de Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [6] [chcon(1) - página del manual de Linux](https://man7.org/linux/man-pages/man1/chcon.1.html)
- [7] [semanage-fcontext(8) - página del manual de Linux](https://man7.org/linux/man-pages/man8/semanage-fcontext.8.html)
- [8] [restorecon(8) - página del manual de Linux](https://man7.org/linux/man-pages/man8/restorecon.8.html)
- [9] [sepolicy-transition(8) - página del manual de Linux](https://man7.org/linux/man-pages/man8/sepolicy-transition.8.html)
- [10] [runcon(1) - página del manual de Linux](https://man7.org/linux/man-pages/man1/runcon.1.html)
- [11] [newrole(1) - página del manual de Linux](https://man7.org/linux/man-pages/man1/newrole.1.html)
- [12] [semanage-permissive(8) - página del manual de Linux](https://man7.org/linux/man-pages/man8/semanage-permissive.8.html)
- [13] [setsebool(8) - página del manual de Linux](https://man7.org/linux/man-pages/man8/setsebool.8.html)
- [14] [audit2allow(1) - página del manual de Linux](https://man7.org/linux/man-pages/man1/audit2allow.1.html)
- [15] [ausearch(8) - página del manual de Linux](https://man7.org/linux/man-pages/man8/ausearch.8.html)
- [16] [Documentación de ejecución de Podman](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [17] [Por qué deberías usar Multi-Category Security en tus contenedores Linux](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Documentación de podman top](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) - página del manual de Linux](https://man7.org/linux/man-pages/man8/selinux.8.html)
- [20] [Cuaderno de SELinux: Transiciones de dominio y objetos](https://github.com/SELinuxProject/selinux-notebook/blob/main/src/domain_object_transitions.md)
- [21] [Red Hat Enterprise Linux 10: Uso de SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html-single/using_selinux/using_selinux)
- [22] [Manual de SETools sesearch(1)](https://manpages.debian.org/testing/setools/sesearch.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
