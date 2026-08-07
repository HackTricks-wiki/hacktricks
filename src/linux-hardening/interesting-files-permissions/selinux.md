# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux es un sistema de **Mandatory Access Control (MAC)** basado en etiquetas. En la práctica, esto significa que, aunque los permisos DAC, los grupos o las capacidades de Linux parezcan suficientes para realizar una acción, el kernel aún puede denegarla porque el **contexto de origen** no tiene permitido acceder al **contexto de destino** con la clase/permiso solicitado.

Un contexto normalmente tiene este aspecto:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Desde la perspectiva de privesc, `type` (domain para procesos, type para objetos) suele ser el campo más importante:

- Un proceso se ejecuta en un **domain** como `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Los archivos y sockets tienen un **type** como `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- La policy decide si un domain puede leer/escribir/ejecutar/hacer transition al otro

## Enumeración rápida

Si SELinux está habilitado, enuméralo al principio, ya que puede explicar por qué fallan las rutas comunes de privesc en Linux o por qué un wrapper privilegiado alrededor de una herramienta SELinux aparentemente "inofensiva" es en realidad crítico:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Comprobaciones de seguimiento útiles:
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
Hallazgos interesantes:

- El modo `Disabled` o `Permissive` elimina gran parte del valor de SELinux como límite.
- `unconfined_t` normalmente significa que SELinux está presente, pero no restringe de forma significativa ese proceso.
- `default_t`, `file_t` o etiquetas obviamente incorrectas en rutas personalizadas suelen indicar una etiquetación incorrecta o un despliegue incompleto.
- Los overrides locales en `file_contexts.local` tienen prioridad sobre los valores predeterminados de la policy, así que revísalos cuidadosamente.

## Análisis de la Policy

SELinux es mucho más fácil de atacar o evadir cuando puedes responder a dos preguntas:

1. **¿A qué puede acceder mi dominio actual?**
2. **¿A qué dominios puedo hacer transition?**

Las herramientas más útiles para esto son `sepolicy` y **SETools** (`seinfo`, `sesearch`, `sedta`):<sup>[[2]](#references)</sup>
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
Esto es especialmente útil cuando un host utiliza **usuarios confinados** en lugar de asignar a todos a `unconfined_u`. En ese caso, busca:<sup>[[3]](#references)</sup>

- asignaciones de usuarios mediante `semanage login -l`
- roles permitidos mediante `semanage user -l`
- dominios administrativos accesibles, como `sysadm_t`, `secadm_t`, `webadm_t`
- entradas de `sudoers` que utilizan `ROLE=` o `TYPE=`

Si `sudo -l` contiene entradas como esta, SELinux forma parte del límite de privilegios:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Comprueba también si `newrole` está disponible:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` y `newrole` no son explotables automáticamente, pero si un wrapper privilegiado o una regla de `sudoers` permite seleccionar un rol/tipo más privilegiado, se convierten en primitivas de escalada de privilegios de gran valor.

## Archivos, relabeling y configuraciones incorrectas de gran valor

La diferencia operativa más importante entre las herramientas comunes de SELinux es:<sup>[[1]](#references)</sup>

- `chcon`: cambio temporal de etiqueta en una ruta específica
- `semanage fcontext`: regla persistente de ruta a etiqueta
- `restorecon` / `setfiles`: vuelve a aplicar la etiqueta de la policy/predeterminada

Esto importa mucho durante el privesc porque **el relabeling no es solo algo cosmético**. Puede convertir un archivo que estaba "bloqueado por la policy" en uno "legible/ejecutable por un servicio confinado privilegiado".

Busca reglas locales de relabeling y desviaciones de relabeling:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Un detalle sutil pero útil: `restorecon` sin opciones **no siempre revierte por completo una etiqueta sospechosa**. Si el tipo objetivo se encuentra en `customizable_types`, puede ser necesario usar `-F` para forzar un restablecimiento completo. Desde una perspectiva ofensiva, esto explica por qué un `chcon` inusual a veces puede sobrevivir a una limpieza superficial de "ya ejecutamos restorecon".
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Comandos de alto valor para buscar en `sudo -l`, wrappers de root, scripts de automatización o capacidades de archivos:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Si aparece cualquiera de las capacidades MAC, consulta también la [página de Linux capabilities](linux-capabilities.md); `cap_mac_admin` y `cap_mac_override` son inusuales, pero directamente relevantes cuando SELinux forma parte del límite de seguridad.

Especialmente interesantes:

- `semanage fcontext`: cambia de forma persistente qué etiqueta debe recibir una ruta
- `restorecon` / `setfiles`: reaplica esos cambios a gran escala
- `semodule -i`: carga un módulo de policy personalizado
- `semanage permissive -a <domain_t>`: hace que un dominio sea permissive sin cambiar todo el host
- `setsebool -P`: cambia permanentemente los booleanos de policy
- `load_policy`: recarga la policy activa

A menudo son **helper primitives**, no exploits de root independientes. Su valor es que permiten:

- hacer que un dominio objetivo sea permissive
- ampliar el acceso entre tu dominio y un tipo protegido
- cambiar las etiquetas de archivos controlados por el atacante para que un servicio privilegiado pueda leerlos o ejecutarlos
- debilitar un servicio confinado lo suficiente como para que un bug local existente sea explotable

Comprobaciones de ejemplo:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Si puedes cargar un módulo de políticas como root, normalmente controlas el límite de SELinux:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Por eso, `audit2allow`, `semodule` y `semanage permissive` deben tratarse como superficies administrativas sensibles durante el post-exploitation. Pueden convertir silenciosamente una cadena bloqueada en una funcional sin cambiar los permisos clásicos de UNIX.

## Denegaciones ocultas y extracción de módulos

Una frustración ofensiva muy común es una cadena que falla con un `EACCES` insípido mientras la denegación AVC esperada nunca aparece. Las reglas `dontaudit` pueden estar ocultando el permiso exacto que necesitas. Si puedes ejecutar `semodule` mediante `sudo` u otro wrapper privilegiado, deshabilitar temporalmente `dontaudit` puede convertir un fallo silencioso en una pista precisa de la policy:<sup>[[4]](#references)</sup>
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Esto también es útil para revisar lo que los administradores locales ya han cambiado. Un módulo personalizado pequeño o una regla permisiva para un solo dominio suele ser la razón por la que un servicio objetivo se comporta de forma mucho más permisiva de lo que sugeriría la policy base.

## Indicadores de auditoría

Las denegaciones AVC suelen ser una señal ofensiva, no solo ruido defensivo. Te indican:

- qué objeto/tipo objetivo alcanzaste
- qué permiso fue denegado
- qué dominio controlas actualmente
- si un pequeño cambio en la policy haría que la cadena funcionara
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Si un exploit local o un intento de persistencia sigue fallando con `EACCES` o errores extraños de «permission denied» a pesar de contar con permisos DAC que parecen propios de root, normalmente conviene comprobar SELinux antes de descartar el vector.

## Usuarios de SELinux

Además de los usuarios normales de Linux, existen usuarios de SELinux. Cada usuario de Linux se asigna a un usuario de SELinux como parte de la policy, lo que permite al sistema imponer diferentes roles y dominios permitidos en distintas cuentas.<sup>[[3]](#references)</sup>

Comprobaciones rápidas:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
En muchos sistemas convencionales, los usuarios están asignados a `unconfined_u`, lo que reduce el impacto práctico del confinamiento de usuarios. Sin embargo, en implementaciones reforzadas, los usuarios confinados pueden hacer que `sudo`, `su`, `newrole` y `runcon` sean mucho más interesantes, porque **la ruta de escalada puede depender de entrar en un rol/tipo de SELinux más privilegiado, no solo de convertirse en UID 0**. También hay que recordar que algunos usuarios confinados no pueden ejecutar `sudo`/`su` en absoluto, a menos que la policy permita explícitamente la transición setuid subyacente; por tanto, un host que utilice `staff_u` + `sysadm_r` puede convertir una regla aparentemente menor `sudo ROLE=` / `TYPE=` en el verdadero límite de privilegios.<sup>[[3]](#references)</sup>

## SELinux en Containers

Los runtimes de containers suelen iniciar las cargas de trabajo en un dominio confinado como `container_t` y etiquetar el contenido del container como `container_file_t`. Si un proceso del container escapa, pero sigue ejecutándose con la etiqueta del container, las escrituras en el host aún pueden fallar porque el límite de etiquetas se mantuvo intacto.

Ejemplo rápido:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
La parte `c647,c780` no es decorativa. En muchos despliegues de contenedores, los runtimes asignan dinámicamente categorías MCS para que dos procesos que se ejecutan como `container_t` sigan estando separados entre sí. Si un escape te lleva a un namespace del host pero conserva el conjunto de categorías original, las discrepancias entre categorías aún pueden explicar por qué algunas rutas del host siguen siendo ilegibles o no se pueden modificar.

Operaciones modernas de contenedores que conviene tener en cuenta:

- `--security-opt label=disable` puede trasladar efectivamente la carga de trabajo a un tipo relacionado con contenedores sin restricciones, como `spc_t`
- los bind mounts con `:z` / `:Z` activan el relabeling de la ruta del host para uso compartido/privado por contenedores
- un relabeling amplio del contenido del host puede convertirse en un problema de seguridad por sí mismo

Esta página mantiene breve el contenido sobre contenedores para evitar duplicaciones. Para consultar los casos de abuso específicos de contenedores y ejemplos de runtimes, revisa:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## Referencias

- [1] [Documentación de Red Hat: Uso de SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: Herramientas de análisis de políticas para SELinux](https://github.com/SELinuxProject/setools)
- [3] [Gestión de usuarios confinados y sin restricciones - Documentación de RHEL 9](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - Página del manual de Linux](https://man7.org/linux/man-pages/man8/semodule.8.html)

{{#include ../../banners/hacktricks-training.md}}
