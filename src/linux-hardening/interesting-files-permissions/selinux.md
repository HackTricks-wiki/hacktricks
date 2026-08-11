# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux es un sistema de **control de acceso obligatorio (MAC) basado en etiquetas**. En la práctica, esto significa que, aunque los permisos DAC, los grupos o las capabilities de Linux parezcan suficientes para realizar una acción, el kernel aún puede denegarla porque no se permite que el **contexto de origen** acceda al **contexto de destino** con la clase/permiso solicitado.<sup>[[1]](#references)</sup>

Un contexto suele tener este aspecto:<sup>[[1]](#references)</sup>
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Desde la perspectiva de privesc, el `type` (domain para procesos, type para objetos) suele ser el campo más importante:<sup>[[1]](#references)</sup>

- Un proceso se ejecuta en un **domain** como `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Los archivos y sockets tienen un **type** como `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- La policy decide si un domain puede leer/escribir/ejecutar/hacer transition al otro

## Enumeración rápida

Si SELinux está habilitado, enuméralo pronto porque puede explicar por qué fallan las rutas comunes de privesc de Linux o por qué un wrapper privilegiado alrededor de una herramienta de SELinux "inofensiva" es en realidad crítico:<sup>[[1]](#references)</sup>
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Comprobaciones de seguimiento útiles:<sup>[[1]](#references)[[3]](#references)[[4]](#references)[[7]](#references)[[12]](#references)</sup>
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

- Los modos `Disabled` o `Permissive` eliminan la mayor parte del valor de SELinux como límite.
- `unconfined_t` normalmente significa que SELinux está presente, pero no restringe de forma significativa ese proceso.
- `default_t`, `file_t` o etiquetas obviamente incorrectas en rutas personalizadas suelen indicar un etiquetado incorrecto o un despliegue incompleto.
- Los overrides locales en `file_contexts.local` tienen prioridad sobre los valores predeterminados de la policy, así que revísalos cuidadosamente.

## Análisis de la policy

SELinux es mucho más fácil de atacar o evadir cuando puedes responder a dos preguntas:

1. **¿A qué puede acceder mi dominio actual?**
2. **¿A qué dominios puedo hacer transition?**

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
Esto es especialmente útil cuando un host utiliza **usuarios confinados** en lugar de asignar a todos a `unconfined_u`. En ese caso, busca:<sup>[[3]](#references)</sup>

- asignaciones de usuarios mediante `semanage login -l`
- roles permitidos mediante `semanage user -l`
- dominios administrativos accesibles, como `sysadm_t`, `secadm_t`, `webadm_t`
- entradas de `sudoers` que utilizan `ROLE=` o `TYPE=`

Si `sudo -l` contiene entradas como esta, SELinux forma parte del límite de privilegios:<sup>[[3]](#references)</sup>
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
También comprueba si `newrole` está disponible:<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` y `newrole` no son explotables automáticamente, pero si un wrapper privilegiado o una regla de `sudoers` permite seleccionar un rol/tipo mejor, se convierten en primitives de escalada de alto valor.<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

## Files, Relabeling, and High-Value Misconfigurations

La diferencia operativa más importante entre las herramientas comunes de SELinux es:<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`: cambio temporal de etiqueta en una ruta específica
- `semanage fcontext`: regla persistente de ruta a etiqueta
- `restorecon` / `setfiles`: aplicar de nuevo la etiqueta definida por la policy/default

Esto es muy importante durante el privesc porque **relabeling no es solo algo cosmético**. Puede convertir un archivo de estar "bloqueado por la policy" a ser "legible/ejecutable por un servicio confinado privilegiado".<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Comprueba las reglas locales de relabeling y la desviación de etiquetas:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Un detalle sutil pero útil: `restorecon` simple **no siempre revierte por completo una etiqueta sospechosa**. Si el tipo de destino está en `customizable_types`, es posible que necesites `-F` para forzar un restablecimiento completo. Desde una perspectiva ofensiva, esto explica por qué un `chcon` inusual a veces puede sobrevivir a una limpieza superficial de "ya ejecutamos restorecon".<sup>[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Comandos de alto valor que buscar en `sudo -l`, wrappers de root, scripts de automatización o capacidades de archivos:<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Si aparece cualquiera de las dos capacidades MAC, consulta también la [página de Linux capabilities](linux-capabilities.md); la documentación de Linux capabilities describe `cap_mac_admin` y `cap_mac_override` como específicos de Smack, así que no asumas que sus nombres por sí solos permiten eludir SELinux.<sup>[[5]](#references)</sup>

Especialmente interesantes:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`: cambia de forma persistente la etiqueta que debe recibir una ruta
- `restorecon` / `setfiles`: reaplica esos cambios a escala
- `semodule -i`: carga un módulo de policy personalizado
- `semanage permissive -a <domain_t>`: hace que un dominio sea permissive sin cambiar todo el host
- `setsebool -P`: cambia permanentemente los booleanos de policy
- `load_policy`: recarga la policy activa

A menudo son **helper primitives**, no root exploits independientes. Su valor es que permiten:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- hacer que un dominio objetivo sea permissive
- ampliar el acceso entre tu dominio y un tipo protegido
- cambiar las etiquetas de archivos controlados por el atacante para que un servicio privilegiado pueda leerlos o ejecutarlos
- debilitar un servicio confinado lo suficiente como para que un bug local existente sea explotable

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

Una frustración ofensiva muy común es una cadena que falla con un `EACCES` genérico mientras que la denegación AVC esperada nunca aparece. Las reglas `dontaudit` pueden estar ocultando exactamente el permiso que necesitas. Si puedes ejecutar `semodule` mediante `sudo` u otro wrapper privilegiado, deshabilitar temporalmente `dontaudit` puede convertir un fallo silencioso en una pista precisa de la policy:<sup>[[4]](#references)[[15]](#references)</sup>
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Esto también resulta útil para revisar lo que los administradores locales ya cambiaron. Un módulo personalizado pequeño o una regla `permissive` para un solo dominio suele ser la razón por la que un servicio objetivo se comporta de forma mucho más permisiva de lo que sugeriría la policy base.<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Pistas de auditoría

Las denegaciones de AVC suelen ser una señal ofensiva, no solo ruido defensivo. Te indican:<sup>[[1]](#references)[[15]](#references)</sup>

- qué objeto/tipo objetivo alcanzaste
- qué permiso fue denegado
- qué dominio controlas actualmente
- si un pequeño cambio en la policy haría que la cadena funcionara
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Si un exploit local o un intento de persistence sigue fallando con `EACCES` o errores extraños de "permission denied" a pesar de que los permisos DAC parecen propios de root, normalmente conviene comprobar SELinux antes de descartar el vector.<sup>[[1]](#references)</sup>

## Usuarios de SELinux

Además de los usuarios normales de Linux, existen usuarios de SELinux. Cada usuario de Linux se asigna a un usuario de SELinux como parte de la policy, lo que permite al sistema imponer diferentes roles y dominios permitidos en distintas cuentas.<sup>[[3]](#references)</sup>

Comprobaciones rápidas:<sup>[[3]](#references)</sup>
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
En muchos sistemas convencionales, los usuarios se asignan a `unconfined_u`, lo que reduce el impacto práctico del confinamiento de usuarios. Sin embargo, en despliegues reforzados, los usuarios confinados pueden hacer que `sudo`, `su`, `newrole` y `runcon` sean mucho más interesantes, porque **la ruta de escalada puede depender de entrar en un rol/tipo SELinux más privilegiado, no solo de convertirse en UID 0**. Recuerda también que algunos usuarios confinados no pueden invocar `sudo`/`su` en absoluto, a menos que la policy permita explícitamente la transición setuid subyacente, por lo que un host que utilice `staff_u` + `sysadm_r` puede convertir una regla aparentemente menor `sudo ROLE=` / `TYPE=` en el verdadero límite de privilegios.<sup>[[3]](#references)</sup>

## SELinux en Contenedores

Los runtimes de contenedores suelen iniciar las cargas de trabajo en un dominio confinado como `container_t` y etiquetar el contenido del contenedor como `container_file_t`. Si un proceso del contenedor escapa, pero sigue ejecutándose con la etiqueta del contenedor, las escrituras en el host pueden seguir fallando porque el límite de etiquetas se mantuvo intacto.<sup>[[1]](#references)[[17]](#references)</sup>

Ejemplo rápido:<sup>[[16]](#references)[[18]](#references)</sup>
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
La parte `c647,c780` no es decorativa. En muchos despliegues de containers, los runtimes asignan dinámicamente categorías MCS para que dos procesos que se ejecutan como `container_t` sigan estando separados entre sí. Si un escape te lleva a un host namespace pero conserva el conjunto de categorías original, las incompatibilidades entre categorías aún pueden explicar por qué algunas rutas del host siguen sin poder leerse o escribirse.<sup>[[17]](#references)</sup>

Operaciones modernas con containers que conviene tener en cuenta:<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable` desactiva la separación de labels de SELinux para el container
- los bind mounts con `:z` / `:Z` activan el relabeling de la ruta del host para el uso compartido/privado por parte del container
- un relabeling amplio del contenido del host puede convertirse por sí mismo en un problema de seguridad

Esta página mantiene breve el contenido sobre containers para evitar duplicaciones. Para consultar los casos de abuse específicos de containers y ejemplos de runtimes, revisa:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## References

- [1] [Documentación de Red Hat: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: Herramientas de análisis de policies para SELinux](https://github.com/SELinuxProject/setools)
- [3] [Gestión de usuarios confinados y no confinados - Documentación de RHEL 9](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - Página del manual de Linux](https://man7.org/linux/man-pages/man8/semodule.8.html)
- [5] [capabilities(7) - Página del manual de Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [6] [chcon(1) - Página del manual de Linux](https://man7.org/linux/man-pages/man1/chcon.1.html)
- [7] [semanage-fcontext(8) - Página del manual de Linux](https://man7.org/linux/man-pages/man8/semanage-fcontext.8.html)
- [8] [restorecon(8) - Página del manual de Linux](https://man7.org/linux/man-pages/man8/restorecon.8.html)
- [9] [sepolicy-transition(8) - Página del manual de Linux](https://man7.org/linux/man-pages/man8/sepolicy-transition.8.html)
- [10] [runcon(1) - Página del manual de Linux](https://man7.org/linux/man-pages/man1/runcon.1.html)
- [11] [newrole(1) - Página del manual de Linux](https://man7.org/linux/man-pages/man1/newrole.1.html)
- [12] [semanage-permissive(8) - Página del manual de Linux](https://man7.org/linux/man-pages/man8/semanage-permissive.8.html)
- [13] [setsebool(8) - Página del manual de Linux](https://man7.org/linux/man-pages/man8/setsebool.8.html)
- [14] [audit2allow(1) - Página del manual de Linux](https://man7.org/linux/man-pages/man1/audit2allow.1.html)
- [15] [ausearch(8) - Página del manual de Linux](https://man7.org/linux/man-pages/man8/ausearch.8.html)
- [16] [Documentación de Podman run](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [17] [Por qué deberías usar Multi-Category Security para tus containers Linux](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Documentación de Podman top](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) - Página del manual de Linux](https://man7.org/linux/man-pages/man8/selinux.8.html)
{{#include ../../banners/hacktricks-training.md}}
