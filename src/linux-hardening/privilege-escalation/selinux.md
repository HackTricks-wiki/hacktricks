# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux es un sistema **Mandatory Access Control (MAC)** basado en etiquetas. En la práctica, esto significa que incluso si los permisos DAC, los grupos o las capacidades de Linux parecen suficientes para una acción, el kernel aún puede denegarla porque el **source context** no tiene अनुमति para acceder al **target context** con la clase/permiso solicitados.

Un context normalmente se ve así:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Desde la perspectiva de privesc, el `type` (domain para procesos, type para objetos) suele ser el campo más importante:

- Un proceso se ejecuta en un **domain** como `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Los archivos y sockets tienen un **type** como `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- La policy decide si un domain puede leer/escribir/ejecutar/transicionar al otro

## Fast Enumeration

Si SELinux está habilitado, enuméralo temprano porque puede explicar por qué fallan rutas comunes de privesc en Linux o por qué un wrapper privilegiado alrededor de una herramienta SELinux "inofensiva" es en realidad crítico:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Comprobaciones útiles de seguimiento:
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

- El modo `Disabled` o `Permissive` elimina la mayor parte del valor de SELinux como frontera.
- `unconfined_t` normalmente significa que SELinux está presente pero no restringe de forma significativa ese proceso.
- `default_t`, `file_t`, o etiquetas obviamente incorrectas en rutas personalizadas a menudo indican un etiquetado incorrecto o una implementación incompleta.
- Los overrides locales en `file_contexts.local` tienen prioridad sobre los valores predeterminados de la policy, así que revísalos cuidadosamente.

## Policy Analysis

SELinux es mucho más fácil de atacar o bypass cuando puedes responder dos preguntas:

1. **¿A qué puede acceder mi dominio actual?**
2. **¿A qué dominios puedo transicionar?**

Las herramientas más útiles para esto son `sepolicy` y **SETools** (`seinfo`, `sesearch`, `sedta`):
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
Esto es especialmente útil cuando un host usa **confined users** en lugar de mapear a todos a `unconfined_u`. En ese caso, busca:

- asignaciones de usuario mediante `semanage login -l`
- roles permitidos mediante `semanage user -l`
- dominios de administrador alcanzables como `sysadm_t`, `secadm_t`, `webadm_t`
- entradas de `sudoers` que usen `ROLE=` o `TYPE=`

Si `sudo -l` contiene entradas como esta, SELinux forma parte del límite de privilegios:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
También comprueba si `newrole` está disponible:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` y `newrole` no son explotables automáticamente, pero si un wrapper privilegiado o una regla de `sudoers` te permite seleccionar un role/type mejor, se convierten en primitivas de escalada de alto valor.

## Files, Relabeling, and High-Value Misconfigurations

La diferencia operativa más importante entre las herramientas SELinux comunes es:

- `chcon`: cambio temporal de label en una ruta específica
- `semanage fcontext`: regla persistente de ruta-a-label
- `restorecon` / `setfiles`: aplicar de nuevo la policy/label por defecto

Esto importa mucho durante privesc porque **relabeling no es solo cosmético**. Puede convertir un archivo de "bloqueado por policy" en "legible/ejecutable por un servicio confinado privilegiado".

Comprueba reglas locales de relabel y relabel drift:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Un detalle sutil pero útil: `restorecon` a secas **no siempre revierte por completo una etiqueta sospechosa**. Si el tipo objetivo está en `customizable_types`, puede que necesites `-F` para forzar un reinicio completo. Desde una perspectiva ofensiva, esto explica por qué un `chcon` inusual a veces puede sobrevivir a una limpieza superficial de "ya ejecutamos restorecon".
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Comandos de alto valor para buscar en `sudo -l`, root wrappers, scripts de automatización o capacidades de archivo:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Si aparece alguna capacidad MAC, también revisa la [Linux capabilities page](linux-capabilities.md); `cap_mac_admin` y `cap_mac_override` son inusuales pero directamente relevantes cuando SELinux forma parte del boundary.

Especialmente interesante:

- `semanage fcontext`: cambia de forma persistente qué label debe recibir una path
- `restorecon` / `setfiles`: reaplica esos cambios a escala
- `semodule -i`: carga un custom policy module
- `semanage permissive -a <domain_t>`: hace permissive un domain sin cambiar todo el host
- `setsebool -P`: cambia permanentemente policy booleans
- `load_policy`: recarga la active policy

Estas suelen ser **helper primitives**, no root exploits independientes. Su valor es que te permiten:

- hacer permissive un target domain
- ampliar el acceso entre tu domain y un protected type
- relabel files controlados por el atacante para que un privileged service pueda leerlos o ejecutarlos
- debilitar un confined service lo suficiente como para que un existing local bug se vuelva explotable

Example checks:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Si puedes cargar un módulo de política como root, normalmente controlas el límite de SELinux:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Por eso `audit2allow`, `semodule` y `semanage permissive` deben tratarse como superficies administrativas sensibles durante post-exploitation. Pueden convertir silenciosamente una cadena bloqueada en una que funciona sin cambiar los permisos clásicos de UNIX.

## Hidden Denials and Module Extraction

Una frustración ofensiva muy común es una cadena que falla con un simple `EACCES` mientras nunca aparece la denegación AVC esperada. Las reglas `dontaudit` pueden estar ocultando exactamente el permiso que necesitas. Si puedes ejecutar `semodule` mediante `sudo` u otro contenedor privilegiado, desactivar temporalmente `dontaudit` puede convertir un fallo silencioso en una pista precisa de la policy:
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Esto también es útil para revisar qué ya cambiaron los admins locales. Un pequeño custom module o una regla permissive de un solo dominio suele ser la razón por la que un target service se comporta mucho más laxo de lo que sugeriría la base policy.

## Audit Clues

Las denials de AVC suelen ser una señal ofensiva, no solo ruido defensivo. Te dicen:

- qué target object/type golpeaste
- qué permission fue denegada
- qué domain controlas actualmente
- si un pequeño policy change haría que la chain funcione
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Si un local exploit o un intento de persistence sigue fallando con `EACCES` o extraños errores de "permission denied" a pesar de tener permisos DAC que parecen de root, SELinux suele valer la pena revisarlo antes de descartar el vector.

## SELinux Users

Hay usuarios de SELinux además de los usuarios regulares de Linux. Cada usuario de Linux se mapea a un usuario de SELinux como parte de la policy, lo que permite al sistema imponer diferentes roles y domains permitidos sobre distintas cuentas.

Quick checks:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
En muchos sistemas convencionales, los usuarios se asignan a `unconfined_u`, lo que reduce el impacto práctico del confinement de usuarios. En despliegues hardened, sin embargo, los usuarios confined pueden hacer que `sudo`, `su`, `newrole` y `runcon` sean mucho más interesantes porque **la vía de escalation puede depender de entrar en un mejor rol/tipo de SELinux, no solo de convertirse en UID 0**. También recuerda que algunos usuarios confined no pueden invocar `sudo`/`su` en absoluto a menos que la policy permita explícitamente la transición setuid subyacente, así que un host que use `staff_u` + `sysadm_r` puede convertir una regla aparentemente menor de `sudo ROLE=` / `TYPE=` en el verdadero límite de privilegio.

## SELinux in Containers

Los runtimes de containers suelen iniciar cargas de trabajo en un dominio confined como `container_t` y etiquetar el contenido del container como `container_file_t`. Si un proceso del container escapa pero sigue ejecutándose con la etiqueta del container, las escrituras en el host pueden seguir fallando porque el límite de etiquetas se mantuvo intacto.

Quick example:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
La parte `c647,c780` no es decoración. En muchas implementaciones de containers, los runtimes asignan dinámicamente categorías MCS para que dos procesos que se ejecutan como `container_t` sigan estando separados entre sí. Si un escape te deja en un namespace del host pero conserva el conjunto original de categorías, las discrepancias de categorías aún pueden explicar por qué algunas rutas del host siguen siendo ilegibles o no se pueden escribir.

Operaciones modernas de containers que conviene señalar:

- `--security-opt label=disable` puede mover efectivamente la carga de trabajo a un tipo relacionado con containers no confinado, como `spc_t`
- los bind mounts con `:z` / `:Z` activan el relabeling de la ruta del host para uso compartido/privado del container
- un relabeling amplio del contenido del host puede convertirse en un problema de seguridad por sí mismo

Esta página mantiene el contenido de containers corto para evitar duplicación. Para los casos de abuso específicos de containers y ejemplos de runtimes, consulta:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## References

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
- [Managing confined and unconfined users - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)
{{#include ../../banners/hacktricks-training.md}}
