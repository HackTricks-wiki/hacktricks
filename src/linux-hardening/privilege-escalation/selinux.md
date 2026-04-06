# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux es un sistema de **Control de Acceso Obligatorio (MAC) basado en etiquetas**. En la práctica, esto significa que incluso si los permisos DAC, los grupos o las capacidades de Linux parecen suficientes para una acción, el kernel aún puede denegarla porque el **contexto de origen** no tiene permitido acceder al **contexto de destino** con la clase/permiso solicitado.

Un contexto suele verse así:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Desde la perspectiva de privesc, el `type` (dominio para procesos, tipo para objetos) suele ser el campo más importante:

- Un proceso se ejecuta en un **dominio** como `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Los archivos y sockets tienen un **tipo** como `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- La política determina si un dominio puede leer/escribir/ejecutar/transicionar a otro

## Enumeración rápida

Si SELinux está habilitado, enuméralo temprano porque puede explicar por qué rutas comunes de privesc en Linux fallan o por qué un wrapper privilegiado alrededor de una herramienta SELinux "inofensiva" es en realidad crítico:
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

- `Disabled` or `Permissive` mode removes most of the value of SELinux as a boundary.
- `unconfined_t` usually means SELinux is present but not meaningfully constraining that process.
- `default_t`, `file_t`, or obviously wrong labels on custom paths often indicate mislabeling or incomplete deployment.
- Local overrides in `file_contexts.local` take precedence over policy defaults, so review them carefully.

## Análisis de la política

SELinux es mucho más fácil de atacar o eludir cuando puedes responder dos preguntas:

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
Esto es especialmente útil cuando un host usa **usuarios confinados** en lugar de mapear a todos a `unconfined_u`. En ese caso, busca:

- mapeos de usuarios mediante `semanage login -l`
- roles permitidos mediante `semanage user -l`
- dominios administrativos alcanzables como `sysadm_t`, `secadm_t`, `webadm_t`
- entradas en `sudoers` que usan `ROLE=` o `TYPE=`

Si `sudo -l` contiene entradas como estas, SELinux forma parte del límite de privilegios:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
También comprueba si `newrole` está disponible:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` y `newrole` no son explotables automáticamente, pero si un wrapper privilegiado o una regla de `sudoers` te permite seleccionar un mejor rol/tipo, se convierten en primitivas de escalada de alto valor.

## Archivos, re-etiquetado y malas configuraciones de alto valor

La diferencia operativa más importante entre las herramientas comunes de SELinux es:

- `chcon`: cambio de etiqueta temporal en una ruta específica
- `semanage fcontext`: regla persistente que asigna una etiqueta a una ruta
- `restorecon` / `setfiles`: vuelven a aplicar la etiqueta por defecto según la política

Esto importa mucho durante privesc porque **el re-etiquetado no es solo cosmético**. Puede convertir un archivo de "bloqueado por la política" a "legible/ejecutable por un servicio confinado privilegiado".

Comprueba reglas locales de re-etiquetado y desviaciones en el re-etiquetado:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Comandos de alto valor para buscar en `sudo -l`, wrappers con privilegios root, scripts de automatización o file capabilities:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Especialmente interesantes:

- `semanage fcontext`: cambia de forma persistente qué etiqueta debería recibir una ruta
- `restorecon` / `setfiles`: vuelve a aplicar esos cambios a escala
- `semodule -i`: carga un módulo de política personalizado
- `semanage permissive -a <domain_t>`: convierte un dominio en permissive sin afectar todo el host
- `setsebool -P`: cambia de forma permanente los booleanos de la política
- `load_policy`: recarga la política activa

Estos suelen ser **helper primitives**, no root exploits independientes. Su valor es que te permiten:

- hacer que un dominio objetivo sea permissive
- ampliar el acceso entre tu dominio y un tipo protegido
- reetiquetar archivos controlados por el atacante para que un servicio privilegiado pueda leerlos o ejecutarlos
- debilitar un servicio confinado lo suficiente como para que una vulnerabilidad local existente se vuelva explotable

Comprobaciones de ejemplo:
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
That is why `audit2allow`, `semodule`, and `semanage permissive` should be treated as sensitive admin surfaces during post-exploitation. They can silently convert a blocked chain into a working one without changing classic UNIX permissions.

## Pistas de auditoría

Las denegaciones AVC suelen ser una señal ofensiva, no solo ruido defensivo. Te indican:

- qué objeto/tipo objetivo alcanzaste
- qué permiso fue denegado
- qué dominio controlas actualmente
- si un pequeño cambio en la política permitiría que la cadena funcionara
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Si un exploit local o un intento de persistencia sigue fallando con `EACCES` o extraños errores de "permission denied" a pesar de permisos DAC que parecen de root, normalmente vale la pena comprobar SELinux antes de descartar el vector.

## Usuarios de SELinux

Además de los usuarios normales de Linux, existen usuarios de SELinux. Cada usuario de Linux se asigna a un usuario de SELinux como parte de la política, lo que permite al sistema imponer diferentes roles y dominios permitidos en distintas cuentas.

Comprobaciones rápidas:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
```
En muchos sistemas convencionales, los usuarios se mapean a `unconfined_u`, lo que reduce el impacto práctico del confinamiento de usuarios. Sin embargo, en entornos reforzados, los usuarios confinados pueden hacer que `sudo`, `su`, `newrole`, y `runcon` sean mucho más interesantes porque **la ruta de escalada puede depender de entrar en un mejor rol/tipo de SELinux, no solo de convertirse en UID 0**.

## SELinux en contenedores

Los runtimes de contenedores comúnmente lanzan cargas de trabajo en un dominio confinado como `container_t` y etiquetan el contenido del contenedor como `container_file_t`. Si un proceso de contenedor escapa pero todavía se ejecuta con la etiqueta del contenedor, las escrituras al host pueden seguir fallando porque el límite de etiquetas se mantuvo intacto.

Ejemplo rápido:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Operaciones modernas de contenedores a tener en cuenta:

- `--security-opt label=disable` puede mover efectivamente la carga de trabajo a un tipo relacionado con contenedores no confinado como `spc_t`
- bind mounts con `:z` / `:Z` desencadenan el relabeling de la ruta del host para uso compartido/privado por el contenedor
- un relabeling amplio del contenido del host puede convertirse por sí mismo en un problema de seguridad

Esta página mantiene el contenido sobre contenedores breve para evitar duplicación. Para los casos de abuso específicos de contenedores y ejemplos en tiempo de ejecución, consulta:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## Referencias

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
{{#include ../../banners/hacktricks-training.md}}
