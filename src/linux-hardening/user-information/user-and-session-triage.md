# Usuarios, sesiones y artefactos de credenciales

{{#include ../../banners/hacktricks-training.md}}

Empieza por la identidad propietaria del shell actual y, luego, enumera otros usuarios, grupos, sesiones activas y almacenes de credenciales. La página sobre el [ID de usuario real, efectivo y guardado](euid-ruid-suid.md) explica por qué los privilegios efectivos de un proceso pueden diferir de su cuenta de inicio de sesión.

## Enumerar identidades y acceso basado en grupos

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` incluye cuentas respaldadas por directorio que una lectura simple de `/etc/passwd` puede pasar por alto. Revisa las cuentas con UID 0, los shells de inicio de sesión, los directorios personales, los grupos suplementarios y las cuentas cuya configuración permite inesperadamente el inicio de sesión interactivo. La página [interesting groups](interesting-groups-linux-pe/README.md) trata el acceso delegado, como `sudo`, `docker`, `disk` y `shadow`. Comprueba las ACL reales del sistema de archivos y la política local antes de considerar que un nombre de grupo implica privilegios.

Si [NSS asigna las consultas de `passwd`, `group` o `shadow`](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) a una base de datos, revisa el proveedor activo y su ruta de configuración antes de evaluar las identidades respaldadas por esa base de datos. En implementaciones de NSS con PostgreSQL, `/etc/nss-pgsql.conf` y `/etc/nss-pgsql-root.conf` son pistas que solo indican rutas, porque la configuración de conexión puede contener credenciales. Un rol de base de datos solo importa si puede modificar registros que el proveedor activo de NSS realmente devuelve y una cuenta puede autenticarse con ellos. Un GID primario de 0 otorga pertenencia al grupo root, no UID 0; una asignación al grupo sudo requiere una [regla de grupo efectiva en sudoers](https://man7.org/linux/man-pages/man5/sudoers.5.html) y cualquier autenticación requerida. Una asignación de UID 0 constituye un límite de identidad distinto. No muestres cadenas de conexión ni modifiques registros de cuentas durante la enumeración pasiva.

Compara también los UID numéricos entre nombres de cuentas locales. Dos nombres en [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) pueden referirse a la misma identidad de archivo de Unix, aunque sus registros de autenticación de inicio de sesión sean distintos. Por lo tanto, un alias agregado recientemente con un UID no nulo compartido puede dar acceso a los archivos o procesos de otro usuario tras una autenticación exitosa; no otorga acceso root, a menos que ese UID u otra vía de privilegios lo permita. Los UID compartidos pueden ser intencionales. Verifica el origen de la cuenta (`/etc/passwd` frente a NSS), el historial de creación, el shell y el directorio personal, la política de autenticación efectiva y si las cuentas están autorizadas a compartir la identidad. Una comprobación limitada a cuentas locales no puede descartar un alias respaldado por directorio.

## Buscar sesiones activas y recientes

```bash
who -a
w
last -a | head
loginctl list-sessions 2>/dev/null
ps -eo user,pid,ppid,tty,cmd --sort=user | head -80
screen -ls 2>/dev/null
tmux ls 2>/dev/null
```

Un socket de `screen` o `tmux` puede exponer un shell existente si sus permisos permiten que el usuario actual se conecte. Comprueba el propietario y el modo del socket antes de intentar acceder; la sesión de otro usuario no se puede conectar automáticamente. Una marca de tiempo activa de `sudo` o un socket de SSH agent también pueden ser relevantes, pero su reutilización depende de la identidad del usuario, los permisos y la política. Para el abuso de agent forwarding, consulta [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md).

Un [socket de control multiplex de OpenSSH](https://man.openbsd.org/ssh_config#ControlMaster) es independiente de `SSH_AUTH_SOCK`: `ControlMaster` y `ControlPath` permiten que clientes SSH posteriores compartan una conexión autenticada existente, mientras que `ControlPersist` puede mantener disponible el master después de que termine la primera sesión. Inspecciona el `.ssh/config` del usuario actual y las rutas de sockets dentro de `.ssh`, incluidos el propietario y los permisos. El nombre de un socket por sí solo no demuestra que el master esté activo, que el usuario actual pueda conectarse ni qué cuenta remota utiliza.

## Revisar artefactos de usuario

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

El historial de shell, los archivos de inicio, las claves SSH, la configuración de aplicaciones, los llaveros de GPG y las cachés de Kerberos pueden revelar credenciales o puntos de persistencia con permisos de escritura. Conviene revisar un archivo `authorized_keys` o de inicio de shell con permisos de escritura que pertenezca a una cuenta con más privilegios. La [página de post-explotación](../post-exploitation/README.md) explica la reubicación del homedir de GPG y la búsqueda de credenciales; [Linux Active Directory](linux-active-directory.md) explica la reutilización de cachés de Kerberos y keytabs. La [página de PAM](../software-information/pam-pluggable-authentication-modules.md) explica los riesgos de las políticas de autenticación.
{{#include ../../banners/hacktricks-training.md}}
