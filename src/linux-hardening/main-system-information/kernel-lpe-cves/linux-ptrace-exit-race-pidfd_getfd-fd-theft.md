# Linux ptrace exit-race `pidfd_getfd()` FD theft

{{#include ../../../banners/hacktricks-training.md}}

Un patrón útil de **privesc del kernel de Linux** consiste en convertir un **bug de autorización de `ptrace`** en un **robo de file descriptors** de un proceso privilegiado.

En el caso de estudio de Qualys sobre `__ptrace_may_access()` (CVE-2026-46333), el atacante provoca una race contra un **proceso privilegiado que está terminando o eliminando credenciales** y utiliza `pidfd_getfd()` para duplicar un FD en el proceso del atacante.

## Core idea

`pidfd_getfd()` duplica un file descriptor de otro proceso, pero primero comprueba los permisos de estilo `ptrace` contra el target. Si esa autorización se concede incorrectamente durante una **ventana de teardown**, un atacante sin privilegios puede copiar:

- FDs de **archivos sensibles** ya abiertos por un helper privilegiado
- FDs de **canales IPC autenticados** ya autorizados como root

Esto transforma un bug de autorización del kernel en una primitiva muy práctica en userspace.

## Why the primitive is dangerous

El ataque **no** necesita un bug en el helper privilegiado. El helper solo necesita mantener temporalmente algo valioso:

- `/etc/shadow`
- `/etc/ssh/*_key`
- una conexión privilegiada de D-Bus / systemd
- cualquier otro secreto ya abierto o canal autorizado

Una vez duplicado en el proceso del atacante, el kernel aplica las operaciones sobre el **FD robado**, no sobre el pathname original ni mediante un flujo de autenticación nuevo.

## Exploitation pattern

1. Identificar un **binario setuid / setgid / con file-capability** o un **daemon root** que abra archivos sensibles o mantenga conexiones IPC útiles.
2. Obtener una relación que satisfaga las comprobaciones relevantes de la política de `ptrace` para el target (por ejemplo, ser el **padre** de un child privilegiado creado bajo una configuración permisiva de YAMA).
3. Provocar una race contra el proceso mientras está **terminando**, **eliminando credenciales** o entrando de cualquier otra forma en un estado en el que el acceso mediante `ptrace` debería haber dejado de estar disponible.
4. Utilizar `pidfd_open()` + `pidfd_getfd()` para duplicar el FD del target durante la estrecha ventana de autorización.
5. Reutilizar el FD robado desde el contexto sin privilegios:
- usar `read()` para leer secretos desde un file descriptor privilegiado
- enviar solicitudes a través de un canal IPC autenticado robado para obtener **acciones del lado de root**

Forma mínima de la primitiva:
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Objetivos prácticos para auditar

Prioriza los binarios y daemons que, aunque sea brevemente, hagan alguna de estas cosas:

- abrir archivos solo para root antes de finalizar las transiciones de privilegios
- conectarse al **system bus** y mantener un canal ya autorizado
- pasar FDs privilegiados entre helpers
- realizar tareas sensibles para la seguridad durante un teardown adyacente a `do_exit()`

Buenos candidatos para investigar:

- helpers de gestión de contraseñas / cuentas
- helpers de SSH
- helpers mediados por PolicyKit / D-Bus
- daemons de escritorio root que expongan métodos D-Bus

## YAMA como barrera de exploit

`kernel.yama.ptrace_scope` es una barrera práctica importante contra el abuso de la familia ptrace:

- `0`: comportamiento clásico de ptrace para el mismo UID
- `1`: normalmente permite el tracing de padre -> hijo, lo que puede mantener accesibles algunas rutas públicas de exploit
- `2`: requiere `CAP_SYS_PTRACE` para el acceso mediante attach y bloquea el abuso de `pidfd_getfd()` por parte de usuarios sin privilegios en esta ruta
- `3`: deshabilita completamente el ptrace attach hasta el reinicio

Para esta técnica, `ptrace_scope=2` es una **mitigación temporal** sólida porque rompe la ruta pública de explotación de `pidfd_getfd()` con `-EPERM` para usuarios sin privilegios.

## Ideas para la detección / revisión

Al auditar software Linux privilegiado, busca estas combinaciones:

- **proceso hijo privilegiado** + **padre controlado por el atacante**
- acceso temporal a **archivos abiertos valiosos**
- acceso temporal a **canales D-Bus/systemd autenticados**
- decisiones de seguridad que reutilizan la **autorización de estilo ptrace** fuera del `ptrace(2)` clásico
- APIs del kernel que puedan **duplicar, heredar o volver a exportar** FDs privilegiados existentes

Al auditar el kernel, considera de alto riesgo cualquier ruta que realice una **autorización equivalente a ptrace** durante el **teardown de una task**, especialmente si el éxito proporciona acceso directo a `task->files` u otros recursos de proceso ya autorizados.

## Referencias

- [Qualys blog: CVE-2026-46333](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)

{{#include ../../../banners/hacktricks-training.md}}
