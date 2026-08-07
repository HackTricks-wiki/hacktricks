# Linux ptrace exit-race `pidfd_getfd()` FD theft

{{#include ../../../banners/hacktricks-training.md}}

Un **patrón de privesc del kernel de Linux** útil consiste en convertir un **fallo de autorización de `ptrace`** en un **robo de descriptores de archivo** desde un proceso privilegiado.

En el caso de estudio de Qualys sobre `__ptrace_may_access()` (CVE-2026-46333), el atacante provoca una condición de carrera con un **proceso privilegiado que está terminando o eliminando credenciales** y utiliza `pidfd_getfd()` para duplicar un FD en el proceso del atacante.<sup>[[1]](#references)[[2]](#references)</sup>

## Idea principal

`pidfd_getfd()` duplica un descriptor de archivo de otro proceso, pero primero comprueba permisos similares a los de `ptrace` contra el objetivo. Si esa autorización se concede incorrectamente durante una **ventana de desmontaje**, un atacante sin privilegios puede copiar:

- FDs de **archivos sensibles** que ya haya abierto un helper privilegiado
- FDs de **canales IPC autenticados** que ya hayan sido autorizados como root

Esto transforma un fallo de autorización en el kernel en una primitiva muy práctica en userspace.<sup>[[1]](#references)</sup>

## Por qué la primitiva es peligrosa

El ataque **no** necesita un fallo en el propio helper privilegiado. El helper solo necesita mantener temporalmente algo valioso:

- `/etc/shadow`
- `/etc/ssh/*_key`
- una conexión privilegiada a D-Bus / systemd
- cualquier otro secreto ya abierto o canal autorizado

Una vez duplicado en el proceso del atacante, el kernel aplica las operaciones sobre el **FD robado**, no sobre la ruta original ni mediante un nuevo flujo de autenticación.<sup>[[1]](#references)</sup>

## Patrón de explotación

1. Identifica un **binario setuid / setgid / con capacidades de archivo** o un **daemon root** que abra archivos sensibles o mantenga conexiones IPC útiles.
2. Obtén una relación que satisfaga las comprobaciones de políticas de `ptrace` relevantes para la ruta del objetivo (por ejemplo, siendo el **padre** de un proceso hijo privilegiado creado bajo una configuración permisiva de YAMA).
3. Provoca una condición de carrera mientras el proceso está **terminando**, **eliminando credenciales** o entrando de otro modo en un estado en el que el acceso mediante `ptrace` debería haber dejado de estar disponible.
4. Usa `pidfd_open()` + `pidfd_getfd()` para duplicar el FD objetivo durante la estrecha ventana de autorización.
5. Reutiliza el FD robado desde el contexto sin privilegios:
- `read()` secretos desde un descriptor de archivo privilegiado
- envía solicitudes a través de un canal IPC autenticado robado para obtener **acciones del lado de root**<sup>[[1]](#references)</sup>

Forma mínima de la primitiva:<sup>[[1]](#references)[[3]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Objetivos prácticos para auditar

Prioriza los binarios y daemons que, aunque sea brevemente, hagan una de estas cosas:<sup>[[1]](#references)</sup>

- abrir archivos solo para root antes de finalizar las transiciones de privilegios
- conectarse al **system bus** y mantener un canal ya autorizado
- pasar FDs privilegiados entre helpers
- realizar operaciones sensibles para la seguridad durante el teardown adyacente a `do_exit()`

Buenos candidatos para investigar:<sup>[[1]](#references)</sup>

- helpers de gestión de contraseñas / cuentas
- helpers de SSH
- helpers mediados por PolicyKit / D-Bus
- daemons de escritorio ejecutándose como root que expongan métodos D-Bus

## YAMA como exploit gate

`kernel.yama.ptrace_scope` es un control práctico importante frente al abuso de la familia ptrace:<sup>[[4]](#references)</sup>

- `0`: comportamiento clásico de ptrace con el mismo UID
- `1`: normalmente permite el tracing de padre -> hijo, lo que puede mantener accesibles algunas rutas de exploit públicas
- `2`: requiere `CAP_SYS_PTRACE` para el acceso de tipo attach y bloquea el abuso no privilegiado de `pidfd_getfd()` en esta ruta
- `3`: deshabilita por completo el attach de ptrace hasta el reinicio

Para esta técnica, `ptrace_scope=2` es una **mitigación temporal** sólida porque rompe la ruta pública de explotación de `pidfd_getfd()` con `-EPERM` para usuarios no privilegiados.<sup>[[1]](#references)</sup>

## Ideas para la detección / revisión

Al auditar software Linux privilegiado, busca estas combinaciones:

- **proceso hijo privilegiado** + **padre controlado por el atacante**
- acceso temporal a **archivos abiertos valiosos**
- acceso temporal a **canales autenticados de D-Bus/systemd**
- decisiones de seguridad que reutilicen la **autorización de tipo ptrace** fuera del `ptrace(2)` clásico
- APIs del kernel que puedan **duplicar, heredar o volver a exportar** FDs privilegiados existentes

Al auditar el kernel, considera de alto riesgo cualquier ruta que realice una **autorización equivalente a ptrace** durante el **teardown de una task**, especialmente si el éxito proporciona acceso directo a `task->files` u otros recursos de proceso ya autorizados.

## Referencias

- [1] [CVE-2026-46333: Local Root Privilege Escalation and Credential Disclosure in the Linux Kernel ptrace Path (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)

{{#include ../../../banners/hacktricks-training.md}}
