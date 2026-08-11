# Linux ptrace exit-race `pidfd_getfd()` robo de FD

{{#include ../../../banners/hacktricks-training.md}}

Un **patrón útil de privesc del kernel de Linux** consiste en convertir un **fallo de autorización de ptrace** en un **robo de descriptores de archivo** de un proceso privilegiado.

En el caso de estudio de Qualys sobre `__ptrace_may_access()` (CVE-2026-46333), el atacante compite con un **proceso privilegiado que está terminando o eliminando credenciales** y utiliza `pidfd_getfd()` para duplicar un FD en el proceso del atacante.<sup>[[1]](#references)[[2]](#references)</sup>

## Idea principal

`pidfd_getfd()` duplica un descriptor de archivo de otro proceso, pero primero comprueba los permisos de estilo ptrace con respecto al objetivo.<sup>[[3]](#references)</sup> Si esa autorización se concede incorrectamente durante una **ventana de desmontaje**, un atacante sin privilegios puede copiar:

- FDs de **archivos sensibles** ya abiertos por un helper privilegiado
- FDs de **canales IPC autenticados** ya autorizados como root

Esto transforma un fallo de autorización del kernel en una primitiva de userspace muy práctica.<sup>[[1]](#references)</sup>

## Por qué la primitiva es peligrosa

El ataque **no** necesita un fallo en el propio helper privilegiado. El helper solo necesita mantener temporalmente algo valioso:

- `/etc/shadow`
- `/etc/ssh/*_key`
- una conexión privilegiada de D-Bus / systemd
- cualquier otro secreto ya abierto o canal autorizado

Una vez duplicado en el proceso del atacante, el duplicado hace referencia a la misma descripción de archivo abierta, por lo que las lecturas posteriores o las solicitudes IPC utilizan el FD ya abierto en lugar de volver a abrir la ruta original o iniciar un flujo de autenticación nuevo.<sup>[[2]](#references)[[3]](#references)</sup>

## Patrón de explotación

1. Identificar un **binario setuid / setgid / con capacidad de archivo** o un **daemon root** que abra archivos sensibles o mantenga conexiones IPC útiles.<sup>[[2]](#references)</sup>
2. Obtener una relación que satisfaga las comprobaciones de política de ptrace relevantes para la ruta del objetivo (por ejemplo, ser el **padre** de un hijo privilegiado generado bajo una configuración permisiva de YAMA).<sup>[[2]](#references)[[4]](#references)</sup>
3. Competir con el proceso mientras está **terminando**, **eliminando credenciales** o entrando de cualquier otra forma en un estado en el que el acceso mediante ptrace debería haber dejado de estar disponible.<sup>[[2]](#references)</sup>
4. Utilizar `pidfd_open()` + `pidfd_getfd()` para duplicar el FD del objetivo durante la estrecha ventana de autorización.<sup>[[2]](#references)[[3]](#references)[[5]](#references)</sup>
5. Reutilizar el FD robado desde el contexto sin privilegios.<sup>[[2]](#references)</sup>
- `read()` secretos desde un descriptor de archivo privilegiado
- enviar solicitudes a través de un canal IPC autenticado robado para obtener **acciones del lado de root**

Forma mínima de la primitiva.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Objetivos prácticos para auditar

Prioriza los binarios y daemons que, aunque sea brevemente, hagan una de estas cosas:<sup>[[1]](#references)[[2]](#references)</sup>

- abrir archivos exclusivos de root antes de finalizar las transiciones de privilegios
- conectarse al **system bus** y mantener un canal ya autorizado
- pasar FDs privilegiados a través de los límites entre helpers
- realizar tareas sensibles para la seguridad durante el desmantelamiento adyacente a `do_exit()`

Buenos candidatos para hunting:<sup>[[1]](#references)</sup>

- helpers de gestión de contraseñas / cuentas
- helpers de SSH
- helpers mediados por PolicyKit / D-Bus
- daemons de escritorio de root que exponen métodos D-Bus

## YAMA como exploit gate

`kernel.yama.ptrace_scope` es un gate práctico importante para el abuso de la familia ptrace:<sup>[[3]](#references)[[4]](#references)</sup>

- `0`: comportamiento clásico de ptrace para el mismo UID
- `1`: normalmente permite el tracing de padre -> hijo, lo que puede mantener accesibles algunas rutas de exploit públicas
- `2`: requiere `CAP_SYS_PTRACE` para el acceso de tipo attach y bloquea el abuso no privilegiado de `pidfd_getfd()` en esta ruta
- `3`: deshabilita completamente el ptrace attach hasta el reinicio

Para esta técnica, `ptrace_scope=2` es una **mitigación temporal** sólida porque rompe la ruta pública de explotación de `pidfd_getfd()` con `-EPERM` para usuarios no privilegiados.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Ideas para la detección / revisión

Al auditar software Linux privilegiado, busca estas combinaciones:

- **proceso hijo privilegiado** + **proceso padre controlado por el atacante**.<sup>[[2]](#references)[[4]](#references)</sup>
- acceso temporal a **archivos abiertos valiosos**
- acceso temporal a **canales D-Bus/systemd autenticados**.<sup>[[2]](#references)</sup>
- decisiones de seguridad que reutilicen la **autorización de estilo ptrace** fuera del `ptrace(2)` clásico
- APIs del kernel que puedan **duplicar, heredar o volver a exportar** FDs privilegiados existentes

Al auditar el kernel, trata cualquier ruta que realice una **autorización equivalente a ptrace** durante el **desmantelamiento de una task** como de alto riesgo, especialmente si el éxito proporciona acceso directo a `task->files` u otros recursos de proceso ya autorizados.<sup>[[2]](#references)</sup>

## References

- [1] [CVE-2026-46333: Escalada local de privilegios de root y divulgación de credenciales en la ruta ptrace del kernel de Linux (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [TXT del advisory de Qualys](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [Página del manual de pidfd_getfd(2)](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Documentación Yama del kernel de Linux](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [5] [Página del manual de pidfd_open(2)](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
{{#include ../../../banners/hacktricks-training.md}}
