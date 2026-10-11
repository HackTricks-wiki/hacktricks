# Conceptos básicos de Linux

{{#include ../../banners/hacktricks-training.md}}

Este es el punto de partida para evaluar hosts Linux. Las páginas cubren un flujo de trabajo amplio de escalada de privilegios, comandos prácticos, variables de entorno y restricciones comunes que afectan lo que se puede ejecutar en un host.

- [Escalada de privilegios en Linux](linux-privilege-escalation/README.md) explica la enumeración y las posibles vías de escalada local. Para una lista de tareas más breve, usa la [lista de verificación de escalada de privilegios](../main-system-information/linux-privilege-escalation-checklist.md).
- [Inicio del shell, alias e historial](shell-startup-aliases-and-history.md) explica la resolución de comandos, la ejecución de archivos de inicio y las pistas del historial.
- [Comandos útiles de Linux](useful-linux-commands.md) recopila comandos para inspeccionar archivos, procesos, servicios y el entorno.
- [Variables de entorno de Linux](linux-environment-variables.md) explica cómo afectan los valores del entorno a la ejecución y dónde pueden aparecer valores sensibles.
- [Eludir restricciones de Linux](bypass-linux-restrictions/README.md) trata los shells restringidos y los entornos de ejecución, incluidas las protecciones del sistema de archivos, `noexec` y los sistemas distroless.

## Explotación de binarios nativos

Cuando una evaluación lleva a un ejecutable vulnerable de Linux, consulta el material pertinente de Binary Exploitation:

- [Formato ELF y comportamiento del loader](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) y [protecciones de binarios y formas de eludirlas](../../binary-exploitation/common-binary-protections-and-bypasses/README.md) explican la estructura del ejecutable y las mitigaciones.
- [Explotación de stack](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) y [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md) cubren los ataques de flujo de control.
- [Explotación del heap de Libc](../../binary-exploitation/libc-heap/README.md) y [format strings](../../binary-exploitation/format-strings/README.md) cubren otras vías comunes de corrupción de memoria.

Los estudios de caso específicos del kernel están enlazados desde [material sobre Kernel/LPE/CVE](../main-system-information/kernel-lpe-cves/README.md).
{{#include ../../banners/hacktricks-training.md}}
