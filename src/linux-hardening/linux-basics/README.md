# Conceptos básicos de Linux

{{#include ../../banners/hacktricks-training.md}}

Este es el punto de partida para evaluar hosts Linux. Las páginas abarcan un flujo de trabajo amplio para la escalada de privilegios, comandos prácticos, variables de entorno y restricciones comunes que afectan a lo que se puede ejecutar en un host.

- [Escalada de privilegios en Linux](linux-privilege-escalation/README.md) explica la enumeración y las posibles vías de escalada local. Para una lista de tareas más breve, consulta la [lista de comprobación para la escalada de privilegios](../main-system-information/linux-privilege-escalation-checklist.md).
- [Inicio de shell, alias e historial](shell-startup-aliases-and-history.md) explica la resolución de comandos, la ejecución de archivos de inicio y las pistas que deja el historial.
- [Comandos útiles de Linux](useful-linux-commands.md) reúne comandos para inspeccionar archivos, procesos, servicios y el entorno.
- [Variables de entorno de Linux](linux-environment-variables.md) explica cómo los valores del entorno afectan a la ejecución y dónde pueden aparecer valores confidenciales.
- [Eludir las restricciones de Linux](bypass-linux-restrictions/README.md) trata sobre shells y entornos de ejecución restringidos, incluidas las protecciones del sistema de archivos, `noexec` y los sistemas distroless.

## Explotación nativa de binarios

Cuando una evaluación conduce a un ejecutable Linux vulnerable, consulta el material pertinente de Binary Exploitation:

- [Formato ELF y comportamiento del cargador](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) y [protecciones de binarios y técnicas para eludirlas](../../binary-exploitation/common-binary-protections-and-bypasses/README.md) explican la estructura del ejecutable y las mitigaciones.
- [Explotación de la pila](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) y [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md) tratan los ataques de flujo de control.
- [Explotación del heap de Libc](../../binary-exploitation/libc-heap/README.md) y [cadenas de formato](../../binary-exploitation/format-strings/README.md) tratan otras vías comunes de corrupción de memoria.

Los estudios de caso específicos del kernel están enlazados desde el material sobre [Kernel/LPE/CVE](../main-system-information/kernel-lpe-cves/README.md).
{{#include ../../banners/hacktricks-training.md}}
