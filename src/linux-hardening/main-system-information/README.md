# Información principal del sistema

{{#include ../../banners/hacktricks-training.md}}

Inspecciona el kernel del host, el sistema de archivos, los helpers privilegiados y las vías de escape disponibles antes de elegir una técnica de escalada local. La [lista de comprobación de escalada de privilegios](linux-privilege-escalation-checklist.md) ofrece un orden de operaciones conciso.

- [Evaluación de vulnerabilidades del kernel y exposición en tiempo de ejecución](kernel-vulnerability-assessment.md) comprueba la aplicabilidad de las compilaciones, la accesibilidad y las mitigaciones activas.
- [Módulos del kernel y abuso de modprobe](kernel-modules-and-modprobe.md) abarca la carga de módulos y la exposición de rutas de helpers.
- [Abuso de comandos de sudo](sudo-command-abuse.md) examina cómo los comandos delegados pueden cruzar límites de privilegios.
- [Symlinks, hardlinks y descriptores de archivo](filesystem-links-and-file-descriptors.md) abarca la redirección de rutas y los archivos heredados o abiertos y eliminados.
- [Sistema de archivos, inodes y recuperación](filesystem-inodes-and-recovery.md) explica el comportamiento del sistema de archivos útil durante una investigación.
- [Lista de comprobación: escalada de privilegios en Linux](linux-privilege-escalation-checklist.md) enumera comprobaciones del host y enlaza a material más detallado.
- [Escapar de entornos aislados](escaping-from-limited-bash.md) abarca shells limitados y entornos restringidos.
- [Material sobre Kernel/LPE/CVE](kernel-lpe-cves/README.md) reúne análisis detallados de escalada local de privilegios y vulnerabilidades.
{{#include ../../banners/hacktricks-training.md}}
