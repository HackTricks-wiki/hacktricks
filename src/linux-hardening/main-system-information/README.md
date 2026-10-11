# Información principal del sistema

{{#include ../../banners/hacktricks-training.md}}

Inspecciona el kernel del host, el sistema de archivos, los auxiliares privilegiados y las vías de escape disponibles antes de elegir una técnica de escalada local. La [lista de verificación de escalada de privilegios](linux-privilege-escalation-checklist.md) ofrece un orden de operaciones compacto.

- [Evaluación de vulnerabilidades del kernel y exposición en tiempo de ejecución](kernel-vulnerability-assessment.md) comprueba la aplicabilidad de la compilación, la accesibilidad y las mitigaciones activas.
- [Módulos del kernel y abuso de modprobe](kernel-modules-and-modprobe.md) cubre la carga de módulos y la exposición de rutas de auxiliares.
- [Abuso de comandos de sudo](sudo-command-abuse.md) examina cómo los comandos delegados pueden cruzar límites de privilegios.
- [Symlinks, hardlinks y descriptores de archivo](filesystem-links-and-file-descriptors.md) cubre la redirección de rutas y los archivos heredados o abiertos y eliminados.
- [Sistema de archivos, inodes y recuperación](filesystem-inodes-and-recovery.md) explica el comportamiento del sistema de archivos que resulta útil durante una investigación.
- [Lista de verificación: escalada de privilegios en Linux](linux-privilege-escalation-checklist.md) enumera comprobaciones del host y enlaces a material más detallado.
- [Escape de jaulas](escaping-from-limited-bash.md) cubre shells limitados y entornos restringidos.
- [Material sobre kernel/LPE/CVE](kernel-lpe-cves/README.md) agrupa análisis detallados sobre vulnerabilidades y escalada local de privilegios.
{{#include ../../banners/hacktricks-training.md}}
