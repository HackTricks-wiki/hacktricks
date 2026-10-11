# Material sobre kernel, LPE y CVE

{{#include ../../../banners/hacktricks-training.md}}

Estos estudios de caso cubren distintas primitivas de escalada local de privilegios. Antes de aplicar una técnica, comprueba el producto o kernel afectado, la configuración y los requisitos previos que se indican en cada artículo. Para una enumeración más amplia del host, consulta la [lista de comprobación de escalada de privilegios en Linux](../linux-privilege-escalation-checklist.md).

Para Dirty Pipe (CVE-2022-0847), la [investigación original](https://dirtypipe.cm4all.com/) identifica correcciones upstream stable en las versiones 5.10.102, 5.15.25 y 5.16.11. Que la versión del kernel esté dentro de un rango antiguo afectado solo es un indicio para revisar: las distribuciones pueden aplicar backports de las correcciones con nombres de versión distintos, y el archivo de destino pertinente debe ser legible para que funcione la primitiva de escritura en page-cache. Sobrescribir un ejecutable SUID legible es una posible vía de escalada de privilegios si la transición set-ID sigue siendo efectiva; modificar `/etc/passwd` y luego autenticarse también puede depender de la pila PAM local. Antes de evaluar si el ataque es viable, comprueba el paquete del kernel del proveedor instalado, el kernel en ejecución después de reiniciar, los permisos del destino, la opción de montaje `nosuid` y `no_new_privs`. No realices una prueba de escritura durante la enumeración pasiva. Consulta el [estado específico de cada versión de Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [VMware Tools service discovery, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): ejecución con privilegios mediante la búsqueda de rutas de procesos no confiables.
- [AF_ALG splice page-cache overwrite, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): una vía de sobrescritura de page-cache del kernel.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): una condición de carrera en la gestión de temporizadores.
- [Linux ptrace exit race and `pidfd_getfd` file-descriptor theft](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): acceso a descriptores durante una condición de carrera al finalizar un proceso.

## Estudios de caso relacionados con la explotación de binarios

La sección Binary Exploitation profundiza en las primitivas de exploit, el diseño de memoria y la evasión de mitigaciones para estos objetivos del kernel de Linux:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): un fallo de socket convertido en primitivas de lectura y escritura del kernel.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): una primitiva de escritura de punteros ampliada mediante búferes de pipe y workqueues.
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): explotación del heap del kernel y evasión de mitigaciones.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): el análisis de la condición de carrera desde la perspectiva de la explotación de binarios, también resumido arriba.
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): descubrimiento de direcciones para la explotación del kernel arm64.
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): una vía de acceso a la memoria del kernel a través de una GPU Android.
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): un fallo de un acelerador Android utilizado para escribir en el kernel.
{{#include ../../../banners/hacktricks-training.md}}
