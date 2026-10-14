# Material sobre kernel, LPE y CVE

{{#include ../../../banners/hacktricks-training.md}}

Estos estudios de caso abarcan distintas primitivas de escalada local de privilegios. Antes de aplicar una técnica, comprueba el producto o kernel afectado, la configuración y los requisitos previos indicados en cada artículo. Para una enumeración más amplia del host, consulta la [lista de comprobación de escalada de privilegios en Linux](../linux-privilege-escalation-checklist.md).

Para Dirty Pipe (CVE-2022-0847), la [investigación original](https://dirtypipe.cm4all.com/) identifica las correcciones upstream estables en las versiones 5.10.102, 5.15.25 y 5.16.11. Que una versión del kernel pertenezca a un rango afectado anterior solo es un indicio para revisar: las distribuciones pueden incorporar correcciones mediante backports con otros nombres de versión, y el archivo de destino debe poder leerse para usar la primitiva de escritura en la page cache. Sobrescribir un ejecutable SUID legible es una posible vía para obtener privilegios si la transición set-ID sigue siendo efectiva; modificar `/etc/passwd` y luego autenticarse también puede depender de la pila PAM local. Antes de evaluar si el vector es viable, comprueba el paquete del kernel del proveedor instalado, el kernel en ejecución después de reiniciar, los permisos del archivo de destino, la opción de montaje `nosuid` y `no_new_privs`. No ejecutes una prueba de escritura durante la enumeración pasiva. Consulta el [estado específico de cada versión de Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [Detección de servicios de VMware Tools, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): ejecución con privilegios mediante la detección de rutas de procesos no confiables.
- [Sobrescritura de la page cache mediante splice de AF_ALG, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): una vía para sobrescribir la page cache del kernel.
- [Carrera TOCTOU en los temporizadores de CPU POSIX y explotación, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md#root-cause-toctou-between-irq-time-expiry-and-concurrent-deletion-under-task-exit): expiración y eliminación de temporizadores al salir una tarea, incluidos los requisitos previos de la ruta IRQ y la investigación sobre explotación.
- [Carrera de salida de ptrace en Linux y robo de descriptores de archivo mediante `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): acceso a descriptores durante una carrera de salida de procesos.

## Estudios de caso relacionados de Binary Exploitation

La sección Binary Exploitation profundiza en las primitivas de explotación, la disposición de memoria y las formas de evadir mitigaciones para estos objetivos del kernel de Linux:

- [Use-after-free de SKB out-of-band de AF_UNIX](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): un fallo de socket convertido en primitivas de lectura y escritura del kernel.
- [Underflow de scatterlist por escritor concurrente de AF_ALG](../../../binary-exploitation/linux-kernel-exploitation/af-alg-concurrent-writer-scatterlist-oob.md): una carrera del escritor skcipher convertida en una escritura en el kernel.
- [Use-after-free de Futex PI](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): una primitiva de escritura de punteros ampliada mediante buffers de pipe y workqueues.
- [Escritura out-of-bounds en streams de ksmbd, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): explotación del heap del kernel y evasión de mitigaciones.
- [Evasión de KASLR del mapa lineal estático de Arm64](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): descubrimiento de direcciones para la explotación del kernel arm64.
- [Evasión de privilegios de GPU/SMMU Adreno A7xx](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): una vía de GPU en Android para acceder a la memoria del kernel.
- [Use-after-free por timeout de trabajo de Pixel Bigwave](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): un fallo de acelerador de Android usado para escribir en el kernel.
{{#include ../../../banners/hacktricks-training.md}}
