# Material sobre Kernel, LPE y CVE

{{#include ../../../banners/hacktricks-training.md}}

Estos estudios de caso abarcan distintas primitivas de escalada de privilegios local. Antes de aplicar una técnica, comprueba en cada artículo el producto o kernel afectado, la configuración y los requisitos previos. Para una enumeration más amplia del host, usa la [lista de comprobación de escalada de privilegios en Linux](../linux-privilege-escalation-checklist.md).

Para Dirty Pipe (CVE-2022-0847), la [investigación original](https://dirtypipe.cm4all.com/) identifica las correcciones upstream estables en las versiones 5.10.102, 5.15.25 y 5.16.11. Una versión del kernel dentro de un rango antiguo afectado solo es un indicio que conviene revisar: las distribuciones pueden integrar correcciones en versiones con otros nombres, y el archivo de destino debe ser legible para que funcione la primitiva de escritura en la page cache. Sobrescribir un ejecutable SUID legible es una posible vía de escalada de privilegios si la transición de set-ID sigue siendo efectiva; modificar `/etc/passwd` y luego autenticarse también puede depender de la pila PAM local. Antes de evaluar si el vector es alcanzable, comprueba el paquete del kernel del proveedor instalado, el kernel en ejecución tras reiniciar, los permisos del destino, el montaje `nosuid` y `no_new_privs`. No realices una prueba de escritura durante la enumeration pasiva. Consulta el [estado específico de cada versión de Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [Descubrimiento del servicio VMware Tools, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): ejecución privilegiada mediante el descubrimiento de rutas de procesos no confiables.
- [Sobrescritura de la page cache mediante splice en AF_ALG, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): una vía de sobrescritura de la page cache del kernel.
- [TOCTOU de los temporizadores de CPU POSIX, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): una race en la gestión de temporizadores.
- [Race de salida de Linux ptrace y robo de descriptores de archivo mediante `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): acceso a descriptores durante una race de salida de un proceso.

## Estudios de caso relacionados de Binary Exploitation

La sección Binary Exploitation profundiza en las primitivas de explotación, la disposición de la memoria y las técnicas para eludir mitigaciones en estos objetivos del kernel de Linux:

- [Use-after-free de SKB fuera de banda en AF_UNIX](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): un fallo de socket convertido en primitivas de lectura y escritura del kernel.
- [Underflow de scatterlist por escritor concurrente en AF_ALG](../../../binary-exploitation/linux-kernel-exploitation/af-alg-concurrent-writer-scatterlist-oob.md): una race entre escritores de skcipher convertida en una escritura en el kernel.
- [Use-after-free de Futex PI](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): una primitiva de escritura de punteros extendida mediante buffers de pipe y workqueues.
- [Escritura fuera de límites en streams de ksmbd, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): explotación del heap del kernel y técnicas para eludir mitigaciones.
- [TOCTOU de los temporizadores de CPU POSIX, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): el análisis desde Binary Exploitation de la race de temporizadores resumida arriba.
- [Elusión de KASLR mediante el mapa lineal estático de Arm64](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): descubrimiento de direcciones para la explotación del kernel arm64.
- [Elusión de privilegios de GPU/SMMU en Adreno A7xx](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): una vía de GPU de Android para acceder a la memoria del kernel.
- [Use-after-free por timeout de trabajo en Pixel Bigwave](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): un fallo de acelerador de Android utilizado para escribir en el kernel.
{{#include ../../../banners/hacktricks-training.md}}
