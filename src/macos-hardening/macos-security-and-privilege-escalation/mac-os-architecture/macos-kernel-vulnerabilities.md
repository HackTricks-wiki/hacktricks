# Vulnerabilidades del kernel de macOS

{{#include ../../../banners/hacktricks-training.md}}

La explotación reciente del kernel de macOS se centra menos en "cargar un kext trivial sin firmar y obtener ring-0" y más en abusar de **parsers Mach/MIG**, **IOKit user clients**, **data-only races dentro de XNU** y **daemons con entitlements especiales** que aún pueden volver a abrir la attack surface del kernel. Para hacer reversing de las interfaces concretas, consulta también las páginas sobre [**IOKit**](macos-iokit.md) y [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Attack surfaces que aún importan

- **Handlers Mach/MIG** en system daemons y servicios orientados al kernel: descriptores malformados, datos out-of-line (OOL) y flujos stateful de múltiples mensajes.
- **IOKit user clients**: parsing específico de cada selector, métodos protegidos por entitlements y wrapper libraries/daemons que ocultan el call graph real.
- **Primitivas data-only de XNU**: races alrededor de credenciales, punteros protegidos por SMR, read-only zones y otros lugares donde la corrupción cambia la policy sin obtener primero el control de RIP/PC.
- **Código de kernel de terceros / auxiliar**: los kexts legacy son menos frecuentes, pero las flotas enterprise, los sistemas Apple Silicon con reduced security y los vendor `.fs` / helper bundles aún crean rutas de gran valor adyacentes al kernel.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

En [**este informe**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) se combinan varios bugs de OTA/update-chain para alcanzar el compromiso del kernel abusando del software update pipeline y de las capacidades relacionadas con rootless.

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: cadena de bypass de protecciones del kernel in-the-wild (CVE-2024-23225 y CVE-2024-23296)

Las [**versiones de seguridad de macOS de marzo de 2024**](https://support.apple.com/en-us/120895) de Apple corrigieron dos problemas que fueron **explotados activamente**:

- **CVE-2024-23225 – Kernel**: un bug de memory corruption mediante el cual un atacante con arbitrary kernel read/write podía bypassar las protecciones de memoria del kernel.
- **CVE-2024-23296 – RTKit**: un segundo bug de memory corruption con el mismo public impact statement.

Los detalles públicos de la causa raíz siguen siendo escasos, pero el par es un buen recordatorio de que las exploit chains modernas de Apple a menudo necesitan **algo más que "simplemente" kernel R/W**: el trabajo de post-exploitation contra las protecciones de memoria, el código adyacente a los coprocesadores o los límites de confianza secundarios suele ser donde se estabiliza realmente la chain.

Triage rápido de parches:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + carrera de credenciales de solo lectura (CVE-2025-24118)

El [**write-up de TRAVERTINE**](https://jprx.io/cve-2025-24118/) de Joseph Ravichandran es un muy buen caso práctico moderno de XNU porque **no** se trata de un classic buffer overflow:

- `proc_ro.p_ucred` es un **puntero protegido por SMR** almacenado en un objeto `proc_ro` de **solo lectura**.
- Los escritores deben actualizar ese puntero **atómicamente**.
- `kauth_cred_proc_update()` usaba `zalloc_ro_mut(...)` para modificar `p_ucred`; en x86_64, esa ruta finalmente llega a `memcpy` / `rep movsb`, por lo que un lector concurrente puede observar un puntero **parcialmente actualizado**.
- El bug se convierte en una **escalada de privilegios basada únicamente en datos**: si el puntero de credenciales corrupto apunta a un objeto de credenciales válido diferente, el thread actual puede heredar un estado más privilegiado sin conseguir primero un control-flow hijack evidente.

Patrón mínimo de activación:
```c
// writer thread: force frequent credential swaps
while (1) {
setgid(real_gid);
setgid(saved_or_effective_gid);
}

// reader thread: repeatedly dereference current credentials
while (1) {
(void)getgid();
}
```
Heurística útil de auditoría: siempre que un kernel path mezcle **SMR readers**, **read-only zone mutation** y **credential or task metadata**, verifica que las actualizaciones utilicen las variantes atómicas `zalloc_ro_mut_*` en lugar de helpers basados en copias.

---

## 2024-2025: SIP bypass que vuelve a abrir los kernel loading paths (CVE-2024-44243)

Microsoft mostró que `storagekitd` podía utilizarse para **bypass de SIP** y hacer que el código kernel de terceros volviera a ser relevante en máquinas que, de otro modo, parecerían "post-kext". La idea clave es:

1. Colocar o sobrescribir un bundle `.fs` malicioso en `/Library/Filesystems`.
2. Activar `storagekitd` mediante Disk Utility o `diskutil`.
3. Hacer que el daemon con los privilegios adecuados ejecute los binarios del bundle **sin eliminar correctamente los privilegios ni validar el path**.
4. Utilizar el bypass de SIP resultante para modificar el estado protegido del sistema de archivos y, en la demostración de Microsoft, sobrescribir la lista de exclusión de extensiones del kernel.

Para los investigadores de kernel, la lección importante es que **la attack surface del kernel puede reintroducirse desde daemons de gestión userland**, incluso cuando la carga directa de kexts de terceros está muy restringida.

Triage útil:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Flujo de fuzzing e investigación

Si estás buscando activamente esta clase de bugs, los trabajos públicos recientes apuntan en la misma dirección:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) sigue siendo una de las mejores referencias para la investigación del kernel en la era Apple Silicon. Utiliza **static binary rewriting** para recuperar la cobertura, desactiva las rutas **entitlement-gated** durante las pruebas e infiere la estructura de las interfaces a partir de los wrappers de userspace.
- El artículo de Project Zero [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) muestra un workflow muy práctico para **rebasing de un kext / fileset en userspace**, de modo que el código centrado en parsers pueda someterse a fuzzing a mucha mayor velocidad antes de reproducirlo en el dispositivo.
- Para objetivos centrados en Mach, crea harnesses alrededor de **real message layouts and multi-call state machines**, no solo de blobs de un único selector. Las investigaciones recientes sobre CoreAudio/Mach de Project Zero y charlas de conferencias como **Fuzzing at Mach Speed** muestran por qué las secuencias de mensajes stateful siguen dando buenos resultados.

Comandos locales rápidos que utilizarás mucho en la práctica:
```bash
# Loaded auxiliary / 3rd party kernel code
kmutil showloaded --collection aux

# Fileset entries in the boot kernel collection
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Diffable version info before matching a KDK / symbols pack
sw_vers
uname -a
```
## Chuleta de enumeración rápida
```bash
uname -a                          # Kernel build
sw_vers                           # ProductVersion / BuildVersion
kmutil showloaded                 # List loaded kernel extensions
kmutil showloaded --collection aux  # Auxiliary / 3rd party collections
kextstat 2>/dev/null | grep -v com.apple
csrutil status                    # Check SIP state
spctl --status                    # Confirm Gatekeeper state
```
## Referencias

* Joseph Ravichandran. “TRAVERTINE: CVE-2025-24118.” https://jprx.io/cve-2025-24118/
* Microsoft Security Blog. “Análisis de CVE-2024-44243, un bypass de macOS System Integrity Protection mediante kernel extensions.” https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}
