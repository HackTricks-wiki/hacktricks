# Vulnerabilidades del kernel de macOS

{{#include ../../../banners/hacktricks-training.md}}

La explotación reciente del kernel de macOS consiste menos en «cargar un kext trivial sin firmar y obtener ring-0» y más en abusar de **parsers de Mach/MIG**, **user clients de IOKit**, **races de solo datos dentro de XNU** y **daemons con entitlements especiales** que todavía pueden volver a abrir la attack surface del kernel. Para hacer reversing de las interfaces concretas, consulta también las páginas sobre [**IOKit**](macos-iokit.md) y [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Attack surfaces que siguen siendo relevantes

- **Handlers de Mach/MIG** en daemons del sistema y servicios orientados al kernel: descriptores malformados, datos out-of-line (OOL) y flujos con múltiples mensajes que mantienen estado.
- **User clients de IOKit**: parsing específico de cada selector, métodos protegidos por entitlements y wrapper libraries/daemons que ocultan el call graph real.
- **Primitives data-only de XNU**: races alrededor de credenciales, punteros protegidos por SMR, read-only zones y otros lugares donde la corrupción cambia la policy sin obtener primero el control de RIP/PC.
- **Código de kernel de terceros / auxiliar**: los kexts legacy son menos habituales, pero las flotas enterprise, los sistemas Apple Silicon con seguridad reducida y los bundles `.fs` / helper de vendors todavía crean paths de alto valor adyacentes al kernel.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

En [**este informe**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) se combinan varios bugs de OTA/update-chain para alcanzar el compromiso del kernel mediante el abuso del software update pipeline y de las capacidades relacionadas con rootless.<sup>[[3]](#references)</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: In-the-wild kernel protection bypass chain (CVE-2024-23225 & CVE-2024-23296)

Las [**versiones de seguridad de macOS de marzo de 2024**](https://support.apple.com/en-us/120895) de Apple corrigieron dos problemas que fueron **explotados activamente**:

- **CVE-2024-23225 – Kernel**: un bug de memory corruption mediante el cual un atacante con arbitrary kernel read/write podía eludir las protecciones de memoria del kernel.
- **CVE-2024-23296 – RTKit**: un segundo bug de memory corruption con la misma declaración pública de impacto.

Los detalles públicos de la root cause siguen siendo escasos, pero el par sirve como recordatorio de que las exploit chains modernas de Apple a menudo necesitan **algo más que «simplemente» kernel R/W**: el trabajo de post-exploitation contra las protecciones de memoria, el código adyacente a los coprocesadores o las trust boundaries secundarias suele ser donde se estabiliza la chain real.

Triage rápido de parches:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + carrera de credenciales de solo lectura (CVE-2025-24118)

El [**write-up de TRAVERTINE**](https://jprx.io/cve-2025-24118/) de Joseph Ravichandran es un caso de estudio moderno muy bueno sobre XNU porque **no** es un classic buffer overflow:<sup>[[1]](#references)</sup>

- `proc_ro.p_ucred` es un **puntero protegido por SMR** almacenado en un objeto `proc_ro` de **solo lectura**.
- Los escritores deben actualizar ese puntero **atómicamente**.
- `kauth_cred_proc_update()` usaba `zalloc_ro_mut(...)` para modificar `p_ucred`; en x86_64, esa ruta finalmente llega a `memcpy` / `rep movsb`, por lo que un lector concurrente puede observar un **puntero dividido**.
- El bug se convierte en una **escalada de privilegios basada únicamente en datos**: si el puntero de credenciales corrupto apunta a un objeto de credenciales válido diferente, el thread actual puede heredar un estado con más privilegios sin conseguir primero un очевидous control-flow hijack.

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
Heurística de auditoría útil: siempre que una ruta del kernel mezcle **SMR readers**, **mutación de read-only zone** y **metadatos de credenciales o tareas**, verifica que las actualizaciones utilicen las variantes atómicas `zalloc_ro_mut_*` en lugar de helpers basados en copias.

---

## 2024-2025: SIP bypass que vuelve a abrir las rutas de carga del kernel (CVE-2024-44243)

Microsoft demostró que `storagekitd` podía utilizarse para **bypass SIP** y hacer que el código de kernel de terceros volviera a ser relevante en máquinas que, de otro modo, parecerían estar en un estado "post-kext". La idea clave es:<sup>[[2]](#references)</sup>

1. Colocar o sobrescribir un bundle `.fs` malicioso en `/Library/Filesystems`.
2. Activar `storagekitd` mediante Disk Utility o `diskutil`.
3. Permitir que el daemon con privilegios especiales ejecute los binarios del bundle **sin eliminar correctamente los privilegios ni validar la ruta**.
4. Utilizar el bypass SIP resultante para modificar el estado protegido del sistema de archivos y, en la demostración de Microsoft, sobrescribir la lista de exclusión de kernel extensions.

Para los investigadores de kernel, la lección importante es que **la superficie de ataque del kernel puede reintroducirse desde daemons de gestión en userland**, incluso cuando la carga directa de kexts de terceros está muy restringida.

Triage útil:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Flujo de fuzzing e investigación

Si estás buscando activamente esta clase de bugs, el trabajo público reciente apunta en la misma dirección:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) sigue siendo una de las mejores referencias para la investigación del kernel en la era de Apple Silicon. Utiliza **reescritura binaria estática** para recuperar la cobertura, desactiva las rutas protegidas por **entitlement** durante las pruebas e infiere la estructura de las interfaces a partir de los wrappers de userspace.<sup>[[4]](#references)</sup>
- El artículo de Project Zero [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) muestra un flujo de trabajo muy práctico para **hacer rebase de un kext / fileset en userspace**, de modo que el código con mucho parsing pueda someterse a fuzzing a mucha mayor velocidad antes de reproducirlo en el dispositivo.<sup>[[5]](#references)</sup>
- Para targets centrados en Mach, crea harnesses alrededor de **layouts de mensajes reales y máquinas de estados con múltiples llamadas**, no solo blobs de selectores individuales. La investigación reciente sobre CoreAudio/Mach de Project Zero y charlas de conferencias como **Fuzzing at Mach Speed** muestran por qué las secuencias de mensajes con estado siguen dando buenos resultados.

Comandos locales rápidos que utilizarás mucho:
```bash
# Loaded auxiliary / 3rd party kernel code
kmutil showloaded --collection aux

# Fileset entries in the boot kernel collection
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Diffable version info before matching a KDK / symbols pack
sw_vers
uname -a
```
## Hoja de referencia rápida de enumeración
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

- [1] [Joseph Ravichandran - TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [2] [Microsoft Security Blog - Análisis de CVE-2024-44243, un bypass de macOS System Integrity Protection mediante extensiones del kernel](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - La pesadilla de la actualización OTA de Apple: Bypass de la verificación de firma y toma de control del kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin et al. - KextFuzz: Fuzzing de extensiones del kernel de macOS en Apple Silicon mediante la explotación de mitigaciones (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - Fuzzing simple de extensiones del kernel de macOS en userspace con IDA y TinyInst](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)

{{#include ../../../banners/hacktricks-training.md}}
