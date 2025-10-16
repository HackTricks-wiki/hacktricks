# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Esta página documenta una ruptura práctica de secure-boot en múltiples plataformas MediaTek al abusar de una brecha de verificación cuando la configuración del bootloader del dispositivo (seccfg) está "unlocked". La falla permite ejecutar un bl2_ext parcheado en ARM EL3 para deshabilitar la verificación de firmas aguas abajo, colapsando la cadena de confianza y permitiendo la carga arbitraria de TEE/GZ/LK/Kernel sin firmar.

> Precaución: El parcheo en etapas tempranas del arranque puede dejar dispositivos permanentemente inutilizables si los offsets son incorrectos. Mantén siempre volcados completos y una ruta de recuperación fiable.

## Flujo de arranque afectado (MediaTek)

- Ruta normal: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Ruta vulnerable: Cuando seccfg está configurado como unlocked, el Preloader puede omitir la verificación de bl2_ext. El Preloader aún salta a bl2_ext en EL3, por lo que un bl2_ext manipulado puede cargar componentes no verificados a continuación.

Límite clave de confianza:
- bl2_ext se ejecuta en EL3 y es responsable de verificar TEE, GenieZone, LK/AEE y el kernel. Si bl2_ext no está autenticado, el resto de la cadena se elude trivialmente.

## Causa raíz

En los dispositivos afectados, el Preloader no exige la autenticación de la partición bl2_ext cuando seccfg indica un estado "unlocked". Esto permite flashear un bl2_ext controlado por el atacante que se ejecuta en EL3.

Dentro de bl2_ext, la función de la política de verificación puede ser parcheada para reportar incondicionalmente que la verificación no es necesaria. Un parche conceptual mínimo es:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Con este cambio, todas las imágenes posteriores (TEE, GZ, LK/AEE, Kernel) son aceptadas sin comprobaciones criptográficas cuando son cargadas por el bl2_ext parcheado que se ejecuta en EL3.

## Cómo evaluar un objetivo (expdb logs)

Volcar/inspeccionar los logs de arranque (p. ej., expdb) alrededor de la carga de bl2_ext. Si img_auth_required = 0 y el tiempo de verificación del certificado es ~0 ms, es probable que la verificación esté desactivada y el dispositivo sea explotable.

Ejemplo de extracto del log:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Nota: Algunos dispositivos supuestamente omiten la verificación de bl2_ext incluso con el bootloader bloqueado, lo que agrava el impacto.

## Flujo de explotación práctico (Fenrir PoC)

Fenrir es un toolkit de exploit/patching de referencia para esta clase de problema. Es compatible con Nothing Phone (2a) (Pacman) y se sabe que funciona (con soporte incompleto) en CMF Phone 1 (Tetris). Portar a otros modelos requiere reverse engineering del bl2_ext específico del dispositivo.

Proceso general:
- Obtén la imagen del bootloader del dispositivo para tu nombre en clave objetivo y colócala como bin/<device>.bin
- Construye una imagen parcheada que deshabilite la política de verificación de bl2_ext
- Flashea el payload resultante al dispositivo (se asume fastboot por el script auxiliar)

Comandos:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by helper script)
./flash.sh
```
If fastboot is unavailable, you must use a suitable alternative flashing method for your platform.

## Runtime payload capabilities (EL3)

A patched bl2_ext payload can:
- Registrar comandos fastboot personalizados
- Controlar/sobrescribir el modo de arranque
- Llamar dinámicamente a funciones integradas del bootloader en tiempo de ejecución
- Suplantar el “lock state” como “locked” mientras está “unlocked” para pasar comprobaciones de integridad más estrictas (algunos entornos pueden seguir requiriendo ajustes de vbmeta/AVB)

Limitation: Current PoCs note that runtime memory modification may fault due to MMU constraints; payloads generally avoid live memory writes until this is resolved.

## Porting tips

- Realiza ingeniería inversa del bl2_ext específico del dispositivo para localizar la lógica de política de verificación (p. ej., sec_get_vfy_policy).
- Identifica el sitio de retorno de la política o la rama de decisión y parchalo a “no verification required” (return 0 / unconditional allow).
- Mantén los offsets completamente específicos al dispositivo y firmware; no reutilices direcciones entre variantes.
- Valida primero en una unidad sacrificial. Prepara un plan de recuperación (p. ej., EDL/BootROM loader/SoC-specific download mode) antes de flashear.

## Security impact

- Ejecución de código en EL3 después del Preloader y colapso total de la cadena de confianza para el resto de la ruta de arranque.
- Capacidad para boot unsigned TEE/GZ/LK/Kernel, eludiendo las expectativas de secure/verified boot y permitiendo una compromisión persistente.

## Detection and hardening ideas

- Asegurar que Preloader verifique bl2_ext independientemente del estado de seccfg.
- Hacer cumplir los resultados de autenticación y recopilar evidencia de auditoría (timings > 0 ms, errores estrictos en caso de discrepancia).
- La suplantación del lock-state debe hacerse ineficaz para attestation (vincular el lock state a las decisiones de verificación AVB/vbmeta y al estado respaldado por fusibles).

## Device notes

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro reportedly did not verify bl2_ext even when locked

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}
