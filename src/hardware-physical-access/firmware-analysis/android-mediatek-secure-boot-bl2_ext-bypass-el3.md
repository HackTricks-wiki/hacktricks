# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Esta página documenta una ruptura práctica de secure-boot en múltiples plataformas MediaTek explotando una brecha de verificación cuando la configuración del bootloader del dispositivo (seccfg) está "unlocked". La vulnerabilidad permite ejecutar un bl2_ext parcheado en ARM EL3 para deshabilitar la verificación de firmas aguas abajo, colapsando la cadena de confianza y permitiendo cargar arbitrariamente TEE/GZ/LK/Kernel sin firmar.

> Precaución: El parcheo en las primeras etapas del arranque puede dejar los dispositivos inservibles de forma permanente si los offsets son incorrectos. Mantén siempre volcados completos y una ruta de recuperación fiable.

## Flujo de arranque afectado (MediaTek)

- Ruta normal: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Ruta vulnerable: Cuando seccfg está establecido en unlocked, el Preloader puede omitir la verificación de bl2_ext. El Preloader aún salta a bl2_ext en EL3, por lo que un bl2_ext manipulado puede cargar componentes no verificados posteriormente.

Límite clave de confianza:
- bl2_ext se ejecuta en EL3 y es responsable de verificar TEE, GenieZone, LK/AEE y el kernel. Si bl2_ext en sí no está autenticado, el resto de la cadena se omite trivialmente.

## Causa raíz

En los dispositivos afectados, el Preloader no aplica la autenticación de la partición bl2_ext cuando seccfg indica un estado "unlocked". Esto permite flashear un bl2_ext controlado por el atacante que se ejecuta en EL3.

Dentro de bl2_ext, la función de política de verificación puede parchearse para reportar incondicionalmente que la verificación no es necesaria. Un parche conceptual mínimo es:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Con este cambio, todas las imágenes posteriores (TEE, GZ, LK/AEE, Kernel) son aceptadas sin comprobaciones criptográficas cuando las carga el bl2_ext parcheado que se ejecuta en EL3.

## Cómo evaluar un objetivo (expdb logs)

Volcar/inspeccionar los registros de arranque (p. ej., expdb) alrededor de la carga de bl2_ext. Si img_auth_required = 0 y el tiempo de verificación del certificado es ~0 ms, es probable que enforcement esté off y el dispositivo sea exploitable.

Ejemplo de extracto de log:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Nota: Se reporta que algunos dispositivos omiten la verificación de bl2_ext incluso con bootloader bloqueado, lo que agrava el impacto.

## Flujo de explotación práctico (Fenrir PoC)

Fenrir es un toolkit de referencia para explotación/parcheo para esta clase de fallos. Soporta Nothing Phone (2a) (Pacman) y se sabe que funciona (con soporte incompleto) en CMF Phone 1 (Tetris). Portar a otros modelos requiere reverse engineering del bl2_ext específico del dispositivo.

Proceso de alto nivel:
- Obtén la imagen del bootloader del dispositivo para tu nombre de código objetivo y colócala como bin/<device>.bin
- Construye una imagen parcheada que desactive la política de verificación de bl2_ext
- Flashea el payload resultante al dispositivo (el helper script asume fastboot)

Comandos:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by helper script)
./flash.sh
```
Si fastboot no está disponible, debe usar un método de flashing alternativo adecuado para su plataforma.

## Capacidades del payload en tiempo de ejecución (EL3)

Un payload bl2_ext parcheado puede:
- Registrar comandos fastboot personalizados
- Controlar/sobrescribir el modo de arranque
- Llamar dinámicamente a funciones integradas del bootloader en tiempo de ejecución
- Suplantar el “lock state” como locked mientras está realmente unlocked para pasar comprobaciones de integridad más estrictas (algunos entornos pueden aún requerir ajustes de vbmeta/AVB)

Limitación: los PoC actuales indican que la modificación de memoria en tiempo de ejecución puede provocar fallos debido a restricciones del MMU; los payloads generalmente evitan escrituras en memoria en vivo hasta que esto se resuelva.

## Consejos para portar

- Realice ingeniería inversa del bl2_ext específico del dispositivo para localizar la lógica de la política de verificación (p. ej., sec_get_vfy_policy).
- Identifique el sitio de retorno de la política o la rama de decisión y páchelo a “no verification required” (return 0 / unconditional allow).
- Mantenga los offsets completamente específicos de dispositivo y firmware; no reutilice direcciones entre variantes.
- Valide primero en una unidad sacrificial. Prepare un plan de recuperación (p. ej., EDL/BootROM loader/SoC-specific download mode) antes de flashear.

## Impacto en la seguridad

- Ejecución de código en EL3 después del Preloader y colapso completo de la cadena de confianza para el resto del flujo de arranque.
- Capacidad de arrancar TEE/GZ/LK/Kernel sin firmar, eludiendo las expectativas de secure/verified boot y habilitando un compromiso persistente.

## Ideas para detección y hardening

- Asegure que el Preloader verifique bl2_ext independientemente del estado de seccfg.
- Aplicar los resultados de autenticación y recopilar evidencia de auditoría (timings > 0 ms, errores estrictos en caso de desajuste).
- La suplantación de lock-state debe hacerse inefectiva para la attestation (vincular el lock state a las decisiones de verificación AVB/vbmeta y al estado respaldado por fusibles).

## Notas de dispositivo

- Confirmado compatible: Nothing Phone (2a) (Pacman)
- Funcionamiento conocido (soporte incompleto): CMF Phone 1 (Tetris)
- Observado: según se informa, el Vivo X80 Pro no verificó bl2_ext incluso cuando estaba locked

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}
