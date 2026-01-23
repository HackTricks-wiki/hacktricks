# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Esta página documenta una vulneración práctica de secure-boot en múltiples plataformas MediaTek aprovechando una brecha de verificación cuando la configuración del bootloader del dispositivo (seccfg) está "unlocked". La falla permite ejecutar un bl2_ext parcheado en ARM EL3 para deshabilitar la verificación de firmas aguas abajo, colapsando la cadena de confianza y permitiendo la carga arbitraria de TEE/GZ/LK/Kernel sin firmar.

> Precaución: Early-boot patching can permanently brick devices if offsets are wrong. Always keep full dumps and a reliable recovery path.

## Flujo de arranque afectado (MediaTek)

- Ruta normal: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Ruta vulnerable: Cuando seccfg está establecido en unlocked, el Preloader puede omitir la verificación de bl2_ext. El Preloader aún salta a bl2_ext en EL3, por lo que un bl2_ext manipulado puede cargar componentes no verificados posteriormente.

Límite clave de confianza:
- bl2_ext se ejecuta en EL3 y es responsable de verificar TEE, GenieZone, LK/AEE y el kernel. Si bl2_ext no está autenticado, el resto de la cadena se omite trivialmente.

## Causa raíz

En los dispositivos afectados, el Preloader no aplica la autenticación de la partición bl2_ext cuando seccfg indica un estado "unlocked". Esto permite flashear un bl2_ext controlado por un atacante que se ejecuta en EL3.

Dentro de bl2_ext, la función de política de verificación puede ser parcheada para informar incondicionalmente que la verificación no es necesaria. Un parche conceptual mínimo es:
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
Nota: Se ha informado que algunos dispositivos omiten la verificación de bl2_ext incluso con el bootloader bloqueado, lo que agrava el impacto.

Se ha observado la misma brecha lógica en dispositivos que incluyen el loader secundario lk2, así que obtén logs expdb de las particiones bl2_ext y lk2 para confirmar si alguna ruta aplica firmas antes de intentar el porting.

Si un Preloader post-OTA ahora registra img_auth_required = 1 para bl2_ext incluso con seccfg desbloqueado, es probable que el vendor haya cerrado la brecha — ver las notas de persistencia OTA abajo.

## Practical exploitation workflow (Fenrir PoC)

Fenrir es un toolkit de exploit/patching de referencia para esta clase de problemas. Soporta Nothing Phone (2a) (Pacman) y se sabe que funciona (con soporte incompleto) en CMF Phone 1 (Tetris). Portar a otros modelos requiere ingeniería inversa del bl2_ext específico del dispositivo.

High-level process:
- Obtén la imagen del bootloader del dispositivo para tu nombre en clave objetivo y colócala como `bin/<device>.bin`
- Construye una imagen parcheada que deshabilite la política de verificación de bl2_ext
- Flashea el payload resultante al dispositivo (se asume fastboot por el script auxiliar)

Commands:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by the helper script)
./flash.sh
```
Si fastboot no está disponible, debes usar un método de flasheo alternativo adecuado para tu plataforma.

### Firmware parcheado OTA: keeping the bypass alive (NothingOS 4, late 2025)

Nothing parcheó el Preloader en el OTA estable NothingOS 4 de noviembre de 2025 (build BP2A.250605.031.A3) para imponer la verificación de bl2_ext incluso cuando seccfg esté desbloqueado. Fenrir `pacman-v2.0` vuelve a funcionar mezclando el Preloader vulnerable del NOS 4 beta con el LK payload estable:
```bash
# on Nothing Phone (2a), unlocked bootloader, in bootloader (not fastbootd)
fastboot flash preloader_a preloader_raw.img   # beta Preloader bundled with fenrir release
fastboot flash lk pacman-fenrir.bin            # patched LK containing stage hooks
fastboot reboot                                # factory reset may be needed
```
Important:
- Flashea el Preloader proporcionado **solo** al device/slot correspondiente; un preloader incorrecto provoca un hard brick instantáneo.
- Revisa expdb después del flash; img_auth_required debería volver a 0 para bl2_ext, confirmando que el Preloader vulnerable se está ejecutando antes de tu LK parcheado.
- Si futuras OTAs parchean tanto Preloader como LK, conserva una copia local de un Preloader vulnerable para reintroducir la brecha.

### Build automation & payload debugging

- `build.sh` ahora descarga y exporta automáticamente Arm GNU Toolchain 14.2 (aarch64-none-elf) la primera vez que lo ejecutes, por lo que no tienes que manejar compiladores cruzados manualmente.
- Exporta `DEBUG=1` antes de invocar `build.sh` para compilar payloads con salidas seriales verbosas, lo que ayuda mucho cuando parcheas a ciegas rutas de código EL3.
- Las compilaciones exitosas generan tanto `lk.patched` como `<device>-fenrir.bin`; este último ya tiene el payload inyectado y es lo que debes flashear/probar en el arranque.

## Runtime payload capabilities (EL3)

Un payload parcheado para bl2_ext puede:
- Registrar comandos fastboot personalizados
- Controlar/sobrescribir el boot mode
- Llamar dinámicamente a funciones built‑in del bootloader en tiempo de ejecución
- Falsificar el “lock state” como locked mientras está realmente unlocked para pasar comprobaciones de integridad más estrictas (algunos entornos pueden aún requerir ajustes de vbmeta/AVB)

Limitación: PoCs actuales señalan que la modificación de memoria en tiempo de ejecución puede fallar debido a restricciones del MMU; los payloads generalmente evitan escrituras en memoria en vivo hasta que esto se resuelva.

## Payload staging patterns (EL3)

Fenrir divide su instrumentación en tres etapas en tiempo de compilación: stage1 se ejecuta antes de `platform_init()`, stage2 se ejecuta antes de que LK indique la entrada a fastboot, y stage3 se ejecuta inmediatamente antes de que LK cargue Linux. Cada encabezado de dispositivo bajo `payload/devices/` proporciona las direcciones para estos hooks más los símbolos auxiliares de fastboot, así que mantén esos offsets sincronizados con tu build objetivo.

Stage2 es un lugar conveniente para registrar verbos arbitrarios `fastboot oem`:
```c
void cmd_r0rt1z2(const char *arg, void *data, unsigned int sz) {
video_printf("r0rt1z2 was here...\n");
fastboot_info("pwned by r0rt1z2");
fastboot_okay("");
}

__attribute__((section(".text.main"))) void main(void) {
fastboot_register("oem r0rt1z2", cmd_r0rt1z2, true, false);
notify_enter_fastboot();
}
```
Stage3 demuestra cómo invertir temporalmente los atributos de la tabla de páginas para parchear cadenas inmutables como la advertencia “Orange State” de Android sin necesitar acceso al kernel aguas abajo:
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
Porque stage1 se ejecuta antes del bring-up de la plataforma, es el lugar adecuado para llamar a primitivas de power/reset del OEM o para insertar registro adicional de integridad antes de que la cadena de arranque verificada sea desmontada.

## Consejos para portar

- Realiza ingeniería inversa del bl2_ext específico del dispositivo para localizar la lógica de la política de verificación (por ejemplo, sec_get_vfy_policy).
- Identifica el sitio de retorno de la política o la rama de decisión y páchela para “no verification required” (return 0 / unconditional allow).
- Mantén los offsets totalmente específicos del dispositivo y del firmware; no reutilices direcciones entre variantes.
- Valida primero en una unidad sacrificial. Prepara un plan de recuperación (por ejemplo, EDL/BootROM loader/SoC-specific download mode) antes de flashear.
- Los dispositivos que usan el bootloader secundario lk2 o que reporten “img_auth_required = 0” para bl2_ext incluso estando bloqueados deben tratarse como copias vulnerables de esta clase de bug; se ha observado que Vivo X80 Pro ya omitía la verificación a pesar de un estado de bloqueo reportado.
- Cuando una OTA empiece a aplicar las firmas de bl2_ext (img_auth_required = 1) en estado desbloqueado, verifica si se puede flashear un Preloader más antiguo (a menudo disponible en OTAs beta) para reabrir la brecha, y luego vuelve a ejecutar fenrir con offsets actualizados para el LK más nuevo.

## Impacto en la seguridad

- Ejecución de código en EL3 tras el Preloader y colapso total de la cadena de confianza para el resto de la ruta de arranque.
- Capacidad para arrancar TEE/GZ/LK/Kernel sin firmar, burlando las expectativas de secure/verified boot y permitiendo un compromiso persistente.

## Notas de dispositivos

- Confirmado soportado: Nothing Phone (2a) (Pacman)
- Probado funcionando (soporte incompleto): CMF Phone 1 (Tetris)
- Observado: según informes, Vivo X80 Pro no verificaba bl2_ext incluso estando bloqueado
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) reactivó la verificación de bl2_ext; fenrir `pacman-v2.0` restaura el bypass flasheando el Preloader beta más el LK parcheado como se muestra arriba
- La cobertura de la industria destaca proveedores adicionales basados en lk2 que envían la misma falla lógica, por lo que se espera mayor solapamiento en los lanzamientos MTK de 2024–2025.

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)

{{#include ../../banners/hacktricks-training.md}}
