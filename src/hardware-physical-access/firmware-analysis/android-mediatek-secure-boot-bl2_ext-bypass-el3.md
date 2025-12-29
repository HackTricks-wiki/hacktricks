# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Esta página documenta una explotación práctica de secure-boot en múltiples plataformas MediaTek aprovechando una brecha de verificación cuando la configuración del bootloader del dispositivo (seccfg) está "unlocked". El fallo permite ejecutar un bl2_ext parcheado en ARM EL3 para deshabilitar la verificación de firmas en etapas posteriores, colapsando la cadena de confianza y permitiendo cargar arbitrariamente TEE/GZ/LK/Kernel sin firmar.

> Precaución: Parchar en early-boot puede brickear permanentemente los dispositivos si los offsets son incorrectos. Mantén siempre volcados completos y una ruta de recuperación fiable.

## Flujo de arranque afectado (MediaTek)

- Ruta normal: BootROM → Preloader → bl2_ext (EL3, verificado) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Ruta vulnerable: Cuando seccfg está en estado "unlocked", Preloader puede omitir la verificación de bl2_ext. Preloader aún salta a bl2_ext en EL3, por lo que un bl2_ext manipulado puede cargar componentes no verificados a continuación.

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

## Cómo evaluar un objetivo (registros expdb)

Dump/inspect boot logs (e.g., expdb) alrededor de la carga de bl2_ext. Si img_auth_required = 0 y el tiempo de verificación del certificado es ~0 ms, probablemente enforcement esté desactivado y el dispositivo sea explotable.

Ejemplo de extracto de registro:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Nota: Se informa que algunos dispositivos omiten la verificación de bl2_ext incluso con el bootloader bloqueado, lo que agrava el impacto.

Se ha observado la misma brecha lógica en dispositivos que incluyen el lk2 secondary bootloader, así que obtén los logs de expdb de las particiones bl2_ext y lk2 para confirmar si alguna ruta aplica firmas antes de intentar portar.

## Flujo de explotación práctico (Fenrir PoC)

Fenrir es un toolkit de referencia de exploit/patching para esta clase de problema. Soporta Nothing Phone (2a) (Pacman) y se sabe que funciona (con soporte incompleto) en CMF Phone 1 (Tetris). Portar a otros modelos requiere reverse engineering del bl2_ext específico del dispositivo.

Proceso de alto nivel:
- Obtén la imagen del bootloader del dispositivo para tu codename objetivo y colócala como `bin/<device>.bin`
- Construye una imagen parcheada que deshabilite la política de verificación de bl2_ext
- Flashea el payload resultante al dispositivo (el script auxiliar asume fastboot)

Commands:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by the helper script)
./flash.sh
```
Si fastboot no está disponible, debes usar un método de flashing alternativo adecuado para tu plataforma.

### Build automation & payload debugging

- `build.sh` ahora descarga y exporta automáticamente Arm GNU Toolchain 14.2 (aarch64-none-elf) la primera vez que lo ejecutes, por lo que no tienes que manejar cross-compilers manualmente.
- Exporta `DEBUG=1` antes de invocar `build.sh` para compilar payloads con salidas seriales verbosas, lo que ayuda mucho cuando parcheas a ciegas rutas de código EL3.
- Las compilaciones exitosas generan tanto `lk.patched` como `<device>-fenrir.bin`; este último ya tiene el payload inyectado y es lo que deberías flash/boot-test.

## Runtime payload capabilities (EL3)

Un payload bl2_ext parcheado puede:
- Registrar comandos fastboot personalizados
- Controlar/sobrescribir el boot mode
- Llamar dinámicamente a funciones built‑in del bootloader en tiempo de ejecución
- Suplantar el “lock state” como locked mientras está realmente unlocked para pasar comprobaciones de integridad más estrictas (algunos entornos pueden aún requerir ajustes de vbmeta/AVB)

Limitación: las PoCs actuales indican que la modificación de memoria en tiempo de ejecución puede fallar debido a restricciones del MMU; los payloads generalmente evitan escrituras en memoria en vivo hasta que esto se resuelva.

## Payload staging patterns (EL3)

Fenrir divide su instrumentación en tres etapas a tiempo de compilación: stage1 se ejecuta antes de `platform_init()`, stage2 se ejecuta antes de que LK señale la entrada a fastboot, y stage3 se ejecuta inmediatamente antes de que LK cargue Linux. Cada device header bajo `payload/devices/` proporciona las direcciones para estos hooks más los símbolos helper de fastboot, así que mantén esos offsets sincronizados con tu build objetivo.

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
Stage3 demuestra cómo voltear temporalmente los atributos de la tabla de páginas para parchear cadenas inmutables, como la advertencia “Orange State” de Android, sin necesitar acceso al kernel downstream:
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
Porque stage1 se ejecuta antes del bring-up de la plataforma, es el lugar adecuado para llamar a las OEM power/reset primitives o para insertar registro adicional de integridad antes de que la cadena de verified boot sea desmontada.

## Consejos para portar

- Reverse engineer el bl2_ext específico del dispositivo para localizar la verification policy logic (p. ej., sec_get_vfy_policy).
- Identifica el sitio de retorno de la policy o la rama de decisión y parchea para “no verification required” (return 0 / unconditional allow).
- Mantén los offsets totalmente específicos por dispositivo y firmware; no reutilices direcciones entre variantes.
- Valida primero en una unidad sacrificial. Prepara un plan de recuperación (p. ej., EDL/BootROM loader/SoC-specific download mode) antes de flashear.
- Los dispositivos que usan el secondary bootloader lk2 o que reportan “img_auth_required = 0” para bl2_ext incluso estando locked deben tratarse como copias vulnerables de esta clase de bug; Vivo X80 Pro ya se ha observado saltándose la verificación a pesar de informar un estado locked.
- Compara los expdb logs entre estados locked y unlocked—si el certificate timing pasa de 0 ms a un valor distinto de cero una vez que relockeas, probablemente parcheste el punto de decisión correcto pero aún necesitas reforzar el spoofing del lock-state para ocultar la modificación.

## Impacto en la seguridad

- EL3 code execution después de Preloader y colapso total de la chain-of-trust para el resto del boot path.
- Capacidad para bootear TEE/GZ/LK/Kernel sin firmar, bypassing secure/verified boot expectations y habilitando compromiso persistente.

## Notas de dispositivos

- Confirmado compatible: Nothing Phone (2a) (Pacman)
- Funciona conocido (soporte incompleto): CMF Phone 1 (Tetris)
- Observado: Vivo X80 Pro reportado sin verificar bl2_ext incluso cuando estaba locked
- La cobertura industrial destaca vendors basados en lk2 que envían la misma falla lógica, así que espera mayor solapamiento a lo largo de los lanzamientos MTK 2024–2025.

## Referencias

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)

{{#include ../../banners/hacktricks-training.md}}
