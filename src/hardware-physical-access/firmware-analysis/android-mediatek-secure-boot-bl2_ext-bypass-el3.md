# MediaTek bl2_ext Secure-Boot Bypass (Ejecución de código EL3)

{{#include ../../banners/hacktricks-training.md}}

Esta página documenta un bypass práctico de secure boot en varias plataformas MediaTek mediante el abuso de una brecha de verificación cuando la configuración del bootloader del dispositivo (seccfg) está «desbloqueada». El fallo permite ejecutar un bl2_ext parcheado en ARM EL3 para deshabilitar la verificación de firmas posterior, colapsando la cadena de confianza y permitiendo cargar arbitrariamente TEE/GZ/LK/Kernel sin firmar.<sup>[[1]](#references)</sup>

> Precaución: El patching durante el arranque temprano puede brickear permanentemente los dispositivos si los offsets son incorrectos. Conserva siempre dumps completos y una vía de recovery fiable.

## Flujo de arranque afectado (MediaTek)

- Ruta normal: BootROM → Preloader → bl2_ext (EL3, verificado) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Ruta vulnerable: Cuando se configura seccfg como desbloqueado, Preloader puede omitir la verificación de bl2_ext. Preloader sigue saltando a bl2_ext en EL3, por lo que un bl2_ext manipulado puede cargar posteriormente componentes no verificados.

Límite de confianza clave:
- bl2_ext se ejecuta en EL3 y es responsable de verificar TEE, GenieZone, LK/AEE y el kernel. Si bl2_ext no está autenticado, el resto de la cadena se puede bypass-ear trivialmente.<sup>[[1]](#references)</sup>

## Causa raíz

En los dispositivos afectados, Preloader no impone la autenticación de la partición bl2_ext cuando seccfg indica un estado «desbloqueado». Esto permite flashear un bl2_ext controlado por el atacante que se ejecuta en EL3.

Dentro de bl2_ext, la función de la política de verificación puede parchearse para informar incondicionalmente de que la verificación no es necesaria (o que siempre tiene éxito), forzando a la cadena de arranque a aceptar imágenes TEE/GZ/LK/Kernel sin firmar. Debido a que este parche se ejecuta en EL3, es efectivo incluso si los componentes posteriores implementan sus propias comprobaciones.<sup>[[1]](#references)</sup>

## Cadena de exploit práctica

1. Obtener las particiones del bootloader (Preloader, bl2_ext, LK/AEE, etc.) mediante paquetes OTA/firmware, readback mediante EDL/DA o dumps de hardware.
2. Identificar la rutina de verificación de bl2_ext y parchearla para que siempre omita o acepte la verificación.
3. Flashear el bl2_ext modificado mediante fastboot, DA u otros maintenance channels similares que sigan permitidos en dispositivos desbloqueados.
4. Reiniciar; Preloader salta al bl2_ext parcheado en EL3, que carga las imágenes posteriores sin firmar (TEE/GZ/LK/Kernel parcheados) y deshabilita la imposición de firmas.<sup>[[1]](#references)</sup>

Si el dispositivo está configurado como bloqueado (seccfg locked), se espera que Preloader verifique bl2_ext. En esa configuración, este ataque fallará salvo que otra vulnerabilidad permita cargar un bl2_ext sin firmar.

## Triage (logs de arranque de expdb)

- Extrae los logs de arranque/expdb alrededor de la carga de bl2_ext. Si `img_auth_required = 0` y el tiempo de verificación del certificado es de aproximadamente 0 ms, es probable que la verificación se haya omitido.<sup>[[1]](#references)</sup>

Ejemplo de extracto de log:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- Algunos dispositivos omiten la verificación de bl2_ext incluso cuando están locked; las rutas del secondary bootloader lk2 han mostrado la misma brecha. Si un Preloader posterior a una OTA registra `img_auth_required = 1` para bl2_ext mientras está unlocked, probablemente se haya restaurado la aplicación de la política.<sup>[[1]](#references)[[2]](#references)</sup>

## Ubicaciones de la lógica de verificación

- El check relevante suele encontrarse dentro de la imagen bl2_ext, en funciones con nombres similares a `verify_img` o `sec_img_auth`.
- La versión parcheada fuerza a la función a devolver éxito o evita por completo la llamada de verificación.<sup>[[1]](#references)</sup>

Enfoque de patch de ejemplo (conceptual):
- Localiza la función que llama a `sec_img_auth` en las imágenes de TEE, GZ, LK y kernel.
- Reemplaza su cuerpo por un stub que devuelva éxito inmediatamente, o sobrescribe la rama condicional que gestiona el fallo de verificación.

Asegúrate de que el patch preserve la configuración de la pila/frame y devuelva los códigos de estado esperados a los callers.<sup>[[1]](#references)</sup>

## Flujo de trabajo de Fenrir PoC (Nothing/CMF)

Fenrir es un toolkit de referencia para aplicar patches a este problema (Nothing Phone (2a) totalmente compatible; CMF Phone 1 parcialmente compatible).<sup>[[1]](#references)</sup> Descripción general:
- Coloca la imagen del bootloader del dispositivo como `bin/<device>.bin`.
- Compila una imagen parcheada que desactive la política de verificación de bl2_ext.
- Flashea el payload resultante (se proporciona un helper de fastboot).
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
Use otro canal de flashing si fastboot no está disponible.

## Notas sobre el patching de EL3

- bl2_ext se ejecuta en ARM EL3. Los crashes en esta fase pueden brickear un dispositivo hasta que se vuelva a flashear mediante EDL/DA o test points.
- Usa logging/UART específico de la placa para validar la ruta de ejecución y diagnosticar crashes.
- Mantén backups de todas las particiones que se modifiquen y prueba primero en hardware desechable.<sup>[[1]](#references)</sup>

## Implicaciones

- Ejecución de código en EL3 después de Preloader y colapso completo de la chain of trust para el resto de la ruta de arranque.
- Capacidad para arrancar TEE/GZ/LK/Kernel sin firmar, evadiendo las expectativas de secure/verified boot y permitiendo un compromiso persistente.<sup>[[1]](#references)</sup>

## Notas sobre dispositivos

- Compatibilidad confirmada: Nothing Phone (2a) (Pacman)
- Funcionando (compatibilidad incompleta): CMF Phone 1 (Tetris)
- Observado: según informes, Vivo X80 Pro no verificaba bl2_ext incluso estando bloqueado<sup>[[1]](#references)</sup>
- NothingOS 4 estable (BP2A.250605.031.A3, noviembre de 2025) volvió a habilitar la verificación de bl2_ext; `pacman-v2.0` de fenrir restaura el bypass mezclando el Preloader beta con un LK parcheado<sup>[[3]](#references)</sup>
- La cobertura del sector destaca otros proveedores basados en lk2 que distribuyen la misma lógica defectuosa, por lo que se espera una mayor coincidencia entre los lanzamientos MTK de 2024–2025.<sup>[[2]](#references)[[4]](#references)</sup>

## Lectura de MTK DA y manipulación de seccfg con Penumbra

Penumbra es un crate/CLI/TUI de Rust que automatiza la interacción con el preloader/bootrom de MTK mediante USB para operaciones en modo DA. Con acceso físico a un dispositivo vulnerable (con extensiones DA permitidas), puede descubrir el puerto USB de MTK, cargar un blob de Download Agent (DA) y emitir comandos privilegiados, como cambiar el estado de bloqueo de seccfg y leer particiones.<sup>[[5]](#references)</sup>

- **Configuración del entorno/controladores**: En Linux, instala `libudev`, añade el usuario al grupo `dialout` y crea reglas udev o ejecuta con `sudo` si no se puede acceder al nodo del dispositivo. La compatibilidad con Windows no es fiable; a veces solo funciona después de reemplazar el controlador MTK por WinUSB mediante Zadig (según las indicaciones del proyecto).
- **Workflow**: Lee un payload DA (por ejemplo, `std::fs::read("../DA_penangf.bin")`), busca periódicamente el puerto MTK con `find_mtk_port()` y crea una sesión usando `DeviceBuilder::with_mtk_port(...).with_da_data(...)`. Después de que `init()` complete el handshake y recopile la información del dispositivo, comprueba las protecciones mediante los bitfields de `dev_info.target_config()` (bit 0 establecido → SBC habilitado). Entra en modo DA e intenta ejecutar `set_seccfg_lock_state(LockFlag::Unlock)`: esto solo tiene éxito si el dispositivo acepta extensiones. Las particiones se pueden volcar con `read_partition("lk_a", &mut progress_cb, &mut writer)` para su análisis offline o patching.
- **Impacto en la seguridad**: El desbloqueo exitoso de seccfg vuelve a abrir las rutas de flashing para imágenes de arranque sin firmar, permitiendo compromisos persistentes como el patching de bl2_ext EL3 descrito anteriormente. La lectura de particiones proporciona artefactos de firmware para reverse engineering y la creación de imágenes modificadas.

<details>
<summary>Sesión Rust DA + desbloqueo de seccfg + volcado de partición (Penumbra)</summary>
```rust
use tokio::fs::File;
use anyhow::Result;
use penumbra::{DeviceBuilder, LockFlag, find_mtk_port};
use tokio::io::{AsyncWriteExt, BufWriter};

#[tokio::main]
async fn main() -> Result<()> {
let da = std::fs::read("../DA_penangf.bin")?;
let mtk_port = loop {
if let Some(port) = find_mtk_port().await {
break port;
}
};

let mut dev = DeviceBuilder::default()
.with_mtk_port(mtk_port)
.with_da_data(da)
.build()?;

dev.init().await?;
let cfg = dev.dev_info.target_config().await;
println!("SBC: {}", (cfg & 0x1) != 0);

dev.set_seccfg_lock_state(LockFlag::Unlock).await?;

let mut progress = |_read: usize, _total: usize| {};
let mut writer = BufWriter::new(File::create("lk_a.bin")?);
dev.read_partition("lk_a", &mut progress, &mut writer).await?;
writer.flush().await?;
Ok(())
}
```
</details>

## Referencias

- [1] [Fenrir – Bypass de secure boot de MediaTek bl2_ext (PoC)](https://github.com/R0rt1z2/fenrir)
- [2] [Cyber Security News – Publicado un exploit PoC para la vulnerabilidad de ejecución de código de Nothing Phone](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [3] [Lanzamiento de Fenrir pacman-v2.0 (bundle de bypass de NothingOS 4)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [4] [The Cyber Express – El PoC de Fenrir rompe el secure boot en Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [5] [Penumbra – Herramientas de DA flash/readback y seccfg de MTK](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
