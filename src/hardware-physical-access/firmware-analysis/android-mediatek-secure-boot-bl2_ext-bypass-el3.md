# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Esta página documenta una ruptura práctica del secure-boot en múltiples plataformas MediaTek al abusar de una brecha de verificación cuando la configuración del bootloader del dispositivo (seccfg) está "unlocked". El fallo permite ejecutar un bl2_ext parcheado en ARM EL3 para desactivar la verificación de firmas aguas abajo, colapsando la cadena de confianza y permitiendo la carga arbitraria de TEE/GZ/LK/Kernel sin firmar.

> Precaución: El parcheo en las primeras etapas del arranque puede dejar permanentemente inservibles los dispositivos si los offsets son incorrectos. Conserva siempre volcados completos y una ruta de recuperación fiable.

## Flujo de arranque afectado (MediaTek)

- Normal path: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Vulnerable path: When seccfg is set to unlocked, Preloader may skip verifying bl2_ext. Preloader still jumps into bl2_ext at EL3, so a crafted bl2_ext can load unverified components thereafter.

Límite clave de confianza:
- bl2_ext ejecuta en EL3 y es responsable de verificar TEE, GenieZone, LK/AEE y el kernel. Si bl2_ext no está autenticado, el resto de la cadena se omite trivialmente.

## Causa raíz

En los dispositivos afectados, el Preloader no aplica la autenticación de la partición bl2_ext cuando seccfg indica un estado "unlocked". Esto permite flashear un bl2_ext controlado por el atacante que se ejecuta en EL3.

Dentro de bl2_ext, la función de política de verificación puede parchearse para informar incondicionalmente que la verificación no es necesaria (o que siempre tiene éxito), forzando a la cadena de arranque a aceptar imágenes TEE/GZ/LK/Kernel sin firmar. Dado que este parche se ejecuta en EL3, es efectivo incluso si los componentes posteriores implementan sus propias comprobaciones.

## Cadena de explotación práctica

1. Obtener las particiones del bootloader (Preloader, bl2_ext, LK/AEE, etc.) vía OTA/firmware packages, EDL/DA readback, o volcado por hardware.
2. Identificar la rutina de verificación en bl2_ext y parchearla para que siempre omita/acepte la verificación.
3. Flashear el bl2_ext modificado usando fastboot, DA, o canales de mantenimiento similares que sigan permitidos en dispositivos unlocked.
4. Reiniciar; Preloader salta al bl2_ext parcheado en EL3, que luego carga imágenes aguas abajo sin firmar (TEE/GZ/LK/Kernel parcheadas) y desactiva la aplicación de firmas.

Si el dispositivo está configurado como locked (seccfg locked), se espera que el Preloader verifique bl2_ext. En esa configuración, este ataque fallará a menos que otra vulnerabilidad permita cargar un bl2_ext sin firmar.

## Triage (expdb boot logs)

- Volcar los registros de boot/expdb alrededor de la carga de bl2_ext. Si `img_auth_required = 0` y el tiempo de verificación de certificados es ~0 ms, probablemente se está omitiendo la verificación.

Ejemplo de extracto de registro:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- Algunos dispositivos omiten la verificación de bl2_ext incluso cuando están bloqueados; las rutas de lk2 secondary bootloader han mostrado la misma brecha. Si un Preloader post-OTA registra `img_auth_required = 1` para bl2_ext mientras está desbloqueado, es probable que la aplicación de la verificación se haya restaurado.

## Verification logic locations

- La comprobación relevante suele residir dentro de la imagen bl2_ext en funciones nombradas de forma similar a `verify_img` o `sec_img_auth`.
- La versión parcheada fuerza que la función devuelva éxito o que omita por completo la llamada de verificación.

Example patch approach (conceptual):
- Localiza la función que llama a `sec_img_auth` sobre las imágenes TEE, GZ, LK y kernel.
- Reemplaza su cuerpo con un stub que devuelva inmediatamente éxito, o sobrescribe la rama condicional que maneja el fallo de verificación.

Asegúrate de que el parche preserve la configuración de stack/frame y devuelva los códigos de estado esperados a los llamantes.

## Fenrir PoC workflow (Nothing/CMF)

Fenrir es un toolkit de parchado de referencia para este problema (Nothing Phone (2a) totalmente soportado; CMF Phone 1 parcialmente). A grandes rasgos:
- Coloca la imagen del bootloader del dispositivo como `bin/<device>.bin`.
- Construye una imagen parcheada que deshabilite la política de verificación de bl2_ext.
- Flashea la payload resultante (se proporciona helper de fastboot).
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
Usa otro canal de flashing si fastboot no está disponible.

## Notas de parcheo EL3

- bl2_ext se ejecuta en ARM EL3. Los fallos aquí pueden brickear un dispositivo hasta que se vuelva a flashear vía EDL/DA o puntos de prueba.
- Usa logging/UART específico de la placa para validar la ruta de ejecución y diagnosticar fallos.
- Mantén copias de seguridad de todas las particiones que se modifiquen y prueba primero en hardware desechable.

## Implicaciones

- Ejecución de código en EL3 tras el Preloader y colapso total de la cadena de confianza para el resto del proceso de arranque.
- Capacidad para arrancar TEE/GZ/LK/Kernel sin firmar, evadiendo las expectativas de secure/verified boot y permitiendo un compromiso persistente.

## Notas del dispositivo

- Soporte confirmado: Nothing Phone (2a) (Pacman)
- Conocido funcionando (soporte incompleto): CMF Phone 1 (Tetris)
- Observado: Vivo X80 Pro aparentemente no verificaba bl2_ext incluso cuando estaba bloqueado
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) volvió a habilitar la verificación de bl2_ext; fenrir `pacman-v2.0` restaura el bypass mezclando el Preloader beta con un LK parcheado
- La cobertura industrial destaca proveedores adicionales basados en lk2 que distribuyen la misma falla lógica, así que espere mayor solapamiento en los lanzamientos MTK de 2024–2025.

## MTK DA readback and seccfg manipulation with Penumbra

Penumbra es un crate/CLI/TUI de Rust que automatiza la interacción con el preloader/bootrom MTK sobre USB para operaciones en modo DA. Con acceso físico a un handset vulnerable (si se permiten extensiones DA), puede descubrir el puerto USB MTK, cargar un blob Download Agent (DA) y emitir comandos privilegiados como el flip del seccfg lock y el readback de particiones.

- **Configuración de entorno/controlador**: En Linux instala `libudev`, añade el usuario al grupo `dialout`, y crea reglas udev o ejecuta con `sudo` si el nodo de dispositivo no es accesible. El soporte en Windows es poco fiable; a veces funciona solo después de reemplazar el driver MTK por WinUSB usando Zadig (según la guía del proyecto).
- **Workflow**: Lee un payload DA (p. ej., `std::fs::read("../DA_penangf.bin")`), consulta el puerto MTK con `find_mtk_port()`, y construye una sesión usando `DeviceBuilder::with_mtk_port(...).with_da_data(...)`. Después de que `init()` complete el handshake y recopile info del dispositivo, verifica las protecciones mediante los bitfields de `dev_info.target_config()` (bit 0 activado → SBC habilitado). Entra en modo DA e intenta `set_seccfg_lock_state(LockFlag::Unlock)`—esto solo tiene éxito si el dispositivo acepta extensiones. Las particiones pueden volcarse con `read_partition("lk_a", &mut progress_cb, &mut writer)` para análisis offline o parcheo.
- **Impacto en la seguridad**: El desbloqueo exitoso de seccfg reabre las vías de flashing para imágenes de arranque sin firmar, permitiendo compromisos persistentes como el parcheo EL3 de bl2_ext descrito arriba. El readback de particiones proporciona artefactos de firmware para ingeniería inversa y para crear imágenes modificadas.

<details>
<summary>Rust DA session + seccfg unlock + partition dump (Penumbra)</summary>
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

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [Penumbra – MTK DA flash/readback & seccfg tooling](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
