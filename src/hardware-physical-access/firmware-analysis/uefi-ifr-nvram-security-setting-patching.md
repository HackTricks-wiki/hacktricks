# Patching de configuraciones de seguridad UEFI IFR y NVRAM

{{#include ../../banners/hacktricks-training.md}}

Una contraseña de configuración protege la interfaz de usuario del firmware, pero no necesariamente autentica los bytes de configuración almacenados en la SPI flash. Con acceso físico de escritura, un evaluador puede asociar una configuración UEFI oculta o bloqueada de su **Human Interface Infrastructure (HII) Internal Forms Representation (IFR)** con la variable NVRAM subyacente, parchear ese valor sin conexión y volver a grabarlo. En un sistema Dell afectado, esto cambió el estado de IOMMU durante el prearranque mientras la configuración gráfica seguía mostrando la protección DMA como habilitada.<sup>[[3]](#references)</sup>

> [!CAUTION]
> Las escrituras en el firmware pueden dejar el objetivo inutilizable permanentemente. Trabaja en un dispositivo de prueba autorizado y recuperable; conserva la imagen original; y obtén al menos tres lecturas independientes cuyos hashes criptográficos coincidan antes de modificar nada.<sup>[[3]](#references)</sup>

## Adquirir la imagen del firmware

Lee únicamente la región BIOS cuando el descriptor de flash de Intel permita el acceso del host, o utiliza un programador externo con el voltaje correcto y una pinza en circuito. Normalmente se requiere un programador externo para restaurar una máquina que ya no arranca.<sup>[[3]](#references)[[9]](#references)</sup>
```bash
flashrom -p internal -r dump.bin --ifd -i bios
sha256sum dump*.bin
```
No asumas que un update capsule del vendor sea equivalente al contenido del chip: puede omitir NVRAM, contener encapsulación o estar cifrado. [UEFITool](https://github.com/LongSoft/UEFITool) puede analizar una imagen UEFI sin procesar en firmware volumes, files y sections.<sup>[[7]](#references)</sup>

## Mapear una pregunta IFR a NVRAM

[IFRExtractor-RS](https://github.com/LongSoft/IFRExtractor-RS) convierte los paquetes de formularios HII en texto y expone settings que una GUI del vendor oculta, renombra o suprime. Su salida puede identificar la pregunta, el variable store, el byte offset, el storage width, los valores válidos y la visibilidad condicional.<sup>[[8]](#references)</sup>

1. Abre el dump en UEFITool, busca el firmware file llamado `Setup`, expándelo hasta la sección de imagen PE32 y utiliza **Extract body**.
2. Ejecuta IFRExtractor-RS sobre el cuerpo EFI/PE32 extraído y, a continuación, busca en el texto generado controles como `DMA`, `IOMMU`, `VT-d`, `Secure Boot` o el label mostrado al usuario por el vendor.
3. Registra `VarStoreId`, `VarOffset`, `Size`, las opciones válidas y el question ID. No infieras la semántica del valor basándote únicamente en `Flags`.
4. Encuentra la declaración `VarStore`/`VarStoreEfi` correspondiente y asigna el ID numérico del store a su variable **name y GUID**.
5. Busca ese GUID en UEFITool hasta llegar al objeto NVRAM correspondiente. Abre **Body hex view** y navega hasta `VarOffset` con respecto al cuerpo de la variable, no a la imagen flash completa.<sup>[[3]](#references)</sup>
```bash
./ifrextractor Section_PE32_image_Setup_body.efi
rg -i 'dma|iommu|vt-d|secure boot' *.ifr.txt
```
Por ejemplo, una imagen de Dell describía la pregunta relevante como `Control Iommu Pre-boot Behavior`, con `VarStoreId: 0x1`, `VarOffset: 0x975` y un campo de 8 bits. El Store `0x1` estaba asociado a la variable `Setup` y al GUID `EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9`; los volcados diferenciales establecieron que `01` significaba habilitado y `00` deshabilitado en ese firmware.<sup>[[3]](#references)</sup>

> [!WARNING]
> Los GUID, offsets, diseños de estructuras, instancias de variables duplicadas y codificaciones de valores pueden cambiar entre modelos y versiones de firmware. Nunca reutilices el offset de ejemplo como un valor universal de Dell.

## Validate with differential dumps

Cuando la interfaz de configuración esté disponible en una unidad de prueba equivalente, crea un volcado con la opción habilitada y otro con ella deshabilitada. Compara el cuerpo de la variable derivado del IFR y confirma que solo cambie el campo esperado. Esto determina la codificación real y distingue una variable activa de copias obsoletas, predeterminadas o de recuperación. Modifica una copia de la imagen original verificada, vuelve a abrirla en UEFITool y confirma que la edición esté fuera de los rangos de código autenticados o medidos antes de volver a flashear.<sup>[[3]](#references)[[4]](#references)</sup>

Una edición específica puede tener menos efectos secundarios que borrar una contraseña de firmware, lo que podría activar un estado de fábrica, requerir que se vuelvan a introducir datos específicos del dispositivo o cambiar las mediciones de TPM PCR. Sin embargo, una edición offline específica también puede crear una peligrosa **divergencia entre el estado mostrado y el estado efectivo**: la interfaz de usuario y las herramientas de administración pueden mostrar el valor antiguo mientras el firmware temprano consume el byte modificado. El cambio demostrado no solicitó la recuperación de BitLocker y sobrevivió a una actualización del BIOS del proveedor porque la actualización conservó el estado de NVRAM alterado.<sup>[[3]](#references)</sup>

El [Dell UEFI Patcher](https://github.com/craigsblackie/Dell_UEFI_Patcher) del autor ilustra un patcher específico para un modelo que descubre los rangos de Intel Boot Guard Initial Boot Block y rechaza las escrituras normales dentro de ellos. Utiliza su modo de análisis antes de `--apply`, inspecciona cada coincidencia candidata y trata sus valores predeterminados como ejemplos, no como offsets portables.<sup>[[4]](#references)</sup>
```bash
python3 dell_bios_patcher.py bios_dump.bin
python3 dell_bios_patcher.py bios_dump.bin patched.bin --apply
```
## Automatiza el mapeo con NVRAMap

[NVRAMap](https://github.com/PN-Tester/NVRAMap) automatiza la extracción de IFR, resuelve el `VarStoreId` de una pregunta asociándolo con el GUID/nombre de NVRAM, muestra los valores actuales de las opciones y puede editar el campo seleccionado. Puede trabajar a partir de un volcado completo del firmware o de blobs EFI y NVRAM extraídos por separado.<sup>[[5]](#references)</sup>
```bash
# EFI question -> backing NVRAM value
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --dump-ifr ifr.txt

# Interactive editor after reviewing the mapping
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --modify
```
La automatización no elimina la necesidad de contar con dumps coincidentes, hardware de recuperación, comprobaciones de integridad de la región ni validación posterior al flash.

## Encadenar un downgrade de IOMMU pre-boot para obtener acceso DMA en Windows

Si el valor parcheado permite DMA de PCIe antes de ExitBootServices, [DMAReaper](https://github.com/PN-Tester/DMAReaper) puede recorrer desde la EFI System Table las tablas raíz de ACPI, localizar la tabla `DMAR` y sobrescribirla antes de que Windows la analice. Sin datos `DMAR` utilizables, Windows puede no inicializar Kernel DMA Protection respaldada por IOMMU. DMAReaper **no** deshabilita VBS/HVCI por sí solo.<sup>[[1]](#references)</sup>

En la cadena demostrada, el objetivo se inició posteriormente en Safe Mode para eliminar la barrera restante de VBS, y [PCILeech](https://github.com/ufrisk/pcileech) parcheó la memoria física con una firma de Sticky Keys:<sup>[[2]](#references)[[3]](#references)</sup>
```bash
sudo ./pcileech patch -sig stickykeys_cmd_win
```
Tras un parche compatible con la build aplicado correctamente, invocar Sticky Keys en la pantalla de inicio de sesión de Windows abría un símbolo del sistema como `NT AUTHORITY\SYSTEM`. Las firmas y los rangos de memoria accesibles dependen del objetivo, la build y el hardware; una coincidencia detectada no demuestra que todas las versiones de Windows sean explotables.<sup>[[2]](#references)[[3]](#references)</sup>

No confíes en el menú del firmware como validación. Comprueba **Información del sistema (`msinfo32.exe`) → Protección DMA del kernel**, verifica VBS por separado, inspecciona si el sistema operativo recibió una tabla DMAR válida y prueba la accesibilidad DMA real. Windows informa de la Protección DMA del kernel únicamente cuando la plataforma y el firmware admiten la configuración IOMMU requerida.<sup>[[6]](#references)</sup>

## References

- [1] [DMAReaper - Deshabilitar la Protección DMA del kernel mediante la sobrescritura de DMAR previa al arranque](https://github.com/PN-Tester/DMAReaper)
- [2] [PCILeech - Software de ataque de acceso directo a memoria](https://github.com/ufrisk/pcileech)
- [3] [MDSec - Deshabilitar funciones de seguridad en una BIOS bloqueada](https://mdsec.co.uk/2026/03/disabling-security-features-in-a-locked-bios)
- [4] [Dell UEFI Patcher - Patching de NVRAM compatible con IBB](https://github.com/craigsblackie/Dell_UEFI_Patcher)
- [5] [NVRAMap - Asignar ajustes EFI a valores de NVRAM](https://github.com/PN-Tester/NVRAMap)
- [6] [Microsoft Learn - Protección DMA del kernel](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [7] [UEFITool - Visor y analizador de imágenes de firmware UEFI](https://github.com/LongSoft/UEFITool)
- [8] [IFRExtractor-RS - Extraer IFR de UEFI a texto legible](https://github.com/LongSoft/IFRExtractor-RS)
- [9] [manual de flashrom - programadores y operaciones de lectura/escritura](https://flashrom.org/classic_cli_manpage.html)
{{#include ../../banners/hacktricks-training.md}}
