# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

**JTAGenum** es una herramienta que puedes cargar en un MCU compatible con Arduino o, de forma experimental, en una Raspberry Pi para hacer brute-force de pinouts JTAG desconocidos y enumerar registros de instrucciones.<sup>[[3]](#references)</sup>

- Arduino: conecta los pines digitales D2–D11 a un máximo de 10 pads/puntos de prueba JTAG sospechosos, y GND del Arduino a GND del objetivo. Alimenta el objetivo por separado, a menos que sepas que el rail es seguro. Prefiere lógica de 3.3 V (por ejemplo, Arduino Due) o utiliza un level shifter/resistencias en serie al probar objetivos de 1.8–3.3 V.
- Raspberry Pi: la build para Pi expone menos GPIO utilizables (por lo que los escaneos son más lentos); consulta el repo para conocer el mapa de pines y las restricciones actuales.

Una vez cargado el firmware, abre el monitor serie a 115200 baudios y envía `h` para obtener ayuda. Flujo habitual:

- `l` busca loopbacks para evitar falsos positivos
- `r` alterna los pull-ups internos si es necesario
- `s` busca TCK/TMS/TDI/TDO (y, a veces, TRST/SRST)
- `y` hace brute-force del IR para descubrir opcodes no documentados
- `x` obtiene una instantánea boundary-scan de los estados de los pines

![JTAG - JTAGenum: x instantánea boundary-scan de los estados de los pines](<../../images/image (939).png>)

![JTAG - JTAGenum: x instantánea boundary-scan de los estados de los pines](<../../images/image (578).png>)

![JTAG - JTAGenum: x instantánea boundary-scan de los estados de los pines](<../../images/image (774).png>)



Si se encuentra un TAP válido, verás líneas que comienzan con `FOUND!` e indican los pines descubiertos.

### Consejos de seguridad para JTAGenum

- Comparte siempre la conexión a tierra y nunca conectes pines desconocidos por encima de Vtref del objetivo. En caso de duda, añade resistencias de 100–470 Ω en serie a los pines candidatos.
- Si el dispositivo utiliza SWD/SWJ en lugar de JTAG de 4 cables, es posible que JTAGenum no lo detecte; prueba herramientas SWD o un adaptador compatible con SWJ-DP.

## Búsqueda más segura de pines y configuración del hardware

- Identifica primero Vtref y GND con un multímetro. Muchos adaptadores necesitan Vtref para establecer el voltaje de I/O.
- Level shifting: prefiere level shifters bidireccionales diseñados para señales push-pull (las líneas JTAG no son open-drain). Evita los shifters I2C de dirección automática para JTAG.
- Adaptadores útiles: placas FT2232H/FT232H (por ejemplo, Tigard), CMSIS-DAP, J-Link, ST-LINK (específico del proveedor), ESP-USB-JTAG (en ESP32-Sx). Conecta como mínimo TCK, TMS, TDI, TDO, GND y Vtref; TRST y SRST son opcionales.

## Primer contacto con OpenOCD (escaneo e IDCODE)

OpenOCD es el OSS de facto para JTAG/SWD. Con un adaptador compatible puedes escanear la cadena y leer los IDCODEs:<sup>[[1]](#references)</sup>

- Ejemplo genérico con un J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- USB-JTAG integrado del ESP32-S3 (no requiere una sonda externa):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Notas

- Si obtienes un IDCODE de "todo unos/todo ceros", comprueba el cableado, la alimentación, Vtref y que el puerto no esté bloqueado por fusibles/option bytes.
- Consulta `irscan`/`drscan` de bajo nivel de OpenOCD para interactuar manualmente con el TAP al poner en marcha cadenas desconocidas.<sup>[[1]](#references)</sup>

## Detener la CPU y volcar la memoria/flash

Una vez reconocido el TAP y elegido un target script, puedes detener el core y volcar regiones de memoria o la flash interna. Ejemplos (ajusta el target, las direcciones base y los tamaños):<sup>[[1]](#references)</sup>

- Target genérico después de la inicialización:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (prefer SBA when available):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programar o leer mediante el helper de OpenOCD:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
### Consejos para volcado de memoria

- Usa `mdw/mdh/mdb` para comprobar que la memoria es coherente antes de realizar volcados largos.
- Para cadenas con varios dispositivos, configura BYPASS en los dispositivos que no sean objetivos o usa un archivo de placa que defina todos los TAP.

## Trucos de boundary-scan (EXTEST/SAMPLE)

Aunque el acceso de depuración de la CPU esté bloqueado, boundary-scan aún puede estar expuesto. Con UrJTAG/OpenOCD puedes:<sup>[[1]](#references)</sup>
- Usar SAMPLE para capturar el estado de los pines mientras el sistema está en ejecución (encontrar actividad del bus y confirmar el mapeo de pines).
- Usar EXTEST para controlar los pines (por ejemplo, hacer bit-banging de las líneas de una memoria flash SPI externa a través del MCU para leerla sin conexión, si el cableado de la placa lo permite).

Flujo mínimo de UrJTAG con un adaptador FT2232x:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
Necesitas el BSDL del dispositivo para conocer el orden de los bits del registro boundary. Ten en cuenta que algunos proveedores bloquean las celdas de boundary-scan en producción.

## Objetivos modernos y notas

- ESP32-S3/C3 incluyen un puente USB-JTAG nativo; OpenOCD puede comunicarse directamente por USB sin una probe externa. Muy conveniente para el triage y los dumps.<sup>[[2]](#references)</sup>
- La depuración RISC-V (v0.13+) es ampliamente compatible con OpenOCD; prefiere SBA para el acceso a memoria cuando no se puede detener el core de forma segura.
- Muchos MCU implementan autenticación de debug y estados de ciclo de vida. Si JTAG parece no funcionar pero la alimentación es correcta, el dispositivo puede estar fundido en un estado cerrado o requerir una probe autenticada.

## Defensas y hardening (qué esperar en dispositivos reales)

- Deshabilitar o bloquear permanentemente JTAG/SWD en producción (por ejemplo, STM32 RDP level 2, eFuses de ESP que deshabilitan PAD JTAG, APPROTECT/DPAP de NXP/Nordic).
- Requerir debug autenticado (ARMv8.2-A ADIv6 Debug Authentication, challenge-response gestionado por el OEM) mientras se mantiene el acceso de fabricación.
- No enrutar test pads de fácil acceso; enterrar las vías de test, retirar o instalar resistencias para aislar el TAP y usar conectores con keying o fixtures de pogo-pin.
- Bloqueo del debug durante el encendido: colocar el TAP detrás de una ROM temprana que imponga secure boot.

## References

- [1] [Guía del usuario de OpenOCD – comandos y configuración de JTAG](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Depuración JTAG de Espressif ESP32-S3 (USB-JTAG, uso de OpenOCD)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – escáner de pinout JTAG basado en Arduino](https://github.com/cyphunk/JTAGenum)
{{#include ../../banners/hacktricks-training.md}}
