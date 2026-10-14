# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

**JTAGenum** es una herramienta que puedes cargar en un MCU compatible con Arduino o, de forma experimental, en una Raspberry Pi para hacer brute-force de pinouts JTAG desconocidos y enumerar registros de instrucciones.<sup>[[3]](#references)</sup>

- Arduino: conecta los pines digitales D2–D11 a un máximo de 10 pads/testpoints JTAG sospechosos y conecta GND de Arduino a GND del objetivo. Alimenta el objetivo por separado, a menos que sepas que el raíl es seguro. Prefiere lógica de 3,3 V (p. ej., Arduino Due) o usa un level shifter/resistencias en serie al sondear objetivos de 1,8–3,3 V.
- Raspberry Pi: la compilación para Pi ofrece menos GPIO utilizables (por lo que los escaneos son más lentos); consulta el repositorio para ver el mapa de pines y las limitaciones actuales.

Una vez cargado el firmware, abre el monitor serie a 115200 baudios y envía `h` para obtener ayuda. Flujo típico:

- `l` busca loopbacks para evitar falsos positivos
- `r` activa o desactiva las pull-ups internas si es necesario
- `s` busca TCK/TMS/TDI/TDO (y, a veces, TRST/SRST)
- `y` hace brute-force del IR para descubrir opcodes no documentados
- `x` toma una instantánea boundary-scan de los estados de los pines

![JTAG - JTAGenum: x instantánea boundary-scan de los estados de los pines](<../../images/image (939).png>)

![JTAG - JTAGenum: x instantánea boundary-scan de los estados de los pines](<../../images/image (578).png>)

![JTAG - JTAGenum: x instantánea boundary-scan de los estados de los pines](<../../images/image (774).png>)



Si se encuentra un TAP válido, verás líneas que empiezan por `FOUND!` e indican los pines descubiertos.

### Consejos de seguridad para JTAGenum

- Comparte siempre la conexión a tierra y nunca apliques a pines desconocidos un voltaje superior a Vtref del objetivo. Si tienes dudas, añade resistencias de 100–470 Ω en serie a los pines candidatos.
- Si el dispositivo usa SWD/SWJ en lugar de JTAG de 4 cables, es posible que JTAGenum no lo detecte; prueba herramientas SWD o un adaptador compatible con SWJ-DP.

## Búsqueda más segura de pines y configuración del hardware

- Identifica primero Vtref y GND con un multímetro. Muchos adaptadores necesitan Vtref para establecer el voltaje de E/S.
- Adaptación de nivel: prefiere level shifters bidireccionales diseñados para señales push-pull (las líneas JTAG no son open-drain). Evita los shifters I2C de dirección automática para JTAG.
- Adaptadores útiles: placas FT2232H/FT232H (p. ej., Tigard), CMSIS-DAP, J-Link, ST-LINK (específico del proveedor), ESP-USB-JTAG (en ESP32-Sx). Conecta como mínimo TCK, TMS, TDI, TDO, GND y Vtref; opcionalmente TRST y SRST.

## Primer contacto con OpenOCD (escaneo e IDCODE)

OpenOCD es el OSS de facto para JTAG/SWD. Con un adaptador compatible puedes escanear la cadena y leer los IDCODEs:<sup>[[1]](#references)</sup>

- Ejemplo genérico con un J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- USB-JTAG integrado en ESP32-S3 (no se requiere una sonda externa):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Notas

- Si obtienes un IDCODE de «todo unos/ceros», comprueba el cableado, la alimentación, Vtref y que los fusibles/option bytes no hayan bloqueado el puerto.
- Consulta `irscan`/`drscan` de bajo nivel de OpenOCD para interactuar manualmente con el TAP al poner en marcha cadenas desconocidas.<sup>[[1]](#references)</sup>

## Detener la CPU y volcar la memoria/flash

Una vez reconocido el TAP y elegido un script de target, puedes detener el core y volcar regiones de memoria o la flash interna. Ejemplos (ajusta el target, las direcciones base y los tamaños):<sup>[[1]](#references)</sup>

- Target genérico después de la inicialización:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
  -c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (preferiblemente SBA cuando esté disponible):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
  -c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programar o leer mediante el helper de OpenOCD:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
  -c "program_esp app.bin 0x10000 verify exit"
```

### Consejos para volcar memoria

- Usa `mdw/mdh/mdb` para comprobar la memoria antes de hacer volcados largos.
- En cadenas con varios dispositivos, configura BYPASS en los que no sean el objetivo o usa un archivo de placa que defina todos los TAPs.

## Trucos de boundary-scan (EXTEST/SAMPLE)

Aunque el acceso de depuración de la CPU esté bloqueado, puede que boundary-scan siga expuesto. Con UrJTAG/OpenOCD puedes:<sup>[[1]](#references)</sup>
- Usar SAMPLE para capturar el estado de los pines mientras el sistema está en funcionamiento (detectar actividad del bus y confirmar el mapeo de pines).
- Usar EXTEST para controlar los pines (por ejemplo, hacer bit-bang de las líneas de SPI flash externas mediante el MCU para leerla sin conexión, si el cableado de la placa lo permite).

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
Necesitas el BSDL del dispositivo para conocer el orden de bits del registro boundary-scan. Ten en cuenta que algunos fabricantes bloquean las celdas boundary-scan durante la producción.

## Objetivos modernos y notas

- ESP32‑S3/C3 incluyen un puente USB‑JTAG nativo; OpenOCD puede comunicarse directamente por USB sin una sonda externa. Muy práctico para triage y dumps.<sup>[[2]](#references)</sup>
- La depuración RISC‑V (v0.13+) es ampliamente compatible con OpenOCD; prefiere SBA para acceder a la memoria cuando no se puede detener el core de forma segura.
- Muchos MCU implementan autenticación de depuración y estados de ciclo de vida. Si JTAG parece inactivo pero la alimentación es correcta, es posible que el dispositivo esté fundido en un estado cerrado o requiera una sonda autenticada.

## Defensas y endurecimiento (qué esperar en dispositivos reales)

- Deshabilitar o bloquear permanentemente JTAG/SWD en producción (p. ej., STM32 RDP nivel 2, eFuses de ESP que deshabilitan PAD JTAG, APPROTECT/DPAP de NXP/Nordic).
- Exigir depuración autenticada (ARMv8.2‑A ADIv6 Debug Authentication, desafío‑respuesta gestionado por el OEM) y mantener el acceso de fabricación.
- No enrutar pads de prueba fácilmente accesibles; ocultar las vías de prueba, quitar/instalar resistencias para aislar TAP y usar conectores con guías de alineación o fixtures de pogo pins.
- Bloqueo de depuración al encender: poner el TAP detrás de una ROM inicial que aplique secure boot.

## References

- [1] [Guía del usuario de OpenOCD – comandos y configuración de JTAG](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Depuración JTAG de Espressif ESP32‑S3 (USB‑JTAG, uso de OpenOCD)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – escáner de pinout JTAG basado en Arduino](https://github.com/cyphunk/JTAGenum)
{{#include ../../banners/hacktricks-training.md}}
