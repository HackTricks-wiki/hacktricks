# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## Búsqueda más segura de pines y configuración del hardware

- Identifica primero Vtref y GND con un multímetro. Muchos adaptadores necesitan Vtref para establecer el voltaje de E/S.
- Adaptación de nivel: prefiere conversores de nivel bidireccionales diseñados para señales push-pull (las líneas JTAG no son open-drain). Evita los conversores I2C de dirección automática para JTAG.
- Adaptadores útiles: placas FT2232H/FT232H (p. ej., Tigard), CMSIS-DAP, J-Link, ST-LINK (específico del fabricante), ESP-USB-JTAG (en ESP32-Sx). Conecta como mínimo TCK, TMS, TDI, TDO, GND y Vtref; opcionalmente, TRST y SRST.

Para identificar un conector no documentado, encuentra GND comprobando la continuidad con un plano de tierra conocido **mientras el dispositivo está apagado**. Después de cambiar al modo de voltaje y encenderlo, no clasifiques todos los pines con voltaje alto como Vtref: las entradas digitales en estado alto pueden parecer similares en un multímetro. Sigue las pistas de los posibles rieles hasta los condensadores de desacoplamiento cercanos y compara sus formas de onda al encender y apagar con un osciloscopio. Una subida o bajada más lenta, con forma de carga o descarga de un condensador, indica que podría tratarse de una red de alimentación o referencia; aun así, verifica el voltaje y el cableado antes de conectar una sonda con adaptación de nivel. En PiFex, se puede seleccionar una referencia externa de menor voltaje para el dispositivo mediante `VCCA_IN`, en lugar del valor predeterminado de 3,3 V.<sup>[[4]](#references)</sup>

## JTAGenum

**JTAGenum** es una herramienta que puedes cargar en un MCU compatible con Arduino o, de forma experimental, en una Raspberry Pi para probar por fuerza bruta distribuciones de pines JTAG desconocidas y enumerar registros de instrucciones.<sup>[[3]](#references)</sup>

- Arduino: conecta los pines digitales D2–D11 a un máximo de 10 pads/puntos de prueba JTAG sospechosos y el pin GND de Arduino a GND del dispositivo. Alimenta el dispositivo por separado, a menos que sepas que es seguro usar su riel de alimentación. Prefiere lógica de 3,3 V (p. ej., Arduino Due) o utiliza un conversor de nivel/resistencias en serie al sondear dispositivos de 1,8–3,3 V.
- Raspberry Pi: la compilación para Pi expone menos GPIO utilizables (por lo que los escaneos son más lentos); consulta el repositorio para ver la asignación de pines y las limitaciones actuales.

Una vez flasheado, abre el monitor serial a 115200 baudios y envía `h` para obtener ayuda. Flujo habitual:

- `l` busca loopbacks para evitar falsos positivos
- `r` activa o desactiva los pull-ups internos si es necesario
- `s` busca TCK/TMS/TDI/TDO (y, a veces, TRST/SRST)
- `y` prueba por fuerza bruta el IR para descubrir opcodes no documentados
- `x` captura una instantánea boundary-scan de los estados de los pines

![JTAG - JTAGenum: x instantánea boundary-scan de los estados de los pines](<../../images/image (939).png>)

![JTAG - JTAGenum: x instantánea boundary-scan de los estados de los pines](<../../images/image (578).png>)

![JTAG - JTAGenum: x instantánea boundary-scan de los estados de los pines](<../../images/image (774).png>)



Si se encuentra un TAP válido, verás líneas que empiezan por `FOUND!` e indican los pines descubiertos.

### Consejos de seguridad para JTAGenum

- Comparte siempre la conexión a tierra y nunca apliques a pines desconocidos un voltaje superior al Vtref del dispositivo. Si tienes dudas, añade resistencias en serie de 100–470 Ω a los pines candidatos.
- Si el dispositivo utiliza SWD/SWJ en lugar de JTAG de 4 cables, es posible que JTAGenum no lo detecte; prueba herramientas SWD o un adaptador compatible con SWJ-DP.

## Descubrimiento de pines GPIO con go-jtagenum

En un dispositivo encendido, con una conexión a tierra común verificada y un voltaje de E/S compatible, `go-jtagenum` puede enumerar señales JTAG candidatas desde los GPIO de Raspberry Pi. El JSON de `-pins` asigna etiquetas a **números GPIO**, no a posiciones físicas del conector.<sup>[[5]](#references)</sup> En el ejemplo del SSD, el primer escaneo de IDCODE también informó una cadena inverosímilmente larga de valores cambiantes: que una línea TDO candidata cambie por sí sola no demuestra que haya un TAP válido. Vuelve a comprobar un resultado plausible con un escaneo BYPASS, que desplaza un patrón de bits conocido desde TDI, a través del registro bypass de un bit, hasta TDO.<sup>[[4]](#references)</sup>

```bash
PINS='{ "pin2": 2, "pin3": 3, "pin9": 9, "pin10": 10, "pin14": 14, "pin15": 15 }'
go-jtagenum -pins "$PINS" -command scan_idcode -delay-tck 50
go-jtagenum -pins "$PINS" -command scan_bypass -delay-tck 50
```

Para esa placa, BYPASS confirmó `TCK=10`, `TMS=14`, `TDI=9` y `TDO=15`; los pines adicionales eran solo posibles candidatos a nTRST. Si un candidato devuelve solo ceros o un patrón incoherente, comprueba el contacto, la alimentación del objetivo, las resistencias pull-up y los retardos del reloj/reset antes de asignarle una señal.<sup>[[4]](#references)[[5]](#references)</sup> La herramienta también acepta `-known-pins` con `test_bypass` para volver a probar una asignación recuperada.<sup>[[5]](#references)</sup>

## Caracterizar un TAP sin documentar con UrJTAG

Un pinout descubierto no identifica los códigos de operación del registro de instrucciones (IR) ni los anchos de los registros de datos (DR) necesarios para la depuración. Con una compilación de UrJTAG compatible con el cable GPIO de Raspberry Pi, configura la asignación recuperada y ejecuta `idcode`, luego `detect` y después `discover`. El ejemplo del SSD devolvió un TAP, un IR de cuatro bits y distintos anchos de DR para diferentes valores de IR. Una longitud de DR de `-1` o el mensaje “TDO stuck at 0” no constituyen una definición de registro utilizable; inspecciona la temporización, el cableado y la instrucción seleccionada en lugar de asignarle un ancho.<sup>[[4]](#references)</sup>

```text
jtag> cable gpio tck=10 tdi=9 tms=14 tdo=15
jtag> idcode
jtag> detect
jtag> discover
```

Esto es reconocimiento TAP, no identificación automática de CPU: compara el IDCODE obtenido con la documentación del dispositivo y los targets de OpenOCD compatibles. La base de datos local de fabricantes de UrJTAG puede marcar como desconocido un ID válido.<sup>[[4]](#references)</sup>

## Primer contacto con OpenOCD (escaneo e IDCODE)

OpenOCD es el OSS de facto para JTAG/SWD. Con un adaptador compatible, puedes escanear la cadena y leer los IDCODE:<sup>[[1]](#references)</sup>

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

- Si obtienes un IDCODE de «todo unos/ceros», comprueba el cableado, la alimentación, Vtref y que los fusibles/bytes de opción no hayan bloqueado el puerto.
- Consulta `irscan`/`drscan` de bajo nivel de OpenOCD para interactuar manualmente con el TAP al poner en marcha cadenas desconocidas.<sup>[[1]](#references)</sup>

## Incorporar un target sin documentar a OpenOCD

Una vez que conozcas el ID del TAP y la longitud del IR, revisa los scripts `cpu/`, `target/` y `board/` de OpenOCD para encontrar una **arquitectura de CPU compatible** y, después, crea configuraciones separadas para el adaptador y el target.<sup>[[4]](#references)[[6]](#references)</sup> La asignación de GPIO del Pi y el target ARCv2 siguientes son el ejemplo probado con un SSD, no una configuración JTAG universal. La elección del target ARC y los ajustes de depuración fueron suposiciones que funcionaron con este dispositivo; en otra placa, sustituye esos valores por el ID, la longitud del IR, la arquitectura y los números de GPIO medidos para el target.<sup>[[4]](#references)</sup>

```tcl
# raspberrypi-io.cfg
source [find interface/raspberrypi-native.cfg]
transport select jtag
adapter gpio tck -chip 0 10
adapter gpio tms -chip 0 14
adapter gpio tdi -chip 0 9
adapter gpio tdo -chip 0 15
adapter speed 100
```

```tcl
# target.cfg: ARCv2 example only
source [find cpu/arc/hs.tcl]
set _CHIPNAME arc-em
set _TARGETNAME $_CHIPNAME.cpu
jtag newtap $_CHIPNAME cpu -irlen 4 -ircapture 0x1 -expected-id 0x100434b1
target create $_TARGETNAME arcv2 -chain-position $_TARGETNAME
$_TARGETNAME configure -coreid 0
$_TARGETNAME configure -dbgbase 0
$_TARGETNAME configure -event reset-assert "arc_hs_reset $_TARGETNAME"
arc_hs_init_regs
$_TARGETNAME arc cache l2 auto 1
```

Ejecuta `openocd -f raspberrypi-io.cfg -f target.cfg` y confirma que el examen del TAP se complete correctamente antes de leer la memoria. En el ejemplo, se abrió Telnet en el puerto `4444` y un servidor GDB en el puerto `3333`; que se reconozca un IDCODE no demuestra por sí solo que se pueda examinar o depurar el target de CPU seleccionado.<sup>[[4]](#references)</sup> No es necesario que los GPIO de Raspberry Pi sean los pines etiquetados como JTAG en una placa breakout si el adaptador permite reasignarlos mediante `adapter gpio`.<sup>[[4]](#references)[[6]](#references)</sup>

## Detener la CPU y volcar la memoria/flash

Una vez reconocido el TAP y elegido un script de target, puedes detener el core y volcar regiones de memoria o la flash interna. Ejemplos (ajusta el target, las direcciones base y los tamaños):<sup>[[1]](#references)</sup>

- Target genérico después de la inicialización:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
  -c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (preferir SBA cuando esté disponible):
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

- Usa `mdw/mdh/mdb` para comprobar rápidamente la memoria antes de hacer volcados largos.
- En cadenas con varios dispositivos, configura BYPASS en los que no sean el objetivo o usa un archivo de placa que defina todos los TAP.

Para un mapa de memoria sin documentar, la investigación del SSD comprobó un volcado de 1 MiB en busca de cadenas reconocibles del controlador y luego usó un GDB compatible con la arquitectura mediante OpenOCD para inspeccionar `$pc`, el desensamblado y los registros. Esas direcciones en tiempo real guiaron un segundo volcado de región, que se comprobó comparándolo con instrucciones coincidentes en una compilación de Ghidra compatible con ARC. Las cadenas por sí solas solo sirven como comprobación de plausibilidad, no demuestran que la imagen esté completa ni que esté mapeada correctamente.<sup>[[4]](#references)</sup> Consulta [análisis de firmware](../firmware-analysis/) para conocer pasos más amplios de análisis estático.

## Trucos de boundary-scan (EXTEST/SAMPLE)

Aunque el acceso de depuración de la CPU esté bloqueado, el boundary-scan podría seguir expuesto. Con UrJTAG/OpenOCD puedes:<sup>[[1]](#references)</sup>
- Usar SAMPLE para capturar el estado de los pines mientras el sistema está en ejecución (detectar actividad del bus y confirmar el mapeo de pines).
- Usar EXTEST para controlar los pines (por ejemplo, controlar por bit-banging las líneas de una memoria flash SPI externa mediante el MCU para leerla sin conexión, si el cableado de la placa lo permite).

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
Necesitas el BSDL del dispositivo para conocer el orden de bits del boundary register. Ten en cuenta que algunos fabricantes bloquean las celdas de boundary-scan durante la producción.

## Objetivos modernos y notas

- ESP32‑S3/C3 incluyen un puente USB‑JTAG nativo; OpenOCD puede comunicarse directamente por USB sin una sonda externa. Muy práctico para triage y volcados.<sup>[[2]](#references)</sup>
- La depuración RISC‑V (v0.13+) es ampliamente compatible con OpenOCD; prefiere SBA para acceder a la memoria cuando no se puede detener el core de forma segura.
- Muchos MCU implementan autenticación de depuración y estados del ciclo de vida. Si JTAG parece no responder, pero la alimentación es correcta, es posible que el dispositivo tenga los fuses configurados para un estado cerrado o requiera una sonda autenticada.

## Defensas y hardening (qué esperar en dispositivos reales)

- Deshabilita o bloquea JTAG/SWD de forma permanente en producción (p. ej., STM32 RDP nivel 2, eFuses de ESP que deshabilitan PAD JTAG, APPROTECT/DPAP de NXP/Nordic).
- Exige autenticación para la depuración (ARMv8.2‑A ADIv6 Debug Authentication, challenge-response gestionado por el OEM) sin perder el acceso de fabricación.
- Evita enrutar fácilmente los test pads; oculta las vías de prueba, quita o instala resistencias para aislar el TAP y usa conectores con guías o fixtures con pogo pins.
- Bloqueo de depuración al encender: pon el TAP detrás de una ROM temprana que aplique secure boot.

## References

- [1] [Guía del usuario de OpenOCD: comandos y configuración de JTAG](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Depuración JTAG de Espressif ESP32‑S3 (USB‑JTAG, uso de OpenOCD)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum: escáner de pinout JTAG basado en Arduino](https://github.com/cyphunk/JTAGenum)
- [4] [VoidStar Security: hacking de JTAG con una Raspberry Pi](https://voidstarsec.com/blog/jtag-pifex)
- [5] [gremwell/go-jtagenum: enumeración JTAG mediante GPIO](https://github.com/gremwell/go-jtagenum)
- [6] [Guía del usuario de OpenOCD: configuración del adaptador de depuración](https://openocd.org/doc-release/html/Debug-Adapter-Configuration.html)
{{#include ../../banners/hacktricks-training.md}}
