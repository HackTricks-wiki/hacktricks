# JTAG

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) es una herramienta que puedes cargar en un MCU compatible con Arduino o (experimentalmente) en una Raspberry Pi para forzar la búsqueda de pinouts JTAG desconocidos e incluso enumerar registros de instrucciones.

- Arduino: conecta los pines digitales D2–D11 a hasta 10 pads/puntos de prueba JTAG sospechosos, y GND de Arduino a GND del objetivo. Alimenta el objetivo por separado a menos que sepas que la línea es segura. Prefiere lógica de 3.3 V (por ejemplo, Arduino Due) o usa un convertidor de nivel/resistencias en serie al sondear objetivos de 1.8–3.3 V.
- Raspberry Pi: la construcción de Pi expone menos GPIO utilizables (por lo que los escaneos son más lentos); consulta el repositorio para el mapa de pines actual y las limitaciones.

Una vez flasheado, abre el monitor serial a 115200 baudios y envía `h` para ayuda. Flujo típico:

- `l` encontrar bucles para evitar falsos positivos
- `r` alternar pull‑ups internos si es necesario
- `s` escanear para TCK/TMS/TDI/TDO (y a veces TRST/SRST)
- `y` forzar IR para descubrir opcodes no documentados
- `x` instantánea de escaneo de frontera de estados de pines

![](<../../images/image (939).png>)

![](<../../images/image (578).png>)

![](<../../images/image (774).png>)

Si se encuentra un TAP válido, verás líneas que comienzan con `FOUND!` indicando pines descubiertos.

Consejos
- Siempre comparte tierra, y nunca impulsa pines desconocidos por encima de Vtref del objetivo. Si tienes dudas, añade resistencias en serie de 100–470 Ω en los pines candidatos.
- Si el dispositivo utiliza SWD/SWJ en lugar de JTAG de 4 hilos, JTAGenum puede no detectarlo; prueba herramientas SWD o un adaptador que soporte SWJ‑DP.

## Búsqueda de pines más segura y configuración de hardware

- Identifica Vtref y GND primero con un multímetro. Muchos adaptadores necesitan Vtref para establecer el voltaje de I/O.
- Cambio de nivel: prefiere convertidores de nivel bidireccionales diseñados para señales push‑pull (las líneas JTAG no son de drenaje abierto). Evita convertidores I2C de auto-dirección para JTAG.
- Adaptadores útiles: placas FT2232H/FT232H (por ejemplo, Tigard), CMSIS‑DAP, J‑Link, ST‑LINK (específicos del proveedor), ESP‑USB‑JTAG (en ESP32‑Sx). Conecta al menos TCK, TMS, TDI, TDO, GND y Vtref; opcionalmente TRST y SRST.

## Primer contacto con OpenOCD (escaneo e IDCODE)

OpenOCD es el OSS de facto para JTAG/SWD. Con un adaptador compatible puedes escanear la cadena y leer IDCODEs:

- Ejemplo genérico con un J‑Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- ESP32‑S3 USB‑JTAG integrado (no se requiere sonda externa):
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
Notas
- Si obtienes un IDCODE de "todos unos/ceros", verifica el cableado, la alimentación, Vtref y que el puerto no esté bloqueado por fusibles/bits de opción.
- Consulta OpenOCD bajo nivel `irscan`/`drscan` para interacción manual con TAP al iniciar cadenas desconocidas.

## Detener la CPU y volcar memoria/flash

Una vez que se reconoce el TAP y se elige un script de destino, puedes detener el núcleo y volcar regiones de memoria o flash interno. Ejemplos (ajusta el destino, las direcciones base y los tamaños):
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (prefiere SBA cuando esté disponible):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programa o lee a través del asistente OpenOCD:
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
Tips
- Usa `mdw/mdh/mdb` para verificar la memoria antes de volcar grandes cantidades.
- Para cadenas de múltiples dispositivos, establece BYPASS en no objetivos o usa un archivo de placa que defina todos los TAPs.

## Trucos de escaneo de límites (EXTEST/SAMPLE)

Incluso cuando el acceso de depuración de la CPU está bloqueado, el escaneo de límites puede seguir estando expuesto. Con UrJTAG/OpenOCD puedes:
- SAMPLE para capturar el estado de los pines mientras el sistema está en funcionamiento (encontrar actividad en el bus, confirmar el mapeo de pines).
- EXTEST para controlar los pines (por ejemplo, bit-bang líneas SPI externas a través del MCU para leerlas sin conexión si el cableado de la placa lo permite).

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
Necesitas el BSDL del dispositivo para conocer el orden de los bits del registro de límite. Ten en cuenta que algunos proveedores bloquean las celdas de escaneo de límite en producción.

## Objetivos modernos y notas

- ESP32‑S3/C3 incluyen un puente USB‑JTAG nativo; OpenOCD puede comunicarse directamente a través de USB sin una sonda externa. Muy conveniente para triage y volcados.
- La depuración RISC‑V (v0.13+) es ampliamente soportada por OpenOCD; se prefiere SBA para el acceso a memoria cuando el núcleo no puede ser detenido de manera segura.
- Muchos MCU implementan autenticación de depuración y estados de ciclo de vida. Si JTAG parece muerto pero la alimentación es correcta, el dispositivo puede estar fusionado en un estado cerrado o requiere una sonda autenticada.

## Defensas y endurecimiento (qué esperar en dispositivos reales)

- Desactivar permanentemente o bloquear JTAG/SWD en producción (por ejemplo, STM32 RDP nivel 2, eFuses de ESP que desactivan PAD JTAG, NXP/Nordic APPROTECT/DPAP).
- Requerir depuración autenticada (ARMv8.2‑A ADIv6 Autenticación de Depuración, desafío-respuesta gestionado por OEM) mientras se mantiene el acceso de fabricación.
- No enrutar almohadillas de prueba fáciles; enterrar vías de prueba, quitar/poblar resistencias para aislar TAP, usar conectores con codificación o fijaciones de pogo-pin.
- Bloqueo de depuración al encender: proteger el TAP detrás de un ROM temprano que impone un arranque seguro.

## Referencias

- OpenOCD User’s Guide – JTAG Commands and configuration. https://openocd.org/doc-release/html/JTAG-Commands.html
- Espressif ESP32‑S3 JTAG debugging (USB‑JTAG, OpenOCD usage). https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/

{{#include ../../banners/hacktricks-training.md}}
