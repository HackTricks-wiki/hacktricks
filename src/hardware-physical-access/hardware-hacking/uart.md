# UART

{{#include ../../banners/hacktricks-training.md}}

## Información básica

UART es una interfaz serial asíncrona que transfiere un flujo de bits enmarcado sin un reloj compartido. No confundas UART a nivel lógico con RS-232: RS-232 utiliza niveles de voltaje diferentes, a menudo negativos, y requiere un transceptor.<sup>[[1]](#references)[[3]](#references)</sup>

Por lo general, la línea se mantiene en nivel alto (valor lógico 1) mientras UART está en estado inactivo. Luego, para señalar el inicio de una transferencia de datos, el transmisor envía un bit de inicio al receptor, durante el cual la señal se mantiene en nivel bajo (valor lógico 0). A continuación, el transmisor envía de cinco a ocho bits de datos que contienen el mensaje real, seguidos de un bit de paridad opcional y uno o dos bits de parada (con valor lógico 1), según la configuración. El bit de paridad, que se utiliza para comprobar errores, rara vez se ve en la práctica. El bit o los bits de parada indican el final de la transmisión.

La configuración más común es 8N1: ocho bits de datos, sin paridad y un bit de parada. UART envía primero el bit de datos menos significativo, así que ASCII `C` (`0x43`) se transmite como: inicio `0`; datos `1, 1, 0, 0, 0, 0, 1, 0`; parada `1`.<sup>[[1]](#references)</sup>

![UART: A la configuración más común la llamamos 8N1: ocho bits de datos, sin paridad y un bit de parada. Por ejemplo, si quisiéramos enviar el carácter C, o 0x43 en ASCII, mediante UART 8N1](<../../images/image (764).png>)

Herramientas de hardware para comunicarse con UART:

- Adaptador USB a serial
- Adaptadores con chips CP2102 o PL2303
- Herramientas multipropósito como Bus Pirate, Adafruit FT232H, Shikra o Attify Badge

### Identificación de puertos UART

Un conector de depuración típico expone **TX**, **RX** y **GND**; también puede exponer un pin **Vcc/Vref**, de reinicio o de control de flujo. Vcc no es una señal UART y normalmente solo debe usarse como referencia de voltaje, no conectarse como fuente de alimentación, a menos que se conozcan el esquema de la placa y los requisitos de corriente.<sup>[[2]](#references)[[3]](#references)</sup>

Empieza con el dispositivo **apagado** y desconectado:

- Identifica **GND** en modo de continuidad, comparándolo con un plano de tierra conocido, el blindaje del conector o la tierra de la fuente de alimentación. Nunca uses el modo de continuidad/resistencia con una placa encendida.
- Cambia al modo de voltaje DC antes de encender el objetivo. Mide los pines candidatos respecto a tierra para identificar el voltaje lógico. Una línea de alimentación estable puede ser Vcc/Vref; no des por hecho que es seguro conectarse a ella.
- Observa los pines candidatos con un analizador lógico o un osciloscopio durante el arranque. **TX** suele estar inactivo en nivel alto y mostrar ráfagas de datos enmarcados. Un multímetro puede mostrar fluctuaciones promedio, pero no permite validar el enmarcado ni la velocidad en baudios.
- **RX** puede permanecer inactivo y no se puede identificar de forma segura solo porque esté junto a TX. Sigue las pistas de la PCB, consulta la hoja de datos del SoC o usa un analizador de alta impedancia antes de aplicar señales.

Intercambiar TX y RX normalmente no produce comunicación; confundir la alimentación, la tierra o los niveles de señal puede dañar permanentemente el objetivo o el adaptador. Conecta primero la tierra y comienza **solo en modo de recepción** (TX del objetivo a RX del adaptador).

Los fabricantes pueden omitir el conector, dejar sin montar las resistencias en serie, desactivar la consola en el firmware o exponer solo TX. Sigue las pistas de los puntos de prueba cercanos y las huellas de las resistencias hasta el SoC, y añade una conexión temporal de alta impedancia solo después de confirmar el nivel eléctrico. Que exista una garantía no implica que tenga que haber un UART accesible.

### Identificación de la velocidad en baudios de UART

La forma más fácil de identificar la velocidad en baudios correcta es observar la salida del pin **TX** e intentar leer los datos. Si los datos que recibes no son legibles, prueba la siguiente velocidad en baudios posible hasta que los datos sean legibles. Puedes usar un adaptador USB a serial o un dispositivo multipropósito como Bus Pirate, junto con un script auxiliar como [baudrate.py](https://github.com/devttys0/baudrate/). Las velocidades en baudios más comunes son 9600, 38400, 19200, 57600 y 115200.

> [!CAUTION]
> ¡Es importante tener en cuenta que en este protocolo debes conectar el TX de un dispositivo al RX del otro!

### Automatización de la captura UART durante el arranque con SCPI

Si la salida de arranque es breve o aún no se conoce el pad TX, automatiza los arranques repetidos en lugar de manejar la fuente de alimentación y el osciloscopio manualmente. Conecta una fuente programable con límite de corriente a la entrada de alimentación verificada del objetivo. Sondea cada pad TX candidato con una entrada de osciloscopio de alta impedancia y una tierra común; no apliques señales al pad.<sup>[[5]](#references)</sup>

VISA abre sesiones con instrumentos seriales o Ethernet, mientras que SCPI controla la salida, el disparo y la lectura de formas de onda.<sup>[[5]](#references)[[6]](#references)</sup> Instala `pyvisa` y `pyvisa-py` (además de `pyserial` para recursos VISA seriales); `ResourceManager('@py')` selecciona explícitamente el backend de Python.<sup>[[5]](#references)[[7]](#references)</sup> Sustituye las cadenas de recursos y los comandos por los que admitan los instrumentos utilizados.<sup>[[5]](#references)</sup>

En el ejemplo con el Rigol MSO5000, arma un disparo único de flanco descendente antes de encender la placa: una señal UART TX inactiva en nivel alto primero baja para enviar su bit de inicio.<sup>[[5]](#references)</sup> Ajusta el umbral de disparo entre los niveles alto inactivo y bajo medidos, y configura la base de tiempo para cubrir el intervalo de arranque que te interesa.<sup>[[5]](#references)[[6]](#references)</sup> `:TRIG:HOLD` puede suprimir flancos repetidos durante capturas continuas, pero no sustituye la comprobación de que la captura de disparo único haya finalizado correctamente.<sup>[[5]](#references)</sup> El siguiente ejemplo captura un arranque y guarda tanto las muestras de bytes sin signo como sus metadatos de escala; si se agota el tiempo de espera, apaga el objetivo en lugar de esperar indefinidamente.<sup>[[5]](#references)[[6]](#references)</sup>

<details>
<summary>Captura de forma de onda UART de disparo único al encender con PyVISA</summary>

```python
import time
from pathlib import Path
import pyvisa

rm = pyvisa.ResourceManager('@py')
psu = rm.open_resource('ASRL/dev/ttyUSB0::INSTR')
scope = rm.open_resource('TCPIP::192.0.2.10::INSTR')
psu.baud_rate = 115200
scope.timeout = 5000
try:
    print(psu.query('*IDN?').strip(), scope.query('*IDN?').strip())
    psu.write('OUTP OFF')
    psu.write('SOUR:VOLT 3.3')
    psu.write('SOUR:CURR 0.5')
    for cmd in (':CHAN1:DISP ON', ':CHAN1:SCAL 0.5',
                ':TIM:MAIN:SCAL 0.05', ':TRIG:MODE EDGE',
                ':TRIG:EDGE:SOUR CHAN1', ':TRIG:EDGE:LEV 1.5',
                ':TRIG:EDGE:SLOP NEG'):
        scope.write(cmd)
    scope.write(':SING')
    psu.write('OUTP ON')
    deadline = time.monotonic() + 30
    while scope.query(':TRIG:STAT?').strip() != 'STOP':
        if time.monotonic() >= deadline:
            raise TimeoutError('No single-shot trigger')
        time.sleep(0.5)
    scope.write(':WAV:SOUR CHAN1')
    scope.write(':WAV:MODE RAW')
    scope.write(':WAV:FORM BYTE')
    preamble = scope.query(':WAV:PRE?').strip()
    points = int(preamble.split(',')[2])
    scope.write(f':WAV:POIN {points}')
    scope.write(':WAV:STAR 1')
    scope.write(f':WAV:STOP {points}')
    scope.timeout = 120000
    raw = scope.query_binary_values(':WAV:DATA?', datatype='B', container=bytes)
    if len(raw) != points:
        raise ValueError('Incomplete waveform; use instrument-specific batch reads')
    Path('capture.bin').write_bytes(raw)
    Path('capture_preamble.txt').write_text(preamble + '\n')
finally:
    psu.write('OUTP OFF')
    scope.close()
    psu.close()
    rm.close()
```

</details>

Para inspeccionar varios pads, repite la captura de una sola adquisición después de mover la sonda, o mantén abierta la sesión de alimentación y cicla su salida con un tiempo de espera de arranque y un intervalo apagado. Rearma el osciloscopio antes de cada encendido para que cada archivo corresponda a un arranque y un pad.<sup>[[5]](#references)</sup>

El preámbulo de Rigol es `<format>,<type>,<points>,<count>,<xincrement>,...`.<sup>[[6]](#references)</sup> El **tercer** valor es el número de puntos, no la tasa de muestreo que se indica en el artículo.<sup>[[5]](#references)[[6]](#references)</sup> En su ejemplo, `25,000,000` puntos y `xincrement = 2e-8` segundos implican `1 / xincrement = 50,000,000` muestras/segundo, no 25 MSa/s.<sup>[[5]](#references)[[6]](#references)</sup> Conserva el preámbulo junto con el archivo binario y comprueba que la longitud de lectura coincida con `<points>`; la guía documenta lecturas segmentadas o por lotes para registros grandes.<sup>[[6]](#references)</sup>

Para decodificar la señal capturada, importa `capture.bin` en PulseView como **Raw Analog Data Without Header**, selecciona valores sin signo de 8 bits (`U8`) e introduce la tasa de muestreo calculada a partir de `xincrement`.<sup>[[5]](#references)[[6]](#references)</sup> Aplica **Logic via Threshold** al canal analógico y elige un umbral entre los valores de muestra bajo y alto.<sup>[[5]](#references)</sup> Mide el ancho de un bit de inicio limpio para estimar la tasa de baudios (unos 17.36 µs para 57,600 baudios); luego aplica el decodificador UART de PulseView y verifica que varios frames se decodifiquen de forma consistente.<sup>[[5]](#references)</sup> Un flanco descendente por sí solo no demuestra que un pad sea UART.

## Adaptador UART a TTY CP210X

Los puentes USB a UART CP210x aparecen en muchas placas de prototipado y adaptadores económicos. Los módulos comunes exponen pines de alimentación junto con GND, RXD y TXD, pero sus conectores y niveles de E/S varían. Confirma el voltaje real en el diseño de la placa o en la hoja de datos. Normalmente, conecta solo GND y el RX del adaptador al TX del objetivo; después de validar solo la recepción, conecta el TX del adaptador al RX del objetivo. No conectes el pin de alimentación de 5 V/3.3 V del adaptador, a menos que quieras alimentar intencionalmente un objetivo que sepas que lo tolera.<sup>[[3]](#references)</sup>

Si no se detecta el adaptador, asegúrate de que los controladores CP210X estén instalados en el sistema anfitrión. Una vez detectado y conectado el adaptador, puedes usar herramientas como picocom, minicom o screen.

Para listar los dispositivos conectados a sistemas Linux/MacOS:

```
ls /dev/
```

Para interactuar de forma básica con la interfaz UART, utiliza el siguiente comando:

```
picocom /dev/<adapter> --baud <baudrate>
```

Para minicom, usa el siguiente comando para configurarlo:

```
minicom -s
```

Configura los ajustes, como la tasa de baudios y el nombre del dispositivo, en la opción `Serial port setup`.

Después de la configuración, ejecuta `minicom` para abrir la consola UART.

## UART mediante Arduino UNO R3 (placas con chip Atmel 328p extraíble)

Si no hay adaptadores de UART a USB disponibles, se puede usar Arduino UNO R3 con un hack rápido. Como Arduino UNO R3 suele estar disponible en cualquier lugar, esto puede ahorrar mucho tiempo.

Arduino UNO R3 tiene integrado en la propia placa un adaptador de USB a serie. Para obtener una conexión UART, solo hay que extraer de la placa el microcontrolador Atmel 328p. Este hack funciona con las variantes de Arduino UNO R3 que no tienen el Atmel 328p soldado a la placa (usan la versión SMD). Conecta el pin RX de Arduino (pin digital 0) al pin TX de la interfaz UART, y el pin TX de Arduino (pin digital 1) al pin RX de la interfaz UART.

Usa el **Monitor Serie** del IDE de Arduino o un terminal dedicado, configurado con la tasa de baudios del dispositivo objetivo. Las señales serie de los Uno R3 clásicos usan lógica de 5 V, así que utiliza un conversor de nivel o un divisor de tensión antes de conectarlas a un dispositivo objetivo de 3,3 V o de menor voltaje.

## Bus Pirate

La siguiente transcripción usa la interfaz del firmware heredado de Bus Pirate para monitorizar la salida UART. Las versiones más recientes del firmware de Bus Pirate usan comandos como `m uart`, `{`/`}`, `monitor` o `bridge`; consulta la documentación de la versión instalada.<sup>[[2]](#references)</sup>

```bash
# Check the modes
UART>m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

# Select UART
(1)>3
Set serial port speed: (bps)
 1. 300
 2. 1200
 3. 2400
 4. 4800
 5. 9600
 6. 19200
 7. 38400
 8. 57600
 9. 115200
10. BRG raw value

# Select the speed the communication is occurring on (you BF all this until you find readable things)
# Or you could later use the macro (4) to try to find the speed
(1)>5
Data bits and parity:
 1. 8, NONE *default
 2. 8, EVEN
 3. 8, ODD
 4. 9, NONE

 # From now on pulse enter for default
(1)>
Stop bits:
 1. 1 *default
 2. 2
(1)>
Receive polarity:
 1. Idle 1 *default
 2. Idle 0
(1)>
Select output type:
 1. Open drain (H=Hi-Z, L=GND)
 2. Normal (H=3.3V, L=GND)

(1)>
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start
UART>W
POWER SUPPLIES ON
Clutch engaged!!!

# Use macro (2) to read the data of the bus (live monitor)
UART>(2)
Raw UART input
Any key to exit
Escritura inicial completada:
AAA Hi Dreg! AAA
waiting a few secs to repeat....
```

## Volcado de firmware con la consola UART

Una consola UART proporciona acceso en tiempo de ejecución a los registros de arranque y, en ocasiones, a un shell del bootloader o del sistema operativo. Incluso una consola de solo lectura revela mapas de memoria, controladores de flash, argumentos de arranque, diseños de particiones y versiones de firmware. El firmware puede estar almacenado en SPI NOR/NAND, eMMC u otro dispositivo; por lo general, no se ejecuta desde una EEPROM, y los archivos escritos en un sistema de archivos persistente montado no necesariamente desaparecen al reiniciar.

Hay varias formas de adquirir el firmware; la sección sobre SPI cubre las lecturas directas desde la memoria flash externa. La adquisición asistida por consola puede ser menos invasiva si el bootloader ya ofrece un comando de lectura seguro, pero cualquier interrupción del arranque o comando de flash puede afectar la disponibilidad, así que registra el estado original y evita las operaciones de escritura o borrado.

El volcado de firmware asistido por consola suele empezar interrumpiendo un bootloader. Muchos dispositivos Linux embebidos usan **Das U-Boot**, pero otros utilizan bootloaders propietarios o deshabilitan la consola interactiva.

Para comprobar si hay un bootloader interactivo, conecta la línea de recepción UART y el terminal mientras el dispositivo objetivo está apagado, empieza a registrar la salida y enciéndelo. Sigue el mensaje de autoboot que se muestra; según la compilación, puede que para interrumpirlo haya que pulsar una tecla, usar una secuencia breve o quizá esté deshabilitado por completo.

Si la interrupción funciona, usa `help`, `printenv` y comandos de reconocimiento de solo lectura para entender el diseño de memoria y almacenamiento de ese fabricante antes de acceder a direcciones.

En U-Boot, `md` muestra **memoria direccionable**, no automáticamente «la EEPROM». Primero usa comandos específicos de la placa, como `mtd list`, `sf probe`, `mmc info`, `part list`, variables de entorno y registros de arranque para identificar la dirección asignada correcta o cargar una región de flash en RAM. Luego muestra un rango conocido byte por byte:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

Registra la salida serie antes de empezar. La salida de `md.b` contiene direcciones y una columna ASCII, por lo que es una representación textual y no una imagen ROM sin procesar.

Elimina las columnas de direcciones y ASCII, concatena solo los campos de bytes hexadecimales y conviértelos a binario (por ejemplo, con `xxd -r -p`). Verifica el número de bytes esperado y registra un hash antes del análisis:

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk identifica las firmas conocidas en el binario reconstruido. Una lectura directa de la flash a través de la interfaz SPI/eMMC/NAND adecuada suele ser más rápida y menos propensa a errores cuando la consola no puede transferir datos de forma fiable.

U-Boot puede deshabilitar la interrupción, requerir una secuencia de teclas específica del proveedor o bloquear los comandos de memoria/flash. Sigue el aviso de autoboot y el registro de arranque en lugar de transmitir caracteres a ciegas. Si no se puede interrumpir la consola, conserva el registro de arranque y utiliza un método de adquisición de firmware no invasivo.

## References

- [1] [Manual de referencia de la familia Microchip PIC32 - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Documentación de Bus Pirate - modo UART y límites eléctricos](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - hoja de datos del CP2102C](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [Documentación de U-Boot - comando `md` para mostrar memoria](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
- [5] [VoidStar Security — SCPI e instrumentación de hardware para ingeniería inversa, parte 1](https://voidstarsec.com/blog/scpi-and-hardware-instrumentation-for-reverse-engineers-part-1)
- [6] [Guía de programación del Rigol MSO5000](https://www.batronix.com/files/Rigol/Oszilloskope/MSO5000/MSO5000_ProgrammingGuide_EN-V2.0.pdf)
- [7] [PyVISA — Configuración del backend](https://pyvisa.readthedocs.io/en/latest/introduction/configuring.html)
{{#include ../../banners/hacktricks-training.md}}
