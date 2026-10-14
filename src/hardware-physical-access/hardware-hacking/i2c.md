# I2C

{{#include ../../banners/hacktricks-training.md}}

## Bus Pirate

> [!CAUTION]
> Verifica el voltaje del objetivo, el pinout, la configuración de pull-up y la conexión a tierra común antes de conectar un Bus Pirate. No actives las fuentes de alimentación del Bus Pirate en un bus activo alimentado por el objetivo solo para hacer sniffing; dos fuentes pueden entrar en conflicto y dañar el hardware. La transcripción siguiente es un ejemplo específico de un Bus Pirate v3 con firmware comunitario, no una guía de cableado universal.<sup>[[1]](#references)[[2]](#references)</sup>

Para comprobar que un Bus Pirate funciona, conecta +5V a VPU y 3.3V a ADC, accede al Bus Pirate (por ejemplo, usando Tera Term) y usa el comando `~`:

```bash
# Use command
HiZ>~
Disconnect any devices
Connect (Vpu to +5V) and (ADC to +3.3V)
Space to continue
# Press space
Ctrl
AUX OK
MODE LED OK
PULLUP H OK
PULLUP L OK
VREG OK
ADC and supply
5V(4.96) OK
VPU(4.96) OK
3.3V(3.26) OK
ADC(3.27) OK
Bus high
MOSI OK
CLK OK
MISO OK
CS OK
Bus Hi-Z 0
MOSI OK
CLK OK
MISO OK
CS OK
Bus Hi-Z 1
MOSI OK
CLK OK
MISO OK
CS OK
MODE and VREG LEDs should be on!
Any key to exit
#Press space
Found 0 errors.
```

Como puedes ver en la línea de comandos anterior, indicó que encontró 0 errores. Es muy útil saber que funciona después de comprarlo o de flashear un firmware.

Para conectarte al Bus Pirate, puedes seguir la documentación:

![Usa el comando - Pulsa espacio: Para conectarte al Bus Pirate, puedes seguir la documentación](<../../images/image (484).png>)

En este caso, el objetivo es una EEPROM I²C de la familia 24C256. Confirma el sufijo exacto y la hoja de datos, porque la tensión de alimentación admitida varía según el modelo.<sup>[[3]](#references)</sup>

![Usa el comando - Pulsa espacio: En este caso voy a conectarme a una EPROM: ATMEL901 24C256 PU27](<../../images/image (964).png>)

Para comunicarme con el Bus Pirate, usé Tera Term conectado al puerto COM del Bus Pirate, con Setup --> Serial Port --> Speed configurado en 115200.\
En la siguiente comunicación puedes ver cómo preparar el Bus Pirate para comunicarse por I2C y cómo escribir y leer desde la memoria (los comentarios aparecen con «#»; no esperes encontrar esa parte en la comunicación):

```bash
# Check communication with buspirate
i
Bus Pirate v3.5
Community Firmware v7.1 - goo.gl/gCzQnW [HiZ 1-WIRE UART I2C SPI 2WIRE 3WIRE KEYB LCD PIC DIO] Bootloader v4.5
DEVID:0x0447 REVID:0x3046 (24FJ64GA00 2 B8)
http://dangerousprototypes.com

# Check voltages
I2C>v
Pinstates:
1.(BR)  2.(RD)  3.(OR)  4.(YW)  5.(GN)  6.(BL)  7.(PU)  8.(GR)  9.(WT)  0.(Blk)
GND     3.3V    5.0V    ADC     VPU     AUX     SCL     SDA     -       -
P       P       P       I       I       I       I       I       I       I
GND     3.27V   4.96V   0.00V   4.96V   L       H       H       L       L

# This particular setup used 5 V pull-ups; do not generalize it to every 24C256 variant or board

# Get mode options
HiZ>m
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

# Select I2C
(1)>4
I2C mode:
 1. Software
 2. Hardware

# Select Software mode
(1)>1
Set speed:
 1. ~5kHz
 2. ~50kHz
 3. ~100kHz
 4. ~240kHz

# Select communication speed
(1)> 2
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start communication
I2C>W
POWER SUPPLIES ON
Clutch engaged!!!

# Get macros
I2C>(0)
 0.Macro menu
 1.7bit address search
 2.I2C sniffer

#Get addresses of slaves connected
I2C>(1)
Searching I2C address space. Found devices at:
0xA0(0x50 W) 0xA1(0x50 R)

# Bus Pirate displays the 8-bit address bytes 0xA0 (write) and 0xA1 (read)
# Both correspond to the same 7-bit I2C target address, 0x50

# Write "BBB" in address 0x69
I2C>[0xA0 0x00 0x69 0x42 0x42 0x42]
I2C START BIT
WRITE: 0xA0 ACK
WRITE: 0x00 ACK
WRITE: 0x69 ACK
WRITE: 0x42 ACK
WRITE: 0x42 ACK
WRITE: 0x42 ACK
I2C STOP BIT

# Prepare to read from address 0x69
I2C>[0xA0 0x00 0x69]
I2C START BIT
WRITE: 0xA0 ACK
WRITE: 0x00 ACK
WRITE: 0x69 ACK
I2C STOP BIT

# Read 20B from address 0x69 configured before
I2C>[0xA1 r:20]
I2C START BIT
WRITE: 0xA1 ACK
READ: 0x42  ACK 0x42  ACK 0x42  ACK 0x20  ACK 0x48  ACK 0x69  ACK 0x20  ACK 0x44  ACK 0x72  ACK 0x65  ACK 0x67  ACK 0x21  ACK 0x20  ACK 0x41  ACK 0x41  ACK 0x41  ACK 0x00  ACK 0xFF  ACK 0xFF  ACK 0xFF
NACK
```

### Sniffer

En este escenario vamos a interceptar la comunicación I2C entre el arduino y la EPROM anterior; solo tienes que comunicar ambos dispositivos y luego conectar el bus pirate a los pines SCL, SDA y GND:

![Leer 20B desde la dirección 0x69 configurada antes - Sniffer: En este escenario vamos a interceptar la comunicación I2C entre el arduino y la EPROM anterior; solo tienes que...](<../../images/image (166).png>)

```bash
I2C>m
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

(1)>4
I2C mode:
 1. Software
 2. Hardware

(1)>1
Set speed:
 1. ~5kHz
 2. ~50kHz
 3. ~100kHz
 4. ~240kHz

(1)>1
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Historical transcript powered this bench setup. On a live target-powered bus, leave Bus Pirate power OFF.

I2C>W
POWER SUPPLIES ON
Clutch engaged!!!

# Start sniffing, you can see we sniffed a write command

I2C>(2)
Sniffer
Any key to exit
[0xA0+0x00+0x69+0x41+0x41+0x41+0x20+0x48+0x69+0x20+0x44+0x72+0x65+0x67+0x21+0x20+0x41+0x41+0x41+0x00+]
```

## Reconstrucción del protocolo I2C de caja negra

### Identificar el bus a partir de los pines activos

Cuando el periférico no tiene pinout ni hoja de datos, empieza de forma pasiva con un analizador lógico de alta impedancia mientras funciona el host original. Tras establecer una tierra común y un nivel lógico seguro, clasifica los pines constantes como posibles líneas de alimentación, tierra o señales con resistencias pull-up; luego compara las líneas activas con los buses habituales: UART tiene TX/RX asíncronos y con dirección independiente; SPI convencional suele exponer reloj, selección de chip y líneas de datos separadas por dirección; I2C tiene un reloj regular y una línea de datos bidireccional. La decodificación de I2C debería revelar entonces las direcciones de destino de 7 bits, la dirección de lectura/escritura, los ACK/NACK y las cargas útiles recurrentes.<sup>[[2]](#references)[[4]](#references)</sup>

Captura varios intercambios legítimos y conserva tanto los bytes decodificados como la temporización sin procesar. Las tramas repetidas sirven como pruebas con respuestas conocidas para los serializadores posteriores, mientras que los cambios entre solicitudes pueden revelar posibles campos de código de operación, índice, desplazamiento, longitud, secuencia o suma de comprobación.<sup>[[4]](#references)</sup>

### Recuperar el encuadre del firmware del host

Si no se puede acceder al firmware del periférico, extrae el firmware del **host** y encuentra el componente que abre el dispositivo I2C. Busca cadenas y símbolos relacionados con el nombre del periférico, `/dev/i2c-`, constructores de comandos, analizadores de respuestas, rutinas de reinicio/inicialización y funciones de suma de comprobación. Para cada constructor, registra los desplazamientos exactos de los campos, las constantes, los tamaños de argumento aceptados, la longitud de la carga útil, los datos cubiertos por la suma de comprobación, el orden de bytes de esta y la longitud de la trama devuelta, en vez de inferir el formato a partir de los nombres de las funciones.<sup>[[4]](#references)</sup>

Una función de suma de comprobación llamada `crc16_ccitt` no basta para elegir un preset. Determina la dirección del desplazamiento, el byte del índice de la tabla, el polinomio representado por la tabla, el registro inicial, la reflexión de entrada/salida, la inversión/XOR final y el orden de bytes del serializador en el cable. Por ejemplo, una tabla de bytes bajos con desplazamiento a la derecha basada en el polinomio invertido `0x8408`, inicializada con `0xFFFF` y complementada al final, identifica **CRC-16/X-25 (IBM-SDLC)**. Una suma de comprobación correcta suele ser necesaria para que los casos de prueba superen la validación de integridad y lleguen al analizador de comandos.<sup>[[4]](#references)</sup>

Tras reconstruir el formato, busca nombres de símbolos y constantes distintivos en código público. En el caso de MJA1, un wrapper de SDK localizado de forma independiente confirmó los ID de comando, la validación de argumentos, las definiciones de respuesta y la implementación reflejada de CRC; usa ese código como validación, no como sustituto de comprobar el binario de destino exacto y el orden de bytes en el cable.<sup>[[4]](#references)[[5]](#references)</sup>

### Enviar tramas desde un host Linux con root

Un host Linux embebido comprometido puede interactuar con el periférico sin añadir otro controlador de bus. Abre el adaptador correspondiente, selecciona la dirección de 7 bits con `I2C_SLAVE` y envía una trama generada por un serializador específico; conserva un modo de trama sin procesar para mutación y fuzzing.<sup>[[4]](#references)</sup>

```c
int fd = open("/dev/i2c-0", O_RDWR);
if (fd < 0 || ioctl(fd, I2C_SLAVE, target_addr) < 0)
    err(1, "I2C setup");
if (write(fd, cmd, cmd_len) != cmd_len)
    err(1, "I2C write");
ssize_t n = read(fd, resp, resp_size);
if (n < 0)
    err(1, "I2C read");
```

Realiza una compilación cruzada con una toolchain compatible con la CPU y la libc del objetivo, y compara los rastros del analizador del cliente de prueba con el tráfico legítimo. Los límites de las transacciones, el orden de escritura/lectura, las demoras y el estado de los periféricos pueden ser importantes, incluso si los bytes visibles coinciden.<sup>[[4]](#references)</sup>

### Enumeración de opcodes guiada por las respuestas

Una vez conocidos el frame válido más corto y la suma de comprobación, enumera todo el ancho del opcode y utiliza la respuesta explícita del protocolo **unsupported-command** como referencia negativa. Un resultado distinto —como argumentos no válidos, estado no válido o un estado no documentado— sugiere que la decodificación llegó a un manejador implementado o parcialmente implementado. Esto **no** demuestra que sea explotable; prioriza el candidato para fuzzing estructurado de longitudes, argumentos, estados y secuencias de comandos.<sup>[[4]](#references)</sup>

Si una prueba bloquea el periférico, automatiza un caso aislado por arranque desde un controlador externo: conéctate por SSH, ejecuta el caso, guarda la solicitud/respuesta sin procesar y los tiempos, reinicia o corta y restablece la alimentación, espera a que se recuperen las comprobaciones de estado y continúa. Más adelante, trasladar el componente a un montaje controlado por microcontrolador puede proporcionar reinicios deterministas, control directo de alimentación y fuzzing más rápido.<sup>[[4]](#references)</sup>

## References

- [1] [Documentación de Bus Pirate — I²C](https://docs.buspirate.com/docs/devices/i2c-eeprom/)
- [2] [NXP — Especificación del bus I²C y manual del usuario](https://www.nxp.com/docs/en/user-guide/UM10204.pdf)
- [3] [Microchip — Hoja de datos de la EEPROM serial I²C AT24C256C](https://ww1.microchip.com/downloads/en/DeviceDoc/AT24C256C-I2C-Compatible-Two-Wire-Serial-EEPROM-256-Kbit-32,768-x-8-20005915A.pdf)
- [4] [Quarkslab — Sondeo de caja negra: análisis de seguridad del chip seguro MJA1 de Xiaomi](https://blog.quarkslab.com/black-box-probing-a-security-analysis-of-xiaomis-mja1-secure-chip.html)
- [5] [Wrapper de criptografía MJA1 del SDK Mijia BLE](https://github.com/iomonad/handshow-firmware/tree/master/components/vendor/common/mijia_ble/libs/cryptography/mja1)
{{#include ../../banners/hacktricks-training.md}}
