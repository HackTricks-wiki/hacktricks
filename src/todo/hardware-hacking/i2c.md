# I2C

{{#include ../../banners/hacktricks-training.md}}

## Bus Pirate

> [!CAUTION]
> Verifique a tensão do alvo, a pinagem, a configuração dos pull-ups e o aterramento comum antes de conectar um Bus Pirate. Não habilite as fontes de alimentação do Bus Pirate em um barramento energizado pelo alvo apenas para fazer sniffing; duas fontes podem entrar em conflito e danificar o hardware. A transcrição abaixo é um exemplo específico do Bus Pirate v3 com firmware comunitário, não uma receita universal de conexão.<sup>[[1]](#references)[[2]](#references)</sup>

Para testar se um Bus Pirate está funcionando, conecte +5V a VPU e 3,3V a ADC, acesse o Bus Pirate (usando o Tera Term, por exemplo) e use o comando `~`:

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

Como você pode ver na linha de comando anterior, ele informou que encontrou 0 erros. Isso é muito útil para saber que está funcionando depois de comprá-lo ou depois de gravar um firmware.

Para se conectar ao Bus Pirate, você pode seguir a documentação:

![Use command - Press space: Para se conectar ao Bus Pirate, você pode seguir a documentação](<../../images/image (484).png>)

Neste caso, o alvo é uma EEPROM I²C da família 24C256. Confirme o sufixo exato e a folha de dados, pois a tensão de alimentação compatível varia conforme a peça.<sup>[[3]](#references)</sup>

![Use command - Press space: Neste caso, vou me conectar a uma EPROM: ATMEL901 24C256 PU27](<../../images/image (964).png>)

Para me comunicar com o Bus Pirate, usei o Tera Term conectado à porta COM do Bus Pirate, com Setup --> Serial Port --> Speed definido como 115200.\
Na comunicação a seguir, você verá como preparar o Bus Pirate para se comunicar por I2C e como gravar e ler a memória (os comentários aparecem usando "#"; não espere encontrar essa parte na comunicação):

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

Neste cenário, vamos capturar a comunicação I2C entre o Arduino e a EPROM anterior. Você só precisa estabelecer a comunicação entre os dois dispositivos e, em seguida, conectar o Bus Pirate aos pinos SCL, SDA e GND:

![Read 20B from address 0x69 configured before - Sniffer: Neste cenário, vamos capturar a comunicação I2C entre o Arduino e a EPROM anterior. Você só precisa...](<../../images/image (166).png>)

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

## Reconstrução de protocolo I2C por caixa-preta

### Identifique o barramento usando os pinos em operação

Quando o periférico não tem pinout nem datasheet, comece passivamente com um analisador lógico de alta impedância enquanto o host original está em operação. Depois de estabelecer um aterramento comum e um nível lógico seguro, classifique os pinos constantes como possíveis linhas de alimentação, aterramento ou sinais com pull-up. Em seguida, compare as linhas ativas com barramentos comuns: UART tem TX/RX assíncronos e com direções independentes; SPI convencional normalmente expõe clock, chip select e linhas de dados separadas por direção; I2C tem um clock regular e uma linha de dados bidirecional. A decodificação de I2C deve então revelar endereços de destino de 7 bits, direção de leitura/escrita, ACK/NACKs e payloads recorrentes.<sup>[[2]](#references)[[4]](#references)</sup>

Capture várias trocas legítimas e preserve tanto os bytes decodificados quanto o timing bruto. Quadros repetidos servem como testes de resposta conhecida para serializadores posteriores, enquanto as diferenças entre solicitações podem revelar campos que provavelmente correspondem a opcode, índice, offset, tamanho, sequência ou checksum.<sup>[[4]](#references)</sup>

### Recupere o framing a partir do firmware do host

Se o firmware do periférico estiver inacessível, extraia o firmware do **host** e encontre o componente que abre o dispositivo I2C. Procure strings e símbolos relacionados ao nome do periférico, `/dev/i2c-`, construtores de comandos, parsers de respostas, rotinas de reset/inicialização e funções de checksum. Para cada construtor, registre os offsets exatos dos campos, constantes, tamanhos de argumentos aceitos, tamanho do payload, cobertura do checksum, ordem dos bytes do checksum e tamanho do quadro retornado, em vez de deduzir o formato pelos nomes das funções.<sup>[[4]](#references)</sup>

Uma função de checksum chamada `crc16_ccitt` não basta para escolher uma variante. Determine a direção do deslocamento, o byte usado como índice da tabela, o polinômio representado pela tabela, o registrador inicial, a reflexão de entrada/saída, o XOR/inversão final e a endianness do serializador na transmissão. Por exemplo, uma tabela de byte baixo com deslocamento à direita, baseada no polinômio invertido `0x8408`, inicializada com `0xFFFF` e complementada no final, identifica **CRC-16/X-25 (IBM-SDLC)**. Um checksum correto costuma ser necessário para que os casos de teste passem pela validação de integridade e cheguem ao parser de comandos.<sup>[[4]](#references)</sup>

Depois de reconstruir o formato, procure nomes de símbolos e constantes distintivos em código público. No caso do MJA1, um wrapper de SDK encontrado de forma independente confirmou IDs de comando, validação de argumentos, definições de resposta e a implementação espelhada do CRC; use esse código como validação, não como substituto da verificação do binário de destino exato e da ordem dos bytes na transmissão.<sup>[[4]](#references)[[5]](#references)</sup>

### Envie quadros a partir de um host Linux com root

Um host Linux embarcado comprometido pode interagir com o periférico sem adicionar outro controlador de barramento. Abra o adaptador relevante, selecione o endereço de 7 bits com `I2C_SLAVE` e envie um quadro produzido por um serializador dedicado; mantenha um modo de quadro bruto para mutação e fuzzing.<sup>[[4]](#references)</sup>

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

Faça cross-compile usando uma toolchain compatível com a CPU e a libc do alvo e compare os rastros do analisador do cliente de teste com o tráfego legítimo. Os limites das transações, a ordem de leitura e escrita, os atrasos e o estado do periférico podem ser importantes, mesmo quando os bytes visíveis coincidem.<sup>[[4]](#references)</sup>

### Enumeração de opcode guiada por resposta

Depois de conhecer o frame válido mais curto e o checksum, enumere toda a largura do opcode e use a resposta explícita do protocolo para **comando não suportado** como referência negativa. Um resultado diferente — como argumentos inválidos, estado inválido ou um status não documentado — sugere que a decodificação chegou a um handler implementado ou parcialmente implementado. Isso **não** comprova que o candidato seja explorável; priorize-o para fuzzing estruturado de comprimento, argumentos, estado e sequência de comandos.<sup>[[4]](#references)</sup>

Se um teste travar o periférico, automatize um caso isolado por inicialização, usando um controlador externo: conecte-se por SSH, execute o caso, salve a requisição/resposta bruta e o tempo, reinicie ou desligue e ligue o dispositivo, aguarde a recuperação das verificações de integridade e continue. Transferir o componente para um dispositivo de teste controlado por microcontrolador pode, mais adiante, permitir reinicializações determinísticas, controle direto da alimentação e fuzzing mais rápido.<sup>[[4]](#references)</sup>

## References

- [1] [Documentação do Bus Pirate — I²C](https://docs.buspirate.com/docs/devices/i2c-eeprom/)
- [2] [NXP — Especificação do barramento I²C e manual do usuário](https://www.nxp.com/docs/en/user-guide/UM10204.pdf)
- [3] [Microchip — Ficha técnica da EEPROM serial I²C AT24C256C](https://ww1.microchip.com/downloads/en/DeviceDoc/AT24C256C-I2C-Compatible-Two-Wire-Serial-EEPROM-256-Kbit-32,768-x-8-20005915A.pdf)
- [4] [Quarkslab — Sondagem de caixa-preta: uma análise de segurança do chip seguro MJA1 da Xiaomi](https://blog.quarkslab.com/black-box-probing-a-security-analysis-of-xiaomis-mja1-secure-chip.html)
- [5] [Wrapper de criptografia MJA1 do SDK Mijia BLE](https://github.com/iomonad/handshow-firmware/tree/master/components/vendor/common/mijia_ble/libs/cryptography/mja1)
{{#include ../../banners/hacktricks-training.md}}
