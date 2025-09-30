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


Firmware é um software essencial que permite que dispositivos funcionem corretamente, gerenciando e facilitando a comunicação entre os componentes de hardware e o software com o qual os usuários interagem. Ele é armazenado em memória permanente, assegurando que o dispositivo possa acessar instruções vitais desde o momento em que é ligado, levando ao carregamento do sistema operacional. Examinar e potencialmente modificar o firmware é um passo crítico na identificação de vulnerabilidades de segurança.

## **Coleta de informações**

**Coletar informação** é um passo inicial crítico para entender a composição de um dispositivo e as tecnologias que ele utiliza. Esse processo envolve a coleta de dados sobre:

- A arquitetura da CPU e o sistema operacional que ele executa
- Especificidades do bootloader
- Disposição do hardware e datasheets
- Métricas do codebase e locais das fontes
- Bibliotecas externas e tipos de licença
- Históricos de atualização e certificações regulatórias
- Diagramas arquiteturais e de fluxo
- Avaliações de segurança e vulnerabilidades identificadas

Para esse propósito, ferramentas de open-source intelligence (OSINT) são inestimáveis, assim como a análise de quaisquer componentes de software open-source disponíveis por meio de processos manuais e automatizados. Ferramentas como [Coverity Scan](https://scan.coverity.com) e [Semmle’s LGTM](https://lgtm.com/#explore) oferecem análise estática gratuita que pode ser aproveitada para encontrar potenciais problemas.

## **Adquirindo o Firmware**

Obter o firmware pode ser abordado por várias vias, cada uma com seu nível de complexidade:

- **Diretamente** da fonte (developers, manufacturers)
- **Construindo** a partir das instruções fornecidas
- **Baixando** de sites de suporte oficiais
- Utilizando queries **Google dork** para encontrar arquivos de firmware hospedados
- Acessando **armazenamento em nuvem** diretamente, com ferramentas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptando **atualizações** via man-in-the-middle techniques
- **Extraindo** do dispositivo através de conexões como **UART**, **JTAG**, ou **PICit**
- **Sniffing** por requisições de update dentro da comunicação do dispositivo
- Identificar e usar **hardcoded update endpoints**
- **Dumping** do bootloader ou da rede
- **Removendo e lendo** o chip de armazenamento, quando tudo mais falhar, usando ferramentas de hardware apropriadas

## Analisando o firmware

Agora que você **tem o firmware**, é preciso extrair informações sobre ele para saber como procedê-lo. Diferentes ferramentas que você pode usar para isso:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Se você não encontrar muita coisa com essas ferramentas, verifique a **entropia** da imagem com `binwalk -E <bin>`; se a entropia for baixa, então provavelmente não está criptografada. Se for alta, provavelmente está criptografada (ou comprimida de alguma forma).

Além disso, você pode usar essas ferramentas para extrair **arquivos incorporados dentro do firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ou [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) para inspecionar o arquivo.

### Obtendo o sistema de arquivos

Com as ferramentas comentadas anteriormente, como `binwalk -ev <bin>`, você deve ter conseguido **extrair o sistema de arquivos**.\
O binwalk geralmente o extrai dentro de uma **pasta com o nome do tipo de sistema de arquivos**, que normalmente é um dos seguintes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extração manual do sistema de arquivos

Às vezes, o binwalk **não terá o magic byte do sistema de arquivos em suas assinaturas**. Nesses casos, use o binwalk para **encontrar o offset do sistema de arquivos e extrair (carve) o sistema de arquivos comprimido** do binário e **extrair manualmente** o sistema de arquivos de acordo com seu tipo usando os passos abaixo.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Execute o seguinte **dd command** para realizar o carving do Squashfs filesystem.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternativamente, o seguinte comando também pode ser executado.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- For squashfs (used in the example above)

`$ unsquashfs dir.squashfs`

Files will be in "`squashfs-root`" directory afterwards.

- CPIO archive files

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- For jffs2 filesystems

`$ jefferson rootfsfile.jffs2`

- For ubifs filesystems with NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analisando Firmware

Uma vez obtido o firmware, é essencial dissecá-lo para entender sua estrutura e possíveis vulnerabilidades. Esse processo envolve utilizar várias ferramentas para analisar e extrair dados valiosos da imagem do firmware.

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
Para avaliar o estado de criptografia da imagem, a **entropia** é verificada com `binwalk -E <bin>`. Baixa entropia sugere ausência de criptografia, enquanto alta entropia indica possível criptografia ou compressão.

Para extrair **arquivos embutidos**, recomenda-se ferramentas e recursos como a documentação **file-data-carving-recovery-tools** e o **binvis.io** para inspeção de arquivos.

### Extraindo o Sistema de Arquivos

Usando `binwalk -ev <bin>`, normalmente é possível extrair o sistema de arquivos, frequentemente em um diretório nomeado conforme o tipo de sistema de arquivos (e.g., squashfs, ubifs). Contudo, quando o **binwalk** falha em reconhecer o tipo de sistema de arquivos devido à ausência dos magic bytes, é necessária a extração manual. Isso envolve usar `binwalk` para localizar o offset do sistema de arquivos, seguido do comando `dd` para extrair o sistema de arquivos:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Depois, dependendo do tipo de sistema de arquivos (por exemplo, squashfs, cpio, jffs2, ubifs), são usados comandos diferentes para extrair manualmente o conteúdo.

### Análise do sistema de arquivos

Com o sistema de arquivos extraído, começa a busca por falhas de segurança. Atenção é dada a network daemons inseguros, credenciais hardcoded, API endpoints, funcionalidades de update server, código não compilado, scripts de inicialização e binários compilados para análise offline.

**Locais-chave** e **itens** a inspecionar incluem:

- **etc/shadow** e **etc/passwd** para credenciais de usuários
- Certificados e chaves SSL em **etc/ssl**
- Arquivos de configuração e scripts em busca de vulnerabilidades potenciais
- Binários embedded para análise adicional
- Common IoT device web servers and binaries

Diversas ferramentas auxiliam na descoberta de informações sensíveis e vulnerabilidades dentro do sistema de arquivos:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) para busca de informações sensíveis
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) para análise abrangente de firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), e [**EMBA**](https://github.com/e-m-b-a/emba) para static and dynamic analysis

### Verificações de segurança em binários compilados

Tanto o código-fonte quanto os binários compilados encontrados no sistema de arquivos devem ser escrutinados em busca de vulnerabilidades. Ferramentas como **checksec.sh** para binários Unix e **PESecurity** para binários Windows ajudam a identificar binários não protegidos que podem ser explorados.

## Emulação de firmware para Dynamic Analysis

O processo de emular firmware permite Dynamic Analysis tanto do funcionamento de um dispositivo quanto de um programa individual. Essa abordagem pode encontrar desafios devido a dependências de hardware ou arquitetura, mas transferir o sistema de arquivos raiz ou binários específicos para um dispositivo com arquitetura e endianness correspondentes, como um Raspberry Pi, ou para uma máquina virtual pré-construída, pode facilitar testes adicionais.

### Emular binários individuais

Para examinar programas isolados, é crucial identificar a endianness (ordem dos bytes) do programa e a arquitetura da CPU.

#### Exemplo com arquitetura MIPS

Para emular um binário de arquitetura MIPS, pode-se usar o comando:
```bash
file ./squashfs-root/bin/busybox
```
E para instalar as ferramentas de emulação necessárias:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### Emulação da Arquitetura ARM

Para binários ARM, o processo é similar, com o emulador `qemu-arm` sendo utilizado para emulação.

### Emulação de Sistema Completo

Ferramentas como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), e outras, facilitam a emulação completa de firmware, automatizando o processo e auxiliando na análise dinâmica.

## Análise Dinâmica na Prática

Nesta fase, um ambiente de dispositivo real ou emulado é usado para análise. É essencial manter acesso shell ao SO e ao sistema de arquivos. A emulação pode não reproduzir perfeitamente as interações com o hardware, exigindo reinícios ocasionais da emulação. A análise deve revisitar o sistema de arquivos, explorar páginas web expostas e serviços de rede, e investigar vulnerabilidades do bootloader. Testes de integridade do firmware são críticos para identificar possíveis backdoors.

## Técnicas de Análise em Runtime

A análise em runtime envolve interagir com um processo ou binário em seu ambiente de execução, usando ferramentas como gdb-multiarch, Frida e Ghidra para definir breakpoints e identificar vulnerabilidades através de fuzzing e outras técnicas.

## Exploração de Binários e Prova de Conceito

Desenvolver um PoC para vulnerabilidades identificadas requer um profundo entendimento da arquitetura alvo e programação em linguagens de baixo nível. Proteções de runtime em binários para sistemas embarcados são raras, mas quando presentes, técnicas como Return Oriented Programming (ROP) podem ser necessárias.

## Sistemas Operacionais Pré-configurados para Análise de Firmware

Sistemas operacionais como [AttifyOS](https://github.com/adi0x90/attifyos) e [EmbedOS](https://github.com/scriptingxss/EmbedOS) fornecem ambientes pré-configurados para testes de segurança de firmware, equipados com as ferramentas necessárias.

## Sistemas Operacionais Preparados para Analisar Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS é uma distro destinada a ajudar você a realizar security assessment e penetration testing de dispositivos Internet of Things (IoT). Economiza muito tempo ao fornecer um ambiente pré-configurado com todas as ferramentas necessárias.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Sistema operacional para testes de segurança embarcada baseado em Ubuntu 18.04, pré-carregado com ferramentas para teste de segurança de firmware.

## Ataques de Downgrade de Firmware e Mecanismos de Atualização Inseguros

Mesmo quando um fabricante implementa verificações de assinatura criptográfica para imagens de firmware, **a proteção contra version rollback (downgrade) é frequentemente omitida**. Quando o bootloader ou recovery-loader apenas verifica a assinatura com uma chave pública embutida mas não compara a *versão* (ou um contador monotônico) da imagem sendo gravada, um atacante pode instalar legitimamente um **firmware mais antigo e vulnerável que ainda possui uma assinatura válida** e assim reintroduzir vulnerabilidades corrigidas.

Fluxo de ataque típico:

1. **Obter uma imagem assinada mais antiga**
* Pegue-a do portal público de downloads do fabricante, CDN ou site de suporte.
* Extraia-a de aplicativos companion para mobile/desktop (por exemplo dentro de um APK Android em `assets/firmware/`).
* Recupere-a de repositórios de terceiros como VirusTotal, arquivos da Internet, fóruns, etc.
2. **Enviar ou servir a imagem para o dispositivo** via qualquer canal de atualização exposto:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Muitos dispositivos IoT de consumo expõem endpoints HTTP(S) *unauthenticated* que aceitam blobs de firmware codificados em Base64, os decodificam no servidor e disparam recovery/upgrade.
3. Após o downgrade, explore uma vulnerabilidade que foi corrigida na versão mais recente (por exemplo, um filtro de command-injection que foi adicionado depois).
4. Opcionalmente grave a imagem mais recente de volta ou desabilite atualizações para evitar detecção uma vez que a persistência seja obtida.

### Exemplo: Command Injection Após Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
No firmware vulnerável (downgraded), o parâmetro `md5` é concatenado diretamente em um comando shell sem sanitização, permitindo a injeção de comandos arbitrários (aqui — habilitando acesso root via chave SSH). Versões posteriores do firmware introduziram um filtro básico de caracteres, mas a ausência de proteção contra downgrade torna a correção inútil.

### Extraindo Firmware de Apps Móveis

Muitos fabricantes empacotam imagens completas de firmware dentro de seus aplicativos móveis companion para que o app possa atualizar o dispositivo via Bluetooth/Wi-Fi. Esses pacotes costumam ser armazenados sem criptografia no APK/APEX sob caminhos como `assets/fw/` ou `res/raw/`. Ferramentas como `apktool`, `ghidra`, ou até mesmo o simples `unzip` permitem extrair imagens assinadas sem tocar no hardware físico.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Checklist para avaliar a lógica de atualização

* O transporte/autenticação do *update endpoint* está adequadamente protegido (TLS + authentication)?
* O dispositivo compara **version numbers** ou um **monotonic anti-rollback counter** antes do flashing?
* A imagem é verificada dentro de uma secure boot chain (por exemplo, signatures checked by ROM code)?
* O código userland realiza checagens adicionais de sanidade (por exemplo, allowed partition map, model number)?
* Os fluxos de update *partial* ou *backup* estão reutilizando a mesma lógica de validação?

> 💡  Se algum dos itens acima estiver faltando, a plataforma provavelmente é vulnerável a rollback attacks.

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

## Referências

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)

## Treinamento e Certificação

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
