# Análise de Firmware

{{#include ../../banners/hacktricks-training.md}}

## **Introdução**

Firmware é um software essencial que permite que dispositivos operem corretamente, gerenciando e facilitando a comunicação entre os componentes de hardware e o software com o qual os usuários interagem. Ele é armazenado em memória permanente, garantindo que o dispositivo possa acessar instruções vitais desde o momento em que é ligado, levando ao lançamento do sistema operacional. Examinar e potencialmente modificar o firmware é um passo crítico na identificação de vulnerabilidades de segurança.

## **Coleta de Informações**

**Coletar informações** é um passo inicial crítico para entender a composição de um dispositivo e as tecnologias que ele utiliza. Este processo envolve a coleta de dados sobre:

- A arquitetura da CPU e o sistema operacional que ele executa
- Especificações do bootloader
- Layout de hardware e folhas de dados
- Métricas da base de código e locais de origem
- Bibliotecas externas e tipos de licença
- Históricos de atualização e certificações regulatórias
- Diagramas arquitetônicos e de fluxo
- Avaliações de segurança e vulnerabilidades identificadas

Para esse propósito, ferramentas de **inteligência de código aberto (OSINT)** são inestimáveis, assim como a análise de quaisquer componentes de software de código aberto disponíveis por meio de processos de revisão manuais e automatizados. Ferramentas como [Coverity Scan](https://scan.coverity.com) e [LGTM da Semmle](https://lgtm.com/#explore) oferecem análise estática gratuita que pode ser aproveitada para encontrar problemas potenciais.

## **Adquirindo o Firmware**

Obter firmware pode ser abordado por vários meios, cada um com seu próprio nível de complexidade:

- **Diretamente** da fonte (desenvolvedores, fabricantes)
- **Construindo** a partir de instruções fornecidas
- **Baixando** de sites de suporte oficiais
- Utilizando consultas de **Google dork** para encontrar arquivos de firmware hospedados
- Acessando **armazenamento em nuvem** diretamente, com ferramentas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptando **atualizações** via técnicas de man-in-the-middle
- **Extraindo** do dispositivo através de conexões como **UART**, **JTAG** ou **PICit**
- **Sniffing** para solicitações de atualização dentro da comunicação do dispositivo
- Identificando e usando **endpoints de atualização hardcoded**
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
Se você não encontrar muito com essas ferramentas, verifique a **entropia** da imagem com `binwalk -E <bin>`, se a entropia for baixa, então é improvável que esteja criptografada. Se a entropia for alta, é provável que esteja criptografada (ou comprimida de alguma forma).

Além disso, você pode usar essas ferramentas para extrair **arquivos incorporados dentro do firmware**:

{{#ref}}
../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ou [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) para inspecionar o arquivo.

### Obtendo o Sistema de Arquivos

Com as ferramentas comentadas anteriormente, como `binwalk -ev <bin>`, você deve ter conseguido **extrair o sistema de arquivos**.\
O binwalk geralmente o extrai dentro de uma **pasta nomeada como o tipo de sistema de arquivos**, que geralmente é um dos seguintes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extração Manual do Sistema de Arquivos

Às vezes, o binwalk **não terá o byte mágico do sistema de arquivos em suas assinaturas**. Nesses casos, use o binwalk para **encontrar o deslocamento do sistema de arquivos e esculpir o sistema de arquivos comprimido** do binário e **extrair manualmente** o sistema de arquivos de acordo com seu tipo usando os passos abaixo.
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

Os arquivos estarão no diretório "`squashfs-root`" depois.

- Arquivos de arquivo CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Para sistemas de arquivos jffs2

`$ jefferson rootfsfile.jffs2`

- Para sistemas de arquivos ubifs com flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analisando o Firmware

Uma vez que o firmware é obtido, é essencial dissecá-lo para entender sua estrutura e potenciais vulnerabilidades. Este processo envolve a utilização de várias ferramentas para analisar e extrair dados valiosos da imagem do firmware.

### Ferramentas de Análise Inicial

Um conjunto de comandos é fornecido para a inspeção inicial do arquivo binário (referido como `<bin>`). Esses comandos ajudam a identificar tipos de arquivo, extrair strings, analisar dados binários e entender os detalhes da partição e do sistema de arquivos:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Para avaliar o status de criptografia da imagem, a **entropia** é verificada com `binwalk -E <bin>`. Baixa entropia sugere a falta de criptografia, enquanto alta entropia indica possível criptografia ou compressão.

Para extrair **arquivos incorporados**, ferramentas e recursos como a documentação de **file-data-carving-recovery-tools** e **binvis.io** para inspeção de arquivos são recomendados.

### Extraindo o Sistema de Arquivos

Usando `binwalk -ev <bin>`, geralmente é possível extrair o sistema de arquivos, muitas vezes em um diretório nomeado de acordo com o tipo de sistema de arquivos (por exemplo, squashfs, ubifs). No entanto, quando **binwalk** não consegue reconhecer o tipo de sistema de arquivos devido à falta de bytes mágicos, a extração manual é necessária. Isso envolve usar `binwalk` para localizar o deslocamento do sistema de arquivos, seguido pelo comando `dd` para extrair o sistema de arquivos:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Depois, dependendo do tipo de sistema de arquivos (por exemplo, squashfs, cpio, jffs2, ubifs), diferentes comandos são usados para extrair manualmente o conteúdo.

### Análise de Sistema de Arquivos

Com o sistema de arquivos extraído, a busca por falhas de segurança começa. A atenção é voltada para daemons de rede inseguros, credenciais codificadas, endpoints de API, funcionalidades de servidor de atualização, código não compilado, scripts de inicialização e binários compilados para análise offline.

**Locais** e **itens** chave a serem inspecionados incluem:

- **etc/shadow** e **etc/passwd** para credenciais de usuário
- Certificados e chaves SSL em **etc/ssl**
- Arquivos de configuração e scripts em busca de vulnerabilidades potenciais
- Binários incorporados para análise adicional
- Servidores web e binários comuns de dispositivos IoT

Várias ferramentas ajudam a descobrir informações sensíveis e vulnerabilidades dentro do sistema de arquivos:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) para busca de informações sensíveis
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) para análise abrangente de firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) e [**EMBA**](https://github.com/e-m-b-a/emba) para análise estática e dinâmica

### Verificações de Segurança em Binários Compilados

Tanto o código-fonte quanto os binários compilados encontrados no sistema de arquivos devem ser examinados em busca de vulnerabilidades. Ferramentas como **checksec.sh** para binários Unix e **PESecurity** para binários Windows ajudam a identificar binários desprotegidos que podem ser explorados.

## Emulando Firmware para Análise Dinâmica

O processo de emular firmware permite **análise dinâmica** tanto da operação de um dispositivo quanto de um programa individual. Essa abordagem pode enfrentar desafios com dependências de hardware ou arquitetura, mas transferir o sistema de arquivos raiz ou binários específicos para um dispositivo com arquitetura e endianness compatíveis, como um Raspberry Pi, ou para uma máquina virtual pré-construída, pode facilitar testes adicionais.

### Emulando Binários Individuais

Para examinar programas únicos, identificar a endianness e a arquitetura da CPU do programa é crucial.

#### Exemplo com Arquitetura MIPS

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

Para binários ARM, o processo é semelhante, com o emulador `qemu-arm` sendo utilizado para emulação.

### Emulação de Sistema Completo

Ferramentas como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) e outras, facilitam a emulação completa de firmware, automatizando o processo e auxiliando na análise dinâmica.

## Análise Dinâmica na Prática

Nesta fase, um ambiente de dispositivo real ou emulado é usado para análise. É essencial manter acesso ao shell do sistema operacional e ao sistema de arquivos. A emulação pode não imitar perfeitamente as interações de hardware, necessitando reinicializações ocasionais da emulação. A análise deve revisitar o sistema de arquivos, explorar páginas da web expostas e serviços de rede, e investigar vulnerabilidades do bootloader. Testes de integridade do firmware são críticos para identificar potenciais vulnerabilidades de backdoor.

## Técnicas de Análise em Tempo de Execução

A análise em tempo de execução envolve interagir com um processo ou binário em seu ambiente operacional, usando ferramentas como gdb-multiarch, Frida e Ghidra para definir pontos de interrupção e identificar vulnerabilidades por meio de fuzzing e outras técnicas.

## Exploração Binária e Prova de Conceito

Desenvolver um PoC para vulnerabilidades identificadas requer um entendimento profundo da arquitetura alvo e programação em linguagens de baixo nível. Proteções de tempo de execução em sistemas embarcados são raras, mas quando presentes, técnicas como Return Oriented Programming (ROP) podem ser necessárias.

## Sistemas Operacionais Preparados para Análise de Firmware

Sistemas operacionais como [AttifyOS](https://github.com/adi0x90/attifyos) e [EmbedOS](https://github.com/scriptingxss/EmbedOS) fornecem ambientes pré-configurados para testes de segurança de firmware, equipados com as ferramentas necessárias.

## Sistemas Operacionais Preparados para Analisar Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS é uma distribuição destinada a ajudar você a realizar avaliação de segurança e testes de penetração de dispositivos da Internet das Coisas (IoT). Ele economiza muito tempo ao fornecer um ambiente pré-configurado com todas as ferramentas necessárias carregadas.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Sistema operacional de teste de segurança embarcada baseado no Ubuntu 18.04 pré-carregado com ferramentas de teste de segurança de firmware.

## Firmware Vulnerável para Prática

Para praticar a descoberta de vulnerabilidades em firmware, use os seguintes projetos de firmware vulneráveis como ponto de partida.

- OWASP IoTGoat
- [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- O Projeto de Firmware de Roteador Extremamente Vulnerável
- [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
- Roteador ARM Extremamente Vulnerável (DVAR)
- [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
- ARM-X
- [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
- Azeria Labs VM 2.0
- [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
- Dispositivo IoT Extremamente Vulnerável (DVID)
- [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Referências

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)

## Treinamento e Certificação

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
