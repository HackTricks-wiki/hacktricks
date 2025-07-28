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

Obter firmware pode ser abordado de várias maneiras, cada uma com seu próprio nível de complexidade:

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
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ou [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) para inspecionar o arquivo.

### Obtendo o Sistema de Arquivos

Com as ferramentas comentadas anteriormente, como `binwalk -ev <bin>`, você deve ter conseguido **extrair o sistema de arquivos**.\
O Binwalk geralmente o extrai dentro de uma **pasta nomeada como o tipo de sistema de arquivos**, que geralmente é um dos seguintes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extração Manual do Sistema de Arquivos

Às vezes, o binwalk **não terá o byte mágico do sistema de arquivos em suas assinaturas**. Nesses casos, use o binwalk para **encontrar o deslocamento do sistema de arquivos e extrair o sistema de arquivos comprimido** do binário e **extrair manualmente** o sistema de arquivos de acordo com seu tipo usando os passos abaixo.
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

Usando `binwalk -ev <bin>`, geralmente é possível extrair o sistema de arquivos, frequentemente em um diretório nomeado de acordo com o tipo de sistema de arquivos (por exemplo, squashfs, ubifs). No entanto, quando **binwalk** não consegue reconhecer o tipo de sistema de arquivos devido à falta de bytes mágicos, a extração manual é necessária. Isso envolve usar `binwalk` para localizar o deslocamento do sistema de arquivos, seguido pelo comando `dd` para extrair o sistema de arquivos:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Depois, dependendo do tipo de sistema de arquivos (por exemplo, squashfs, cpio, jffs2, ubifs), diferentes comandos são usados para extrair manualmente o conteúdo.

### Análise de Sistema de Arquivos

Com o sistema de arquivos extraído, a busca por falhas de segurança começa. A atenção é voltada para daemons de rede inseguros, credenciais hardcoded, endpoints de API, funcionalidades de servidor de atualização, código não compilado, scripts de inicialização e binários compilados para análise offline.

**Locais** e **itens** chave a serem inspecionados incluem:

- **etc/shadow** e **etc/passwd** para credenciais de usuário
- Certificados e chaves SSL em **etc/ssl**
- Arquivos de configuração e scripts para potenciais vulnerabilidades
- Binários incorporados para análise adicional
- Servidores web e binários comuns de dispositivos IoT

Várias ferramentas ajudam a descobrir informações sensíveis e vulnerabilidades dentro do sistema de arquivos:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) e [**Firmwalker**](https://github.com/craigz28/firmwalker) para busca de informações sensíveis
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) para análise abrangente de firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) e [**EMBA**](https://github.com/e-m-b-a/emba) para análise estática e dinâmica

### Verificações de Segurança em Binários Compilados

Tanto o código-fonte quanto os binários compilados encontrados no sistema de arquivos devem ser examinados em busca de vulnerabilidades. Ferramentas como **checksec.sh** para binários Unix e **PESecurity** para binários Windows ajudam a identificar binários desprotegidos que podem ser explorados.

## Emulando Firmware para Análise Dinâmica

O processo de emular firmware permite **análise dinâmica** tanto da operação de um dispositivo quanto de um programa individual. Essa abordagem pode enfrentar desafios com dependências de hardware ou arquitetura, mas transferir o sistema de arquivos raiz ou binários específicos para um dispositivo com arquitetura e endianness correspondentes, como um Raspberry Pi, ou para uma máquina virtual pré-construída, pode facilitar testes adicionais.

### Emulando Binários Individuais

Para examinar programas únicos, identificar o endianness e a arquitetura da CPU do programa é crucial.

#### Exemplo com Arquitetura MIPS

Para emular um binário de arquitetura MIPS, pode-se usar o comando:
```bash
file ./squashfs-root/bin/busybox
```
E para instalar as ferramentas de emulação necessárias:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Para MIPS (big-endian), `qemu-mips` é utilizado, e para binários little-endian, `qemu-mipsel` seria a escolha.

#### Emulação da Arquitetura ARM

Para binários ARM, o processo é semelhante, com o emulador `qemu-arm` sendo utilizado para emulação.

### Emulação de Sistema Completo

Ferramentas como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) e outras, facilitam a emulação completa de firmware, automatizando o processo e ajudando na análise dinâmica.

## Análise Dinâmica na Prática

Nesta fase, um ambiente de dispositivo real ou emulado é utilizado para análise. É essencial manter acesso ao shell do sistema operacional e ao sistema de arquivos. A emulação pode não imitar perfeitamente as interações de hardware, necessitando reinicializações ocasionais da emulação. A análise deve revisitar o sistema de arquivos, explorar páginas da web expostas e serviços de rede, e investigar vulnerabilidades do bootloader. Testes de integridade do firmware são críticos para identificar potenciais vulnerabilidades de backdoor.

## Técnicas de Análise em Tempo de Execução

A análise em tempo de execução envolve interagir com um processo ou binário em seu ambiente operacional, utilizando ferramentas como gdb-multiarch, Frida e Ghidra para definir pontos de interrupção e identificar vulnerabilidades através de fuzzing e outras técnicas.

## Exploração Binária e Prova de Conceito

Desenvolver um PoC para vulnerabilidades identificadas requer um entendimento profundo da arquitetura alvo e programação em linguagens de baixo nível. Proteções de tempo de execução binárias em sistemas embarcados são raras, mas quando presentes, técnicas como Return Oriented Programming (ROP) podem ser necessárias.

## Sistemas Operacionais Preparados para Análise de Firmware

Sistemas operacionais como [AttifyOS](https://github.com/adi0x90/attifyos) e [EmbedOS](https://github.com/scriptingxss/EmbedOS) fornecem ambientes pré-configurados para testes de segurança de firmware, equipados com as ferramentas necessárias.

## Sistemas Operacionais Preparados para Analisar Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS é uma distribuição destinada a ajudar você a realizar avaliação de segurança e testes de penetração de dispositivos da Internet das Coisas (IoT). Ele economiza muito tempo ao fornecer um ambiente pré-configurado com todas as ferramentas necessárias carregadas.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Sistema operacional de teste de segurança embarcada baseado no Ubuntu 18.04 pré-carregado com ferramentas de teste de segurança de firmware.

## Ataques de Downgrade de Firmware e Mecanismos de Atualização Inseguros

Mesmo quando um fornecedor implementa verificações de assinatura criptográfica para imagens de firmware, **a proteção contra retrocesso de versão (downgrade) é frequentemente omitida**. Quando o bootloader ou o recovery-loader apenas verifica a assinatura com uma chave pública embutida, mas não compara a *versão* (ou um contador monotônico) da imagem que está sendo gravada, um atacante pode instalar legitimamente um **firmware mais antigo e vulnerável que ainda possui uma assinatura válida** e, assim, reintroduzir vulnerabilidades corrigidas.

Fluxo de ataque típico:

1. **Obter uma imagem assinada mais antiga**
* Pegue-a do portal de download público do fornecedor, CDN ou site de suporte.
* Extraia-a de aplicativos móveis/escrita acompanhantes (por exemplo, dentro de um APK Android sob `assets/firmware/`).
* Recupere-a de repositórios de terceiros, como VirusTotal, arquivos da Internet, fóruns, etc.
2. **Carregar ou servir a imagem para o dispositivo** através de qualquer canal de atualização exposto:
* UI da Web, API de aplicativo móvel, USB, TFTP, MQTT, etc.
* Muitos dispositivos IoT de consumo expõem endpoints HTTP(S) *não autenticados* que aceitam blobs de firmware codificados em Base64, decodificam-nos no lado do servidor e acionam a recuperação/atualização.
3. Após o downgrade, explore uma vulnerabilidade que foi corrigida na versão mais nova (por exemplo, um filtro de injeção de comando que foi adicionado posteriormente).
4. Opcionalmente, grave a imagem mais recente de volta ou desative atualizações para evitar detecção uma vez que a persistência seja obtida.

### Exemplo: Injeção de Comando Após Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
No firmware vulnerável (rebaixado), o parâmetro `md5` é concatenado diretamente em um comando de shell sem sanitização, permitindo a injeção de comandos arbitrários (aqui – habilitando o acesso root baseado em chave SSH). Versões posteriores do firmware introduziram um filtro básico de caracteres, mas a ausência de proteção contra rebaixamento torna a correção irrelevante.

### Extraindo Firmware de Aplicativos Móveis

Muitos fornecedores agrupam imagens de firmware completas dentro de seus aplicativos móveis acompanhantes para que o aplicativo possa atualizar o dispositivo via Bluetooth/Wi-Fi. Esses pacotes são comumente armazenados sem criptografia no APK/APEX sob caminhos como `assets/fw/` ou `res/raw/`. Ferramentas como `apktool`, `ghidra` ou até mesmo o simples `unzip` permitem que você extraia imagens assinadas sem tocar no hardware físico.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Checklist para Avaliação da Lógica de Atualização

* O transporte/autenticação do *endpoint de atualização* está adequadamente protegido (TLS + autenticação)?
* O dispositivo compara **números de versão** ou um **contador anti-rollback monotônico** antes de gravar?
* A imagem é verificada dentro de uma cadeia de inicialização segura (por exemplo, assinaturas verificadas pelo código ROM)?
* O código do espaço do usuário realiza verificações adicionais de sanidade (por exemplo, mapa de partição permitido, número do modelo)?
* Os fluxos de atualização *parciais* ou *de backup* reutilizam a mesma lógica de validação?

> 💡  Se algum dos itens acima estiver ausente, a plataforma provavelmente é vulnerável a ataques de rollback.

## Firmware Vulnerável para Prática

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

## Treinamento e Certificação

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
