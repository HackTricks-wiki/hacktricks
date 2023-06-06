# Análise de Firmware

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Introdução

Firmware é um tipo de software que fornece comunicação e controle sobre os componentes de hardware de um dispositivo. É o primeiro código que um dispositivo executa. Geralmente, ele **inicializa o sistema operacional** e fornece serviços de tempo de execução muito específicos para programas, **comunicando-se com vários componentes de hardware**. A maioria, senão todos, os dispositivos eletrônicos possuem firmware.

Os dispositivos armazenam o firmware em **memória não volátil**, como ROM, EPROM ou memória flash.

É importante **examinar** o **firmware** e, em seguida, tentar **modificá-lo**, porque podemos descobrir muitos problemas de segurança durante esse processo.

## Coleta de informações e reconhecimento

Durante esta etapa, colete o máximo de informações possível sobre o alvo para entender sua composição geral e tecnologia subjacente. Tente coletar o seguinte:

* Arquitetura(s) de CPU suportada(s)
* Plataforma do sistema operacional
* Configurações do bootloader
* Esquemas de hardware
* Datasheets
* Estimativas de linhas de código (LoC)
* Localização do repositório de código-fonte
* Componentes de terceiros
* Licenças de código aberto (por exemplo, GPL)
* Changelogs
* IDs da FCC
* Diagramas de design e fluxo de dados
* Modelos de ameaças
* Relatórios anteriores de testes de penetração
* Tickets de rastreamento de bugs (por exemplo, Jira e plataformas de recompensa por bugs como BugCrowd ou HackerOne)

Sempre que possível, adquira dados usando ferramentas e técnicas de inteligência de fontes abertas (OSINT). Se o software de código aberto for usado, baixe o repositório e execute análises estáticas manuais e automatizadas no código base. Às vezes, projetos de software de código aberto já usam ferramentas de análise estática gratuitas fornecidas por fornecedores que fornecem resultados de varredura, como [Coverity Scan](https://scan.coverity.com) e [Semmle’s LGTM](https://lgtm.com/#explore).

## Obtendo o Firmware

Existem diferentes maneiras com diferentes níveis de dificuldade para baixar o firmware

* **Diretamente** da equipe de desenvolvimento, fabricante/fornecedor ou cliente
* **Construir do zero** usando tutoriais fornecidos pelo fabricante
* Do **site de suporte** do fornecedor
* Consultas **Google dork** direcionadas a extensões de arquivo binário e plataformas de compartilhamento de arquivos como Dropbox, Box e Google Drive
  * É comum encontrar imagens de firmware por meio de clientes que carregam conteúdo em fóruns, blogs ou comentam em sites onde entraram em contato com o fabricante para solucionar um problema e receberam firmware via um zip ou unidade flash enviada.
  * Exemplo: `intitle:"Netgear" intext:"Firmware Download"`
* Baixe compilações de locais de armazenamento de provedores de nuvem expostos, como buckets do Amazon Web Services (AWS) (com ferramentas como [https://github.com/sa7mon/S3Scanner](https://github.com/sa7mon/S3Scanner))
* Comunicação do dispositivo **man-in-the-middle** (MITM) durante **atualizações**
* Extrair diretamente do hardware via **UART**, **JTAG**, **PICit**, etc.
* Capturar a **comunicação serial** dentro dos componentes de hardware para **solicitações de servidor de atualização**
* Via um **ponto de extremidade codificado** nos aplicativos móveis ou espessos
* **Despejando** o firmware do **bootloader** (por exemplo, U-boot) para armazenamento flash ou pela **rede** via **tftp**
* Removendo o **chip flash** (por exemplo, SPI) ou MCU da placa para análise offline e extração de dados (ÚLTIMO RECURSO).
  * Você precisará de um programador de chip suportado para armazenamento flash e/ou o MCU.

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
Se não encontrar muita coisa com essas ferramentas, verifique a **entropia** da imagem com `binwalk -E <bin>`. Se a entropia for baixa, é pouco provável que esteja criptografada. Se a entropia for alta, é provável que esteja criptografada (ou compactada de alguma forma).

Além disso, você pode usar essas ferramentas para extrair **arquivos incorporados no firmware**:

{% content-ref url="../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

Ou [**binvis.io**](https://binvis.io/#/) ([código](https://code.google.com/archive/p/binvis/)) para inspecionar o arquivo.

### Obtendo o Sistema de Arquivos

Com as ferramentas mencionadas anteriormente, como `binwalk -ev <bin>`, você deve ter sido capaz de **extrair o sistema de arquivos**.\
O Binwalk geralmente o extrai dentro de uma **pasta com o nome do tipo de sistema de arquivos**, que geralmente é um dos seguintes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

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

* Para squashfs (usado no exemplo acima)

`$ unsquashfs dir.squashfs`

Os arquivos estarão no diretório "`squashfs-root`" depois.

* Arquivos de arquivo CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

* Para sistemas de arquivos jffs2

`$ jefferson rootfsfile.jffs2`

* Para sistemas de arquivos ubifs com flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Analisando o sistema de arquivos

Agora que você tem o sistema de arquivos, é hora de começar a procurar más práticas, como:

* **daemons de rede inseguros legados** como telnetd (às vezes os fabricantes renomeiam binários para disfarçar)
* **credenciais codificadas** (nomes de usuário, senhas, chaves de API, chaves SSH e variantes de backdoor)
* **pontos de extremidade de API codificados** e detalhes do servidor de back-end
* **funcionalidade do servidor de atualização** que pode ser usada como ponto de entrada
* **Revisar código não compilado e scripts de inicialização** para execução remota de código
* **Extrair binários compilados** para serem usados para análise offline com um desmontador para etapas futuras

Algumas **coisas interessantes para procurar** dentro do firmware:

* etc/shadow e etc/passwd
* listar o diretório etc/ssl
* procurar por arquivos relacionados a SSL, como .pem, .crt, etc.
* procurar por arquivos de configuração
* procurar por arquivos de script
* procurar por outros arquivos .bin
* procurar por palavras-chave como admin, senha, remoto, chaves AWS, etc.
* procurar por servidores web comuns usados em dispositivos IoT
* procurar por binários comuns como ssh, tftp, dropbear, etc.
* procurar por funções c proibidas
* procurar por funções vulneráveis ​​comuns de injeção de comando
* procurar por URLs, endereços de e-mail e endereços IP
* e mais...

Ferramentas que procuram por esse tipo de informação (mesmo que você sempre deva dar uma olhada manual e se familiarizar com a estrutura do sistema de arquivos, as ferramentas podem ajudá-lo a encontrar **coisas ocultas**):

* [**LinPEAS**](https://github.com/carlospolop/PEASS-ng)**:** Script bash incrível que, neste caso, é útil para procurar **informações confidenciais** dentro do sistema de arquivos. Apenas **chroot dentro do sistema de arquivos do firmware e execute-o**.
* [**Firmwalker**](https://github.com/craigz28/firmwalker)**:** Script bash para procurar informações confidenciais potenciais
* [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT\_core):
  * Identificação de componentes de software, como sistema operacional, arquitetura de CPU e componentes de terceiros, juntamente com suas informações de versão associadas
  * Extração do sistema de arquivos do firmware (s) de imagens
  * Detecção de certificados e chaves privadas
  * Detecção de implementações fracas mapeando para Common Weakness Enumeration (CWE)
  * Alimentação e detecção baseada em assinatura de vulnerabilidades
  * Análise comportamental estática básica
  * Comparação (diff) de versões e arquivos de firmware
  * Emulação de modo de usuário de binários de sistema de arquivos usando QEMU
  * Detecção de mitigação binária, como NX, DEP, ASLR, canários de pilha, RELRO e FORTIFY\_SOURCE
  * REST API
  * e mais...
* [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer): FwAnalyzer é uma ferramenta para analisar imagens de sistemas de arquivos (ext2/3/4), FAT/VFat, SquashFS, UBIFS, arquivos de arquivo cpio e conteúdo de diretório usando um conjunto de regras configuráveis.
* [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep): Uma ferramenta de análise de segurança de firmware IoT de software livre
* [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go): Esta é uma reescrita completa do projeto ByteSweep original em Go.
* [**EMBA**](https://github.com/e-m-b-a/emba): _EMBA_ é projetado como a ferramenta central de análise de firmware para testadores de penetração. Ele suporta o processo completo de análise de segurança, começando com o processo de extração de firmware, fazendo análise estática e análise dinâmica por meio de emulação e, finalmente, gerando um relatório. _EMBA_ descobre automaticamente possíveis pontos fracos e vulnerabilidades no firmware. Exemplos são binários inseguros, componentes de software antigos e desatualizados, scripts potencialmente vulneráveis ​​ou senhas codificadas.

{% hint style="warning" %}
Dentro do sistema de arquivos, você também pode encontrar **código-fonte** de programas (que você sempre deve **verificar**), mas também **binários compilados**. Esses programas podem ser de alguma forma expostos e você deve **descompilar** e **verificar** para possíveis vulnerabilidades.

Ferramentas como [**checksec.sh**](https://github.com/slimm609/checksec.sh) podem ser úteis para encontrar binários desprotegidos. Para binários do Windows, você pode usar [**PESecurity**](https://github.com/NetSPI/PESecurity).
{% endhint %}

## Emulando Firmware

A ideia de emular o Firmware é ser capaz de realizar uma **análise dinâmica** do dispositivo **em execução** ou de um **único programa**.

{% hint style="info" %}
Às vezes, a emulação parcial ou total **pode não funcionar devido a dependências de hardware ou arquitetura**. Se a arquitetura e a ordem dos bytes corresponderem a um dispositivo de propriedade, como um raspberry pie, o sistema de arquivos raiz ou um binário específico pode ser transferido para o dispositivo para testes adicionais. Este método também se aplica a máquinas virtuais pré-construídas usando a mesma arquitetura e ordem dos bytes que o alvo.
{% endhint %}

### Emulação binária

Se você deseja apenas emular um programa para procurar vulnerabilidades, primeiro precisa identificar a ordem dos bytes e a arquitetura da CPU para a qual foi compilado.

#### Exemplo MIPS
```bash
file ./squashfs-root/bin/busybox
./squashfs-root/bin/busybox: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, stripped
```
Agora você pode **emular** o executável do busybox usando o **QEMU**.
```bash
 sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Como o executável **é** compilado para **MIPS** e segue a ordem dos bytes **big-endian**, usaremos o emulador **`qemu-mips`** do QEMU. Para emular executáveis **little-endian**, teríamos que selecionar o emulador com o sufixo `el` (`qemu-mipsel`).
```bash
qemu-mips -L ./squashfs-root/ ./squashfs-root/bin/ls
100              100.7z           15A6D2.squashfs  squashfs-root    squashfs-root-0
```
#### Exemplo ARM
```bash
file bin/busybox                
bin/busybox: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-musl-armhf.so.1, no section header
```
Emulação:

A emulação é uma técnica usada para executar um software em um ambiente diferente daquele para o qual foi projetado originalmente. No contexto da análise de firmware, a emulação é usada para executar o firmware em um ambiente controlado e monitorado, permitindo que o analista observe o comportamento do firmware sem afetar o dispositivo real. A emulação pode ser usada para identificar vulnerabilidades, backdoors e outras anomalias no firmware. Além disso, a emulação pode ser usada para desenvolver exploits e ferramentas de análise de firmware.
```bash
qemu-arm -L ./squashfs-root/ ./squashfs-root/bin/ls
1C00000.squashfs  B80B6C            C41DD6.xz         squashfs-root     squashfs-root-0
```
### Emulação completa do sistema

Existem várias ferramentas, baseadas em **qemu** em geral, que permitirão que você emule o firmware completo:

* [**https://github.com/firmadyne/firmadyne**](https://github.com/firmadyne/firmadyne)**:**
  * Você precisa instalar várias coisas, configurar o postgres, em seguida, executar o script extractor.py para extrair o firmware, usar o script getArch.sh para obter a arquitetura. Em seguida, use os scripts tar2db.py e makeImage.sh para armazenar informações da imagem extraída no banco de dados e gerar uma imagem QEMU que podemos emular. Em seguida, use o script inferNetwork.sh para obter as interfaces de rede e, finalmente, use o script run.sh, que é criado automaticamente na pasta ./scratch/1/.
* [**https://github.com/attify/firmware-analysis-toolkit**](https://github.com/attify/firmware-analysis-toolkit)**:**
  * Esta ferramenta depende do firmadyne e automatiza o processo de emulação do firmware usando o firmadyne. você precisa configurar o `fat.config` antes de usá-lo: `sudo python3 ./fat.py IoTGoat-rpi-2.img --qemu 2.5.0`
* [**https://github.com/therealsaumil/emux**](https://github.com/therealsaumil/emux)
* [**https://github.com/getCUJO/MIPS-X**](https://github.com/getCUJO/MIPS-X)
* [**https://github.com/qilingframework/qiling#qltool**](https://github.com/qilingframework/qiling#qltool)

## **Análise dinâmica**

Nesta etapa, você deve ter um dispositivo executando o firmware para atacar ou o firmware sendo emulado para atacar. Em qualquer caso, é altamente recomendável que você também tenha **um shell no sistema operacional e no sistema de arquivos que está sendo executado**.

Observe que às vezes, se você estiver emulando o firmware, **algumas atividades dentro da emulação falharão** e você pode precisar reiniciar a emulação. Por exemplo, um aplicativo da web pode precisar obter informações de um dispositivo com o qual o dispositivo original está integrado, mas a emulação não está emulando.

Você deve **verificar novamente o sistema de arquivos** como já fizemos em um **passo anterior, pois no ambiente em execução, novas informações podem ser acessíveis**.

Se **páginas da web** estiverem expostas, lendo o código e tendo acesso a elas, você deve **testá-las**. No hacktricks, você pode encontrar muitas informações sobre diferentes técnicas de hacking na web.

Se **serviços de rede** estiverem expostos, você deve tentar atacá-los. No hacktricks, você pode encontrar muitas informações sobre diferentes técnicas de hacking de serviços de rede. Você também pode tentar fuzzá-los com **fuzzers** de rede e protocolo, como [Mutiny](https://github.com/Cisco-Talos/mutiny-fuzzer), [boofuzz](https://github.com/jtpereyda/boofuzz) e [kitty](https://github.com/cisco-sas/kitty).

Você deve verificar se pode **atacar o bootloader** para obter um shell raiz:

{% content-ref url="bootloader-testing.md" %}
[bootloader-testing.md](bootloader-testing.md)
{% endcontent-ref %}

Você deve testar se o dispositivo está fazendo algum tipo de **teste de integridade do firmware**, se não, isso permitiria que os invasores oferecessem firmwares backdored, os instalassem em dispositivos de outras pessoas ou até mesmo os implantassem remotamente se houver alguma vulnerabilidade de atualização de firmware:

{% content-ref url="firmware-integrity.md" %}
[firmware-integrity.md](firmware-integrity.md)
{% endcontent-ref %}

As vulnerabilidades de atualização de firmware geralmente ocorrem porque, a **integridade** do **firmware** pode **não** ser **validada**, uso de protocolos de **rede** **não** criptografados, uso de **credenciais codificadas** **hardcoded**, uma **autenticação insegura** ao componente de nuvem que hospeda o firmware e até mesmo **logging** excessivo e inseguro (dados sensíveis), permitem **atualizações físicas** sem verificações.

## **Análise em tempo de execução**

A análise em tempo de execução envolve a anexação a um processo em execução ou binário enquanto um dispositivo está sendo executado em seu ambiente normal ou emulado. As etapas básicas de análise em tempo de execução são fornecidas abaixo:

1. `sudo chroot . ./qemu-arch -L <optionalLibPath> -g <gdb_port> <binary>`
2. Anexe o gdb-multiarch ou use o IDA para emular o binário
3. Defina pontos de interrupção para funções identificadas durante a etapa 4, como memcpy, strncpy, strcmp, etc.
4. Execute grandes strings de carga útil para identificar sobrecargas ou falhas no processo usando um fuzzer
5. Mova-se para a etapa 8 se uma vulnerabilidade for identificada

Ferramentas que podem ser úteis são (não exaustivas):

* gdb-multiarch
* [Peda](https://github.com/longld/peda)
* Frida
* ptrace
* strace
* IDA Pro
* Ghidra
* Binary Ninja
* Hopper

## **Exploração binária**

Após identificar uma vulnerabilidade dentro de um binário a partir das etapas anteriores, é necessário um prova de conceito (PoC) adequada para demonstrar o impacto e o risco no mundo real. O desenvolvimento de código de exploração requer experiência em programação em linguagens de nível inferior (por exemplo, ASM, C/C++, shellcode, etc.) e experiência no ambiente de destino específico (por exemplo, MIPS, ARM, x86 etc.). O código PoC envolve a obtenção de execução arbitrária em um dispositivo ou aplicativo controlando uma instrução na memória.

Não é comum que as proteções de tempo de execução binárias (por exemplo, NX, DEP, ASLR, etc.) estejam em vigor dentro de sistemas embarcados, no entanto, quando isso acontece, técnicas adicionais podem ser necessárias, como programação orientada a retorno (ROP). ROP permite que um invasor implemente funcionalidade maliciosa arbitrária encadeando código existente no código do processo/binário do alvo conhecido como gadgets. Serão necessárias etapas para explorar uma vulnerabilidade identificada, como um estouro de buffer, formando uma cadeia ROP. Uma ferramenta que pode ser
