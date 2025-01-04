# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving & Recovery tools

Mais ferramentas em [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

A ferramenta mais comum usada em forense para extrair arquivos de imagens é [**Autopsy**](https://www.autopsy.com/download/). Baixe, instale e faça com que ela processe o arquivo para encontrar arquivos "ocultos". Note que o Autopsy é projetado para suportar imagens de disco e outros tipos de imagens, mas não arquivos simples.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** é uma ferramenta para analisar arquivos binários para encontrar conteúdo embutido. É instalável via `apt` e seu código-fonte está no [GitHub](https://github.com/ReFirmLabs/binwalk).

**Comandos úteis**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

Outra ferramenta comum para encontrar arquivos ocultos é **foremost**. Você pode encontrar o arquivo de configuração do foremost em `/etc/foremost.conf`. Se você quiser apenas procurar por alguns arquivos específicos, descomente-os. Se você não descomentar nada, o foremost irá procurar pelos tipos de arquivo configurados por padrão.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** é outra ferramenta que pode ser usada para encontrar e extrair **arquivos incorporados em um arquivo**. Neste caso, você precisará descomentar no arquivo de configuração (_/etc/scalpel/scalpel.conf_) os tipos de arquivo que deseja que ele extraia.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

Esta ferramenta vem dentro do kali, mas você pode encontrá-la aqui: [https://github.com/simsong/bulk_extractor](https://github.com/simsong/bulk_extractor)

Esta ferramenta pode escanear uma imagem e **extrair pcaps** dentro dela, **informações de rede (URLs, domínios, IPs, MACs, e-mails)** e mais **arquivos**. Você só precisa fazer:
```
bulk_extractor memory.img -o out_folder
```
Navegue por **todas as informações** que a ferramenta coletou (senhas?), **analise** os **pacotes** (leia[ **análise de Pcaps**](../pcap-inspection/index.html)), procure por **domínios estranhos** (domínios relacionados a **malware** ou **inexistentes**).

### PhotoRec

Você pode encontrá-lo em [https://www.cgsecurity.org/wiki/TestDisk_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Ele vem com versões GUI e CLI. Você pode selecionar os **tipos de arquivo** que deseja que o PhotoRec procure.

![](<../../../images/image (524).png>)

### binvis

Verifique o [código](https://code.google.com/archive/p/binvis/) e a [página da ferramenta](https://binvis.io/#/).

#### Recursos do BinVis

- Visualizador de **estrutura** visual e ativa
- Múltiplos gráficos para diferentes pontos de foco
- Foco em porções de uma amostra
- **Visualizando strings e recursos**, em executáveis PE ou ELF, por exemplo
- Obtendo **padrões** para criptoanálise em arquivos
- **Identificando** algoritmos de empacotamento ou codificação
- **Identificar** Esteganografia por padrões
- **Diferença** binária visual

BinVis é um ótimo **ponto de partida para se familiarizar com um alvo desconhecido** em um cenário de caixa-preta.

## Ferramentas Específicas de Carving de Dados

### FindAES

Procura por chaves AES pesquisando por seus cronogramas de chaves. Capaz de encontrar chaves de 128, 192 e 256 bits, como as usadas pelo TrueCrypt e BitLocker.

Baixe [aqui](https://sourceforge.net/projects/findaes/).

## Ferramentas Complementares

Você pode usar [**viu** ](https://github.com/atanunq/viu) para ver imagens a partir do terminal.\
Você pode usar a ferramenta de linha de comando do linux **pdftotext** para transformar um pdf em texto e lê-lo.

{{#include ../../../banners/hacktricks-training.md}}
