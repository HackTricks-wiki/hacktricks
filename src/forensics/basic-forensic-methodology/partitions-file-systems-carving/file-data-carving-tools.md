{{#include ../../../banners/hacktricks-training.md}}

# Ferramentas de Carving

## Autopsy

A ferramenta mais comum usada em forense para extrair arquivos de imagens é [**Autopsy**](https://www.autopsy.com/download/). Baixe, instale e faça com que ela processe o arquivo para encontrar arquivos "ocultos". Note que o Autopsy é projetado para suportar imagens de disco e outros tipos de imagens, mas não arquivos simples.

## Binwalk <a id="binwalk"></a>

**Binwalk** é uma ferramenta para buscar arquivos binários como imagens e arquivos de áudio em busca de arquivos e dados incorporados. 
Pode ser instalada com `apt`, no entanto, a [fonte](https://github.com/ReFirmLabs/binwalk) pode ser encontrada no github. 
**Comandos úteis**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Outra ferramenta comum para encontrar arquivos ocultos é **foremost**. Você pode encontrar o arquivo de configuração do foremost em `/etc/foremost.conf`. Se você quiser apenas procurar por alguns arquivos específicos, descomente-os. Se você não descomentar nada, o foremost irá procurar pelos tipos de arquivo configurados por padrão.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** é outra ferramenta que pode ser usada para encontrar e extrair **arquivos incorporados em um arquivo**. Neste caso, você precisará descomentar no arquivo de configuração \(_/etc/scalpel/scalpel.conf_\) os tipos de arquivo que deseja que ele extraia.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Esta ferramenta vem dentro do kali, mas você pode encontrá-la aqui: [https://github.com/simsong/bulk_extractor](https://github.com/simsong/bulk_extractor)

Esta ferramenta pode escanear uma imagem e **extrair pcaps** dentro dela, **informações de rede (URLs, domínios, IPs, MACs, e-mails)** e mais **arquivos**. Você só precisa fazer:
```text
bulk_extractor memory.img -o out_folder
```
Navegue por **todas as informações** que a ferramenta coletou \(senhas?\), **analise** os **pacotes** \(leia[ **análise de Pcaps**](../pcap-inspection/index.html)\), procure por **domínios estranhos** \(domínios relacionados a **malware** ou **inexistentes**\).

## PhotoRec

Você pode encontrá-lo em [https://www.cgsecurity.org/wiki/TestDisk_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Ele vem com versão GUI e CLI. Você pode selecionar os **tipos de arquivo** que deseja que o PhotoRec procure.

![](../../../images/image%20%28524%29.png)

# Ferramentas Específicas de Carving de Dados

## FindAES

Procura por chaves AES pesquisando suas programações de chave. Capaz de encontrar chaves de 128, 192 e 256 bits, como as usadas pelo TrueCrypt e BitLocker.

Baixe [aqui](https://sourceforge.net/projects/findaes/).

# Ferramentas Complementares

Você pode usar [**viu** ](https://github.com/atanunq/viu) para ver imagens a partir do terminal.  
Você pode usar a ferramenta de linha de comando do linux **pdftotext** para transformar um pdf em texto e lê-lo.

{{#include ../../../banners/hacktricks-training.md}}
