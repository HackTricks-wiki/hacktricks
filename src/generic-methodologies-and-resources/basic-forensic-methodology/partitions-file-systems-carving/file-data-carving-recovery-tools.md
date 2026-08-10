# Ferramentas de Carving e Recuperação de Arquivos/Dados

## Ferramentas de Carving e Recuperação

Mais ferramentas em [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

A ferramenta mais comum usada em forensics para extrair arquivos de imagens é o [**Autopsy**](https://www.autopsy.com/download/). Faça o download, instale-o e faça com que ele processe o arquivo para encontrar arquivos "ocultos". Observe que o Autopsy foi desenvolvido para oferecer suporte a imagens de disco e outros tipos de imagens, mas não a arquivos simples.

### Binwalk <a href="#binwalk" id="binwalk"></a>

O **Binwalk** é uma ferramenta para analisar arquivos binários e encontrar conteúdo incorporado. Ela pode ser instalada via `apt` e seu código-fonte está no [GitHub](https://github.com/ReFirmLabs/binwalk).

**Comandos úteis**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Nota de segurança** – As versões **2.1.2b a 2.3.3** são afetadas por uma vulnerabilidade de **Path Traversal** (CVE-2022-4510); o advisory não lista nenhuma versão corrigida do pip. Evite extrair samples não confiáveis com releases afetadas ou isole a ferramenta com um container/UID não privilegiado.<sup>[[4]](#references)</sup>

### Foremost

Outra ferramenta comum para encontrar arquivos ocultos é o **foremost**. Você pode encontrar o arquivo de configuração do foremost em `/etc/foremost.conf`. Se quiser apenas procurar alguns arquivos específicos, descomente-os. Se não descomentar nada, o foremost procurará os tipos de arquivo configurados por padrão.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** é outra ferramenta que pode ser usada para localizar e extrair **arquivos incorporados em um arquivo**. Nesse caso, será necessário remover o comentário, no arquivo de configuração (_/etc/scalpel/scalpel.conf_), dos tipos de arquivo que você deseja extrair.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Esta ferramenta vem incluída no Kali, mas você pode encontrá-la aqui: <https://github.com/simsong/bulk_extractor>

Bulk Extractor pode analisar uma imagem de evidência e realizar o carving de **fragmentos pcap**, **artefatos de rede (URLs, domínios, IPs, MACs, e-mails)** e muitos outros objetos **em paralelo usando vários scanners**.

A versão v2.1.1 documenta um build do Autotools e a configuração `-S jpeg_carve_mode=2` para realizar o carving de todos os JPEGs contíguos.<sup>[[2]](#references)</sup>
```bash
# Build from source – v2.1.1 (April 2024) requires C++17
git clone --branch v2.1.1 --recurse-submodules https://github.com/simsong/bulk_extractor.git
cd bulk_extractor
./bootstrap.sh
./configure
make -j"$(nproc)"
sudo make install

# Scan an image and carve contiguous JPEGs
bulk_extractor -o out_folder -S jpeg_carve_mode=2 /evidence/disk.img
```
O `bulk_diff.py` incluído compara duas execuções do bulk_extractor, enquanto o `bulk_extractor_reader.py` lê o relatório e os arquivos de features.<sup>[[3]](#references)</sup>

### PhotoRec

Você pode encontrá-lo em <https://www.cgsecurity.org/wiki/TestDisk_Download>

Ele vem com versões GUI e CLI. Você pode selecionar os **tipos de arquivo** que deseja que o PhotoRec procure.

![Executar todos os scanners, fazer o carving agressivo de JPEGs e gerar um bodyfile - PhotoRec: Ele vem com versões GUI e CLI. Você pode selecionar os tipos de arquivo que deseja que o PhotoRec procure](<../../../images/image (242).png>)

### ddrescue + ddrescueview (imaging de drives com falhas)

Quando um drive físico está instável, é uma boa prática fazer o **imaging primeiro** e executar as ferramentas de carving somente na imagem. O `ddrescue` (projeto GNU) concentra-se em copiar discos danificados de forma confiável, mantendo um log dos setores ilegíveis.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
A opção **`--cluster-size`** controla quantos setores são copiados por vez; valores menores podem ajudar com drives lentos.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (undelete de EXT 3/4)

Se o sistema de arquivos de origem for baseado em Linux EXT, talvez seja possível recuperar arquivos excluídos recentemente **sem fazer carving completo**; essas ferramentas baseadas em journal funcionam em um sistema de arquivos desmontado ou em uma imagem somente leitura.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **Nota de compatibilidade** – ext4magic foi abandonado; a página do projeto alerta que os sistemas de arquivos atuais não são mais compatíveis com ele.<sup>[[10]](#references)</sup>

> 🛈 Se o sistema de arquivos foi montado após a exclusão, os blocos de dados podem já ter sido reutilizados – nesse caso, o carving adequado (Foremost/Scalpel) ainda é necessário.

### binvis

Confira o [código](https://code.google.com/archive/p/binvis/) e a [ferramenta da página web](https://binvis.io/#/).

#### Recursos do BinVis

- **Visualizador de estrutura** visual e ativo
- Vários gráficos para diferentes pontos de foco
- Foco em partes de uma amostra
- **Visualização de strings e recursos**, em executáveis PE ou ELF, por exemplo
- Obtenção de **padrões** para criptoanálise em arquivos
- **Identificação** de algoritmos de packers ou encoders
- **Identificação** de esteganografia por padrões
- **Diffing** binário **visual**

O BinVis é um excelente **ponto de partida para se familiarizar com um alvo desconhecido** em um cenário de black-boxing.

## Ferramentas específicas de Data Carving

### FindAES

Pesquisa chaves AES procurando pelos respectivos key schedules. Capaz de encontrar chaves de 128, 192 e 256 bits, como as usadas pelo TrueCrypt e pelo BitLocker.

Baixe [aqui](https://sourceforge.net/projects/findaes/).

### YARA-X (triagem de artefatos obtidos por carving)

O [YARA-X](https://github.com/VirusTotal/yara-x) é uma reescrita do YARA em Rust, introduzida em 2024; o VirusTotal informa que algumas regras de expressões regulares e loops complexos podem ser executadas significativamente mais rápido.<sup>[[5]](#references)</sup> Sua CLI é chamada `yr`, e o comando `scan` oferece suporte a scans recursivos, definição do número de threads e saída de metadados.<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## Ferramentas complementares

Você pode usar [**viu** ](https://github.com/atanunq/viu)para ver imagens pelo terminal.  \
Você pode usar a ferramenta de linha de comando do Linux **pdftotext** para transformar um PDF em texto e lê-lo.



## References

- [1] [Notas de lançamento do Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [README do bulk_extractor v2.1.1](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [README das ferramentas Python do bulk_extractor](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Path traversal no binwalk (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA morreu, vida longa ao YARA-X - Blog do VirusTotal](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [Comandos CLI do YARA-X](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [Manual do GNU ddrescue](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [Manual do ext4magic](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [Status do projeto ext4magic](https://sourceforge.net/projects/ext4magic/)
{{#include ../../../banners/hacktricks-training.md}}
