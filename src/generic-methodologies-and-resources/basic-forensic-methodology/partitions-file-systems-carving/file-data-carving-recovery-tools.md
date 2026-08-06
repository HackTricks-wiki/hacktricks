# Ferramentas de File/Data Carving e Recovery

{{#include ../../../banners/hacktricks-training.md}}

## Ferramentas de Carving e Recovery

Mais ferramentas em [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

A ferramenta mais comum usada em forensics para extrair arquivos de imagens é o [**Autopsy**](https://www.autopsy.com/download/). Faça o download, instale-o e faça com que ele ingira o arquivo para encontrar arquivos "ocultos". Observe que o Autopsy foi desenvolvido para oferecer suporte a imagens de disco e outros tipos de imagens, mas não a arquivos simples.

> **Atualização de 2024-2025** – A versão **4.21** (lançada em fevereiro de 2025) adicionou um **módulo de carving baseado no SleuthKit v4.13** reconstruído, que é significativamente mais rápido ao lidar com imagens de vários terabytes e oferece suporte à extração paralela em sistemas multi-core. Também foi introduzido um pequeno wrapper CLI (`autopsycli ingest <case> <image>`), tornando possível criar scripts para o carving em ambientes de CI/CD ou laboratórios de grande escala.<sup>[[1]](#references)</sup>
```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```
### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** é uma ferramenta para analisar arquivos binários e encontrar conteúdo incorporado. Ela pode ser instalada via `apt` e seu código-fonte está disponível no [GitHub](https://github.com/ReFirmLabs/binwalk).

**Comandos úteis**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Nota de segurança** – As versões **≤2.3.3** são afetadas por uma vulnerabilidade de **Path Traversal** (CVE-2022-4510). Faça o upgrade (ou isole usando um container/UID não privilegiado) antes de realizar o carving de samples não confiáveis.<sup>[[2]](#references)</sup>

### Foremost

Outra ferramenta comum para encontrar arquivos ocultos é o **foremost**. Você pode encontrar o arquivo de configuração do foremost em `/etc/foremost.conf`. Se quiser pesquisar apenas alguns arquivos específicos, descomente-os. Se não descomentar nada, o foremost pesquisará os tipos de arquivo configurados por padrão.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** é outra ferramenta que pode ser usada para encontrar e extrair **arquivos incorporados em um arquivo**. Nesse caso, você precisará remover os comentários dos tipos de arquivo que deseja extrair no arquivo de configuração (_/etc/scalpel/scalpel.conf_).
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Esta ferramenta vem incluída no kali, mas você pode encontrá-la aqui: <https://github.com/simsong/bulk_extractor>

O Bulk Extractor pode analisar uma imagem de evidência e recuperar **fragmentos de pcap**, **artefatos de rede (URLs, domínios, IPs, MACs, e-mails)** e muitos outros objetos **em paralelo usando vários scanners**.
```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```
Scripts úteis de pós-processamento (`bulk_diff`, `bulk_extractor_reader.py`) podem eliminar artefatos duplicados entre duas imagens ou converter os resultados para JSON para ingestão em SIEM.

### PhotoRec

Você pode encontrá-lo em <https://www.cgsecurity.org/wiki/TestDisk_Download>

Ele vem com versões GUI e CLI. Você pode selecionar os **tipos de arquivo** que deseja que o PhotoRec procure.

![Executar todos os scanners, fazer carving agressivo de JPEGs e gerar um bodyfile - PhotoRec: Ele vem com versões GUI e CLI. Você pode selecionar os tipos de arquivo que deseja que o PhotoRec procure](<../../../images/image (242).png>)

### ddrescue + ddrescueview (criação de imagens de drives com falhas)

Quando um drive físico está instável, a prática recomendada é **criar uma imagem dele primeiro** e executar as ferramentas de carving somente na imagem. O `ddrescue` (projeto GNU) concentra-se em copiar discos com falhas de forma confiável, mantendo um log dos setores ilegíveis.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
A versão **1.28** (dezembro de 2024) introduziu **`--cluster-size`**, que pode acelerar a criação de imagens de SSDs de alta capacidade, nos quais os tamanhos de setor tradicionais já não se alinham com os blocos de flash.

### Extundelete / Ext4magic (recuperação de arquivos EXT 3/4)

Se o sistema de arquivos de origem for baseado em Linux EXT, talvez seja possível recuperar arquivos excluídos recentemente **sem carving completo**. Ambas as ferramentas funcionam diretamente em uma imagem somente leitura:
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```
> 🛈 Se o sistema de arquivos foi montado após a exclusão, os blocos de dados podem já ter sido reutilizados – nesse caso, o carving adequado (Foremost/Scalpel) ainda é necessário.

### binvis

Confira o [código](https://code.google.com/archive/p/binvis/) e a [ferramenta da página web](https://binvis.io/#/).

#### Recursos do BinVis

- **Visualizador de estrutura** visual e ativo
- Vários gráficos para diferentes pontos de foco
- Foco em partes de uma amostra
- **Visualização de strings e recursos**, em executáveis PE ou ELF, por exemplo
- Obtenção de **padrões** para criptoanálise em arquivos
- **Detecção** de algoritmos de packers ou encoders
- **Identificação** de Steganography por meio de padrões
- **Diffing** binário **visual**

BinVis é um excelente **ponto de partida para se familiarizar com um alvo desconhecido** em um cenário de black-boxing.

## Ferramentas específicas de Data Carving

### FindAES

Busca chaves AES procurando por seus key schedules. É capaz de encontrar chaves de 128, 192 e 256 bits, como as usadas pelo TrueCrypt e pelo BitLocker.

Baixe [aqui](https://sourceforge.net/projects/findaes/).

### YARA-X (triagem de artefatos carved)

[YARA-X](https://github.com/VirusTotal/yara-x) é uma reescrita do YARA em Rust, lançada em 2024. É **10–30× mais rápido** que o YARA clássico e pode ser usado para classificar milhares de objetos carved muito rapidamente:<sup>[[3]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```
O aumento de velocidade torna realista **auto-tag** todos os arquivos recuperados em investigações de grande escala.

## Ferramentas complementares

Você pode usar [**viu** ](https://github.com/atanunq/viu)para ver imagens pelo terminal.  \
Você pode usar a ferramenta de linha de comando do Linux **pdftotext** para transformar um PDF em texto e lê-lo.



## Referências

- [1] [Notas de lançamento do Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21)
- [2] [Path traversal no binwalk (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [3] [YARA está morto, vida longa ao YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)

{{#include ../../../banners/hacktricks-training.md}}
