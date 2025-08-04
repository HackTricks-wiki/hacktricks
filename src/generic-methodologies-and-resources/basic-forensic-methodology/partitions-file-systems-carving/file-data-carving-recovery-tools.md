# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving & Recovery tools

Mais ferramentas em [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

A ferramenta mais comum usada em forense para extrair arquivos de imagens é [**Autopsy**](https://www.autopsy.com/download/). Baixe, instale e faça com que ela processe o arquivo para encontrar arquivos "ocultos". Note que o Autopsy é projetado para suportar imagens de disco e outros tipos de imagens, mas não arquivos simples.

> **Atualização 2024-2025** – A versão **4.21** (lançada em fevereiro de 2025) adicionou um **módulo de carving refeito baseado no SleuthKit v4.13** que é visivelmente mais rápido ao lidar com imagens de múltiplos terabytes e suporta extração paralela em sistemas multi-core.¹ Um pequeno wrapper CLI (`autopsycli ingest <case> <image>`) também foi introduzido, tornando possível scriptar carving dentro de ambientes CI/CD ou de laboratório em grande escala.
```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```
### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** é uma ferramenta para analisar arquivos binários em busca de conteúdo embutido. Pode ser instalada via `apt` e seu código-fonte está no [GitHub](https://github.com/ReFirmLabs/binwalk).

**Comandos úteis**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Nota de segurança** – Versões **≤2.3.3** são afetadas por uma vulnerabilidade de **Path Traversal** (CVE-2022-4510). Atualize (ou isole com um contêiner/UID não privilegiado) antes de fazer carving de amostras não confiáveis.

### Foremost

Outra ferramenta comum para encontrar arquivos ocultos é **foremost**. Você pode encontrar o arquivo de configuração do foremost em `/etc/foremost.conf`. Se você quiser apenas procurar por alguns arquivos específicos, descomente-os. Se você não descomentar nada, o foremost irá procurar pelos tipos de arquivo configurados por padrão.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** é outra ferramenta que pode ser usada para encontrar e extrair **arquivos incorporados em um arquivo**. Neste caso, você precisará descomentar no arquivo de configuração (_/etc/scalpel/scalpel.conf_) os tipos de arquivo que deseja que ele extraia.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Esta ferramenta vem incluída no kali, mas você pode encontrá-la aqui: <https://github.com/simsong/bulk_extractor>

Bulk Extractor pode escanear uma imagem de evidência e extrair **fragmentos de pcap**, **artefatos de rede (URLs, domínios, IPs, MACs, e-mails)** e muitos outros objetos **em paralelo usando múltiplos scanners**.
```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```
Scripts de pós-processamento úteis (`bulk_diff`, `bulk_extractor_reader.py`) podem deduplicar artefatos entre duas imagens ou converter resultados para JSON para ingestão em SIEM.

### PhotoRec

Você pode encontrá-lo em <https://www.cgsecurity.org/wiki/TestDisk_Download>

Ele vem com versões GUI e CLI. Você pode selecionar os **tipos de arquivo** que deseja que o PhotoRec procure.

![](<../../../images/image (242).png>)

### ddrescue + ddrescueview (imagem de drives com falha)

Quando um drive físico está instável, é uma boa prática **fazer a imagem primeiro** e apenas executar ferramentas de carving contra a imagem. `ddrescue` (projeto GNU) foca em copiar de forma confiável discos ruins enquanto mantém um registro de setores ilegíveis.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Versão **1.28** (dezembro de 2024) introduziu **`--cluster-size`** que pode acelerar a imagem de SSDs de alta capacidade onde os tamanhos de setor tradicionais não se alinham mais com os blocos de flash.

### Extundelete / Ext4magic (EXT 3/4 undelete)

Se o sistema de arquivos de origem for baseado em Linux EXT, você pode ser capaz de recuperar arquivos recentemente excluídos **sem carving completo**. Ambas as ferramentas funcionam diretamente em uma imagem somente leitura:
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```
> 🛈 Se o sistema de arquivos foi montado após a exclusão, os blocos de dados podem já ter sido reutilizados – nesse caso, a recuperação adequada (Foremost/Scalpel) ainda é necessária.

### binvis

Verifique o [código](https://code.google.com/archive/p/binvis/) e a [ferramenta da página web](https://binvis.io/#/).

#### Recursos do BinVis

- Visual e ativo **visualizador de estrutura**
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

### YARA-X (triagem de artefatos esculpidos)

[YARA-X](https://github.com/VirusTotal/yara-x) é uma reescrita em Rust do YARA lançada em 2024. É **10-30× mais rápida** que o YARA clássico e pode ser usada para classificar milhares de objetos esculpidos muito rapidamente:
```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```
O aumento de velocidade torna realista **auto-tag** todos os arquivos extraídos em investigações em larga escala.

## Ferramentas complementares

Você pode usar [**viu** ](https://github.com/atanunq/viu) para ver imagens a partir do terminal.  \
Você pode usar a ferramenta de linha de comando do linux **pdftotext** para transformar um pdf em texto e lê-lo.

## Referências

1. Notas de lançamento do Autopsy 4.21 – <https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21>
{{#include ../../../banners/hacktricks-training.md}}
