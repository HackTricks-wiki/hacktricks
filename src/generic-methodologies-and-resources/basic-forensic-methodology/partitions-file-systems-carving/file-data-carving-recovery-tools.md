# Ferramentas de Carving e Recuperação de Arquivos/Dados

{{#include ../../../banners/hacktricks-training.md}}

## Ferramentas de Carving e Recuperação

Sempre faça carving em uma **cópia verificada**, não no dispositivo original. Consulte [Aquisição e Montagem de Imagem](../image-acquisition-and-mount.md) para obter workflows de aquisição somente leitura e hashing.

Mais ferramentas em [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

A ferramenta mais comum usada em forensics para extrair arquivos de imagens é o [**Autopsy**](https://www.autopsy.com/download/). Faça o download, instale-o e faça com que ele processe o arquivo para encontrar arquivos "ocultos". Observe que o Autopsy foi desenvolvido para oferecer suporte a imagens de disco e outros tipos de imagens, mas não a arquivos simples.

### Binwalk <a href="#binwalk" id="binwalk"></a>

O **Binwalk** é uma ferramenta para analisar arquivos binários e encontrar conteúdo incorporado. O **Binwalk v3** é uma reescrita em Rust com extração automática (`-e`), carving bruto de objetos conhecidos e desconhecidos (`-c`), varredura recursiva/Matryoshka (`-M`) e threads de workers configuráveis. O projeto recomenda seu build Docker quando todos os extractors externos forem necessários; `cargo install binwalk` instala a CLI em Rust, mas não essas dependências externas.<sup>[[11]](#references)</sup>

**Comandos úteis da v3**:
```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```
A receita legada `--dd='.*'` da v2 **não é o equivalente na v3 de `-c`**; primeiro verifique `binwalk --version` ao seguir comandos antigos de CTF/write-up.<sup>[[11]](#references)</sup>

⚠️  **Nota de segurança** – As versões **2.1.2b a 2.3.3** são afetadas por uma vulnerabilidade de **Path Traversal** (CVE-2022-4510); o aviso não lista nenhuma versão corrigida do pip. Evite extrair amostras não confiáveis com versões afetadas ou isole a ferramenta usando um container/UID não privilegiado.<sup>[[4]](#references)</sup>

### Foremost

Outra ferramenta comum para encontrar arquivos ocultos é o **foremost**. Você pode encontrar o arquivo de configuração do foremost em `/etc/foremost.conf`. Se quiser apenas procurar por alguns arquivos específicos, remova o comentário deles. Se você não remover nenhum comentário, o foremost procurará pelos tipos de arquivo configurados por padrão.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** é outra ferramenta que pode ser usada para localizar e extrair **arquivos incorporados em um arquivo**. Nesse caso, será necessário remover o comentário dos tipos de arquivo que você deseja extrair no arquivo de configuração (_/etc/scalpel/scalpel.conf_).
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Esta ferramenta vem incluída no kali, mas você pode encontrá-la aqui: <https://github.com/simsong/bulk_extractor>

O Bulk Extractor pode analisar uma imagem de evidência e fazer o carving de **fragmentos pcap**, **artefatos de rede (URLs, domínios, IPs, MACs, e-mails)** e muitos outros objetos **em paralelo usando vários scanners**.

A versão v2.1.1 documenta um build com Autotools e a configuração `-S jpeg_carve_mode=2` para fazer o carving de todos os JPEGs contíguos.<sup>[[2]](#references)</sup>
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
O `bulk_diff.py` incluído compara duas execuções do bulk_extractor, enquanto o `bulk_extractor_reader.py` lê o relatório e os arquivos de recursos.<sup>[[3]](#references)</sup>

### PhotoRec

Você pode encontrá-lo em <https://www.cgsecurity.org/wiki/TestDisk_Download>

Ele vem com versões GUI e CLI. Você pode selecionar os **tipos de arquivo** que deseja que o PhotoRec pesquise.

![Execute todos os scanners, faça o carving agressivo de arquivos JPEG e gere um bodyfile - PhotoRec: Ele vem com versões GUI e CLI. Você pode selecionar os tipos de arquivo que deseja que o PhotoRec pesquise](<../../../images/image (242).png>)

### `tsk_recover` do The Sleuth Kit (metadados primeiro)

Antes do carving de assinaturas brutas, tente a recuperação com reconhecimento do sistema de arquivos quando os metadados do volume ainda puderem ser analisados. Por padrão, `tsk_recover` exporta apenas arquivos não alocados; `-a` seleciona arquivos alocados e `-e` exporta ambos. Para uma imagem de disco inteira, passe o **setor inicial** da partição, obtido com `mmls`, para `-o` (não o converta em bytes). Se a entrada já for uma imagem de partição, omita `-o`.<sup>[[12]](#references)</sup>
```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```
Esta etapa pode preservar nomes e caminhos derivados do filesystem que o carving de cabeçalho/rodapé não consegue; execute Foremost, Scalpel ou PhotoRec posteriormente para entradas cujo metadata esteja ausente ou inutilizável.<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview (criação de imagem de drives com falhas)

Quando um drive físico está instável, a prática recomendada é **criar uma imagem dele primeiro** e executar as ferramentas de carving somente na imagem. O `ddrescue` (projeto GNU) concentra-se em copiar discos defeituosos de forma confiável, mantendo um log dos setores ilegíveis.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
A opção **`--cluster-size`** controla quantos setores são copiados de cada vez; valores menores podem ajudar com unidades lentas.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (EXT 3/4 undelete)

Se o sistema de arquivos de origem for baseado em Linux EXT, talvez seja possível recuperar arquivos excluídos recentemente **sem carving completo**; essas ferramentas baseadas em journal funcionam em um sistema de arquivos desmontado ou em uma imagem somente leitura.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **Nota de compatibilidade** – ext4magic foi abandonado; a página do projeto alerta que os sistemas de arquivos atuais já não são compatíveis com ele.<sup>[[10]](#references)</sup>

> 🛈 Se o sistema de arquivos foi montado após a exclusão, os blocos de dados podem já ter sido reutilizados – nesse caso, o carving adequado (Foremost/Scalpel) ainda é necessário.

### binvis

Confira o [código](https://code.google.com/archive/p/binvis/) e a [ferramenta da página web](https://binvis.io/#/).

#### Recursos do BinVis

- **Visualizador de estrutura** ativo e visual
- Vários gráficos para diferentes pontos de foco
- Foco em partes de uma amostra
- **Visualização de strings e recursos**, por exemplo, em executáveis PE ou ELF
- Obtenção de **padrões** para criptoanálise em arquivos
- **Detecção** de algoritmos de packer ou encoder
- **Identificação** de Steganography por padrões
- **Diffing** binário **visual**

BinVis é um excelente **ponto de partida para se familiarizar com um alvo desconhecido** em um cenário de black-boxing.

## Ferramentas específicas de Data Carving

### FindAES

Procura chaves AES buscando seus key schedules. Capaz de encontrar chaves de 128, 192 e 256 bits, como as usadas pelo TrueCrypt e BitLocker.

Baixe [aqui](https://sourceforge.net/projects/findaes/).

### YARA-X (triagem de artefatos carved)

[YARA-X](https://github.com/VirusTotal/yara-x) é uma reescrita do YARA em Rust, introduzida em 2024; o VirusTotal relata que algumas regras de expressões regulares e loops complexos podem ser executadas significativamente mais rápido.<sup>[[5]](#references)</sup> Sua CLI se chama `yr`, e o comando `scan` oferece suporte a varreduras recursivas, definição do número de threads e saída de metadados.<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## Ferramentas complementares

Você pode usar [**viu** ](https://github.com/atanunq/viu)para ver imagens no terminal.  \
Você pode usar a ferramenta de linha de comando do Linux **pdftotext** para transformar um pdf em texto e lê-lo.





## References

- [1] [Notas de lançamento do Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [README do bulk_extractor v2.1.1](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [README das ferramentas Python do bulk_extractor](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Path traversal no binwalk (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA morreu, longa vida ao YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [Comandos da CLI do YARA-X](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [Manual do GNU ddrescue](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [Manual do ext4magic](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [Status do projeto ext4magic](https://sourceforge.net/projects/ext4magic/)
- [11] [README do Binwalk v3](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit: manual do tsk_recover](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
{{#include ../../../banners/hacktricks-training.md}}
