# Ferramentas de carving e recuperação de arquivos/dados

{{#include ../../../banners/hacktricks-training.md}}

## Ferramentas de carving e recuperação

Sempre faça carving de uma **cópia verificada**, nunca do dispositivo original. Consulte [Image Acquisition & Mount](../image-acquisition-and-mount.md) para workflows de aquisição somente leitura e hashing.

Mais ferramentas em [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

A ferramenta mais comum em forense para extrair arquivos de imagens é o [**Autopsy**](https://www.autopsy.com/download/). Baixe-o, instale-o e faça com que processe o arquivo para encontrar arquivos "ocultos". Observe que o Autopsy foi desenvolvido para oferecer suporte a imagens de disco e outros tipos de imagens, mas não a arquivos simples.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** é uma ferramenta para analisar arquivos binários e encontrar conteúdo incorporado. **Binwalk v3** é uma reescrita em Rust com extração automática (`-e`), carving bruto de objetos conhecidos e desconhecidos (`-c`), varredura recursiva (Matryoshka) (`-M`) e threads de trabalho configuráveis. O projeto recomenda sua imagem Docker quando todos os extratores externos forem necessários; `cargo install binwalk` instala a CLI em Rust, mas não essas dependências externas.<sup>[[11]](#references)</sup>

**Comandos úteis do v3**:

```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```

A receita legada `--dd='.*'` do v2 **não** é o equivalente no v3 de `-c`; primeiro verifique `binwalk --version` ao seguir comandos antigos de CTF/write-up.<sup>[[11]](#references)</sup>

⚠️  **Nota de segurança** – As versões **2.1.2b até 2.3.3** são afetadas por uma vulnerabilidade de **Path Traversal** (CVE-2022-4510); o comunicado não lista nenhuma versão corrigida do pip. Evite extrair amostras não confiáveis com versões afetadas ou isole a ferramenta usando um contêiner/UID sem privilégios.<sup>[[4]](#references)</sup>

### Foremost

Outra ferramenta comum para encontrar arquivos ocultos é o **foremost**. Você pode encontrar o arquivo de configuração do foremost em `/etc/foremost.conf`. Se quiser procurar apenas alguns arquivos específicos, descomente-os. Se não descomentar nada, o foremost procurará os tipos de arquivo configurados por padrão.

```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```

### **Scalpel**

**Scalpel** é outra ferramenta que pode ser usada para localizar e extrair **arquivos incorporados em um arquivo**. Nesse caso, você precisará descomentar, no arquivo de configuração (_/etc/scalpel/scalpel.conf_), os tipos de arquivo que deseja extrair.

```bash
sudo apt-get install scalpel
scalpel file.img -o output
```

### Scalpel3: carving fragmentado

Quando a recuperação baseada primeiro em metadados e os carvers contíguos deixam arquivos divididos incompletos, o **Scalpel3** pode remontar formatos compatíveis usando validadores de arquivo/bloco. Ele é uma base de código diferente do comando legado `scalpel` mencionado acima. Primeiro, crie o blockmap necessário usando o **mesmo tamanho de bloco** empregado no carving; use o tamanho do cluster do sistema de arquivos informado por `fsstat`, se conhecido, ou determine um valor justificável antes de analisar uma imagem de partição. Execute-o apenas sobre uma cópia verificada e grave a saída em um volume separado.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

```bash
git clone https://github.com/nolaforensix/scalpel3-release.git
cd scalpel3-release && ./init_scalpel3.sh && cd src
./crblockmap -q 4096 /evidence/partition.img /analysis/partition.blockmap
./scalpel3 -Y cpu -q 4096 -w -b -o /analysis/scalpel3 \
  /evidence/partition.img /analysis/partition.blockmap
```

Substitua `4096` pelo tamanho de bloco selecionado. `-w` mantém candidatos **PROMISING**, assim como os validados, e `-b` grava vetores de blocos para ajudar a verificar layouts reconstruídos. Um arquivo em PROMISING ou com uma extensão conhecida não comprova uma recuperação completa; valide o conteúdo antes de usá-lo.<sup>[[13]](#references)[[14]](#references)</sup> Para localizar partições excluídas ou lacunas antes do carving, consulte [Encontrar dados fora das partições listadas](./#finding-data-outside-listed-partitions).

### Bulk Extractor 2.x   

Esta ferramenta vem com o Kali, mas você pode encontrá-la aqui: <https://github.com/simsong/bulk_extractor>

O Bulk Extractor pode examinar uma imagem de evidência e fazer carving de **fragmentos de pcap**, **artefatos de rede (URLs, domínios, IPs, MACs, e-mails)** e muitos outros objetos **em paralelo, usando vários scanners**.

A versão 2.1.1 documenta uma compilação com Autotools e a configuração `-S jpeg_carve_mode=2` para fazer carving de todos os JPEGs contíguos.<sup>[[2]](#references)</sup>

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

O `bulk_diff.py` incluído compara duas execuções do bulk_extractor, enquanto o `bulk_extractor_reader.py` lê os arquivos de relatório e de recursos.<sup>[[3]](#references)</sup>

### PhotoRec

Você pode encontrá-lo em <https://www.cgsecurity.org/wiki/TestDisk_Download>

Ele vem com versões GUI e CLI. Você pode selecionar os **tipos de arquivo** que deseja que o PhotoRec procure.

![Execute todos os scanners, faça carving agressivo de JPEGs e gere um bodyfile - PhotoRec: Ele vem com versões GUI e CLI. Você pode selecionar os tipos de arquivo que deseja que o PhotoRec procure](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover` (metadata-first)

Antes de fazer carving de assinaturas brutas, tente a recuperação com reconhecimento do sistema de arquivos quando os metadados do volume ainda puderem ser analisados. Por padrão, `tsk_recover` exporta apenas arquivos não alocados; `-a` seleciona arquivos alocados e `-e` exporta ambos. Para uma imagem de disco inteira, passe o **setor inicial** da partição, obtido com `mmls`, para `-o` (não converta para bytes). Se a entrada já for uma imagem de partição, omita `-o`.<sup>[[12]](#references)</sup>

```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```

Esta etapa pode preservar nomes e caminhos derivados do sistema de arquivos, algo que a recuperação por cabeçalho/rodapé não consegue fazer; depois, execute Foremost, Scalpel ou PhotoRec para entradas cujos metadados estejam ausentes ou inutilizáveis.<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview (criação de imagens de unidades com falhas)

Quando uma unidade física está instável, é recomendável **criar uma imagem dela primeiro** e só então executar ferramentas de carving na imagem. `ddrescue` (projeto GNU) concentra-se em copiar discos danificados de forma confiável, mantendo um registro dos setores ilegíveis.

```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
 ddrescueview suspect.log
```

A opção **`--cluster-size`** controla quantos setores são copiados por vez; valores menores podem ajudar com unidades lentas.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (recuperação de arquivos excluídos EXT 3/4)

Se o sistema de arquivos de origem for baseado em Linux EXT, talvez seja possível recuperar arquivos excluídos recentemente **sem carving completo**; essas ferramentas baseadas em journal funcionam em um sistema de arquivos desmontado ou em uma imagem somente leitura.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```

> **Nota de compatibilidade** – o ext4magic foi abandonado; a página do projeto avisa que os sistemas de arquivos atuais não são mais compatíveis com ele.<sup>[[10]](#references)</sup>

> 🛈 Se o sistema de arquivos foi montado após a exclusão, os blocos de dados podem já ter sido reutilizados – nesse caso, ainda é necessário fazer carving adequado (Foremost/Scalpel).

### binvis

Confira o [código](https://code.google.com/archive/p/binvis/) e a [ferramenta da página web](https://binvis.io/#/).

#### Recursos do BinVis

- **Visualizador de estruturas** visual e interativo
- Vários gráficos para diferentes pontos de foco
- Foco em partes de uma amostra
- **Visualização de strings e recursos**, por exemplo, em executáveis PE ou ELF
- Obtenção de **padrões** para criptoanálise de arquivos
- **Detecção** de algoritmos de empacotamento ou codificação
- **Identificação** de esteganografia por padrões
- **Comparação visual** de binários

O BinVis é um ótimo **ponto de partida para se familiarizar com um alvo desconhecido** em um cenário de black-boxing.

## Ferramentas específicas de Data Carving

### FindAES

Procura chaves AES pesquisando seus key schedules. É capaz de encontrar chaves de 128, 192 e 256 bits, como as usadas pelo TrueCrypt e BitLocker.

Baixe [aqui](https://sourceforge.net/projects/findaes/).

### YARA-X (triagem de artefatos recuperados)

[YARA-X](https://github.com/VirusTotal/yara-x) é uma reescrita do YARA em Rust, lançada em 2024; o VirusTotal informa que algumas regras com expressões regulares e loops complexos podem ser executadas significativamente mais rápido.<sup>[[5]](#references)</sup> Sua CLI se chama `yr`, e o comando `scan` oferece suporte a varreduras recursivas, configuração do número de threads e saída de metadados.<sup>[[6]](#references)</sup>

```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```

## Ferramentas complementares

Você pode usar [**viu** ](https://github.com/atanunq/viu)para ver imagens no terminal.  \
Você pode usar a ferramenta de linha de comando **pdftotext** do Linux para transformar um PDF em texto e lê-lo.







## References

- [1] [Notas de lançamento do Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [README do bulk_extractor v2.1.1](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [README das ferramentas Python do bulk_extractor](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Path traversal no binwalk (CVE-2022-4510) - Banco de dados de avisos do GitHub](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA morreu, vida longa ao YARA-X - Blog do VirusTotal](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [Comandos da CLI do YARA-X](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [Manual do GNU ddrescue](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [Manual do ext4magic](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [Status do projeto ext4magic](https://sourceforge.net/projects/ext4magic/)
- [11] [README do Binwalk v3](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit: manual do tsk_recover](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
- [13] [README do Scalpel3](https://github.com/nolaforensix/scalpel3-release/blob/main/README.md)
- [14] [Manual do Scalpel3](https://github.com/nolaforensix/scalpel3-release/blob/main/man/scalpel3.1)
- [15] [Fluxo de trabalho de teste do Scalpel3](https://github.com/nolaforensix/scalpel3-release/blob/main/src/TESTS/cmdline.test)
{{#include ../../../banners/hacktricks-training.md}}
