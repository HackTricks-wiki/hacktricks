# Traversal de Caminho na Extração de Arquivos ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Visão geral

Muitos formatos de arquivo (ZIP, RAR, TAR, 7-ZIP etc.) permitem que cada entrada contenha seu próprio **caminho interno**. Quando um utilitário de extração considera esse caminho cegamente, um nome de arquivo criado contendo `..` ou um **caminho absoluto** (por exemplo, `C:\Windows\System32\`) será gravado fora do diretório escolhido pelo usuário.
Essa classe de vulnerabilidade é amplamente conhecida como *Zip-Slip* ou **traversal de caminho na extração de arquivos**.<sup>[[6]](#references)</sup>

As consequências variam desde a sobrescrita de arquivos arbitrários até a obtenção direta de **execução remota de código (RCE)** ao colocar um payload em um local de **execução automática**, como a pasta *Startup* do Windows.

## Causa raiz

1. O atacante cria um arquivo contendo um ou mais cabeçalhos de arquivo com:
* Sequências de traversal relativas (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Caminhos absolutos (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ou **symlinks** criados para resolver fora do diretório de destino (comum em ZIP/TAR em sistemas *nix).
2. A vítima extrai o arquivo com uma ferramenta vulnerável que confia no caminho incorporado (ou segue symlinks), em vez de sanitizá-lo ou forçar a extração dentro do diretório escolhido.
3. O arquivo é gravado no local controlado pelo atacante e executado/carregado na próxima vez que o sistema ou o usuário acionar esse caminho.

### Traversal com `.NET` `Path.Combine` + `ZipArchive`

Um anti-pattern comum em .NET consiste em combinar o destino pretendido com `ZipArchiveEntry.FullName` **controlado pelo usuário** e extrair sem normalização de caminho:<sup>[[4]](#references)[[8]](#references)</sup>
```csharp
using (var zip = ZipFile.OpenRead(zipPath))
{
foreach (var entry in zip.Entries)
{
var dest = Path.Combine(@"C:\samples\queue\", entry.FullName); // drops base if FullName is absolute
entry.ExtractToFile(dest);
}
}
```
- Se `entry.FullName` começa com `..\\`, ele atravessa diretórios; se for um **absolute path**, o componente à esquerda será completamente descartado, resultando em um **arbitrary file write** como identidade da extração.
- Archive de prova de conceito para gravar em um diretório `app` irmão monitorado por um scanner agendado:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Colocar esse ZIP na caixa de entrada monitorada resulta em `C:\samples\app\0xdf.txt`, comprovando traversal para fora de `C:\samples\queue\` e habilitando primitives subsequentes (por exemplo, DLL hijacks).

## Primitives Avançadas de Archive-Breakout

Trate a extração como uma sequência de mutações no filesystem, não como verificações independentes de nomes de arquivo. Uma entry que é segura quando analisada pode se tornar insegura depois que um membro anterior cria ou substitui um link; o mesmo problema ocorre quando um extractor armazena um diretório em cache como seguro e depois altera seu tipo.<sup>[[11]](#references)</sup>

### Pivots de Link e Colisões de Entries

* **Symlink write-through**: crie `pivot -> /tmp` e depois extraia um membro regular como `pivot/PWNED.txt`. Se o extractor seguir o primeiro membro ao materializar o segundo, a escrita escapará sem `..` no segundo nome.
* **Colisão de Directory-cache/TOCTOU**: emita o diretório `d/sub/`, substitua `d/sub` por um symlink para `/tmp` e depois emita `d/sub/PWNED.txt`. Isso tem como alvo extractors que validam ou armazenam o diretório em cache uma vez e não o verificam novamente antes da escrita final.
* **Hardlink read/overwrite**: TAR e RAR podem representar hardlinks. Um hardlink para um arquivo existente no host pode expor seu conteúdo se um componente posterior servir o nome extraído; uma entry regular conflitante pode, em vez disso, sobrescrever o inode vinculado. Isso é limitado pelas regras de same-filesystem e permissões de hardlink do sistema operacional.
* **Pivot preexistente ou entre archives**: tente novamente com um destino não vazio. Um archive pode plantar um link e uma extração posterior pode escrever através dele, mesmo que cada archive passe por uma verificação stateless do nome no header.<sup>[[11]](#references)</sup>

### Colisões de Equivalência do Filesystem

Compare os nomes usando a semântica do filesystem que os receberá. Casos diferenciais úteis incluem `LINK` versus `link` em filesystems case-insensitive, grafias Unicode NFC versus NFD, nomes equivalentes por compatibilidade, como `ﬁle` versus `file`, membros duplicados que alteram um path de diretório para symlink e backslashes interpretadas como separadores somente no Windows. Teste também nomes que contêm ADS no NTFS. Esses casos podem fazer o validator enxergar dois paths enquanto o filesystem resolve um.<sup>[[5]](#references)[[11]](#references)</sup>

Um corpus compacto deve, portanto, testar combinações ordenadas de **directory → symlink → child**, **symlink → colliding regular file**, **hardlink → colliding regular file**, misturas de `/` e `\`, nomes absolutos/rooted e wrappers comprimidos, como `.tar.gz`. Execute isso somente em uma VM/container descartável e monitore tanto o destino quanto o canary path externo pretendido.<sup>[[11]](#references)</sup>

## Exemplo do Mundo Real – WinRAR ≤ 7.12 (CVE-2025-8088)

O WinRAR para Windows e seus componentes Windows RAR/UnRAR não validavam os nomes de arquivo durante a extração. A falha usava NTFS alternate data streams (ADS) para contornar o path de extração selecionado e gravar arquivos em locais não pretendidos.<sup>[[5]](#references)</sup>
Um archive RAR malicioso contendo uma entry como:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
ficaria **fora** do diretório de saída selecionado e dentro da pasta *Startup* do usuário. A ESET observou arquivos LNK maliciosos sendo descompactados nesse local e executados no logon do usuário, fornecendo persistência e um caminho para RCE.<sup>[[5]](#references)</sup>

### Criando um Archive PoC (Linux/Mac)

Como o CVE-2025-8088 usa um path de traversal em um nome de ADS, use um gerador criado especificamente para gerar o RAR e, em seguida, teste a extração somente em um lab isolado com uma build vulnerável do WinRAR.<sup>[[5]](#references)</sup>

### Exploração Observada In the Wild

A ESET relatou campanhas de spear-phishing do RomCom (Storm-0978/UNC2596) que anexavam archives RAR explorando o CVE-2025-8088 para implantar backdoors customizados e facilitar operações de ransomware.<sup>[[5]](#references)</sup>

## Casos Mais Recentes (2024–2026)

### Traversal de symlink em ZIP do 7-Zip → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: entradas ZIP que eram **symlinks** eram desreferenciadas durante a extração, permitindo que attackers escapassem do diretório de destino e sobrescrevessem paths arbitrários. A interação do usuário consiste apenas em *abrir/extrair* o archive.<sup>[[1]](#references)</sup>
* **Afetado**: builds do 7-Zip anteriores à **25.00**. A falha no processamento de symlinks foi corrigida na versão **25.00** (julho de 2025) e posteriores.<sup>[[1]](#references)[[10]](#references)</sup>
* **Caminho do impacto**: Sobrescrever `Start Menu/Programs/Startup` ou locais de execução de serviços → o código é executado no próximo logon ou reinício do serviço.
* **Fixture rápido para tratamento de symlink (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Este archive contém uma entrada de symlink apontando para fora do diretório de extração; use um destino descartável e verifique se o extractor não o segue. Um teste de write-through também precisa de uma entrada de arquivo regular abaixo do symlink.

### Colisão de symlink em `Unarchive()` do Go mholt/archiver (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` pode extrair um symlink de ZIP e depois desreferenciá-lo quando um membro regular posterior tem o mesmo nome, transformando uma escrita aparentemente dentro da raiz em uma escrita fora da raiz.<sup>[[2]](#references)</sup>
* **Afetado**: `github.com/mholt/archiver` ≤ 3.5.1 (o projeto agora está deprecated).<sup>[[2]](#references)</sup>
* **Correção**: Mude para `mholt/archives` ≥ 0.1.0 ou rejeite links e resolva novamente cada destino imediatamente antes de abri-lo.<sup>[[2]](#references)</sup>
* **Gerador mínimo de colisão** (depois chame `archiver.Unarchive("exploit.zip", "/tmp/safe")`):<sup>[[2]](#references)</sup>
```python
import zipfile

with zipfile.ZipFile("exploit.zip", "w") as z:
link = zipfile.ZipInfo("./x")
link.create_system = 3
link.external_attr = 0o120777 << 16
z.writestr(link, "../../../tmp/PWNED")
z.writestr("./x", b"owned\n")
```

### Bypass do filtro de extração de TAR do CPython (CVE-2026-11940)

Até `tarfile.extractall(filter="data")` e `filter="tar"` tiveram bypasses relacionados à ordem dos links. Nesse caso, um hardlink referenciava um symlink arquivado em um path mais profundo; a extração de fallback validava o symlink relativo nesse local profundo, mas o recriava no local mais superficial do hardlink, onde o mesmo target relativo escapava. Este é um teste geral útil: faça a validação e a materialização discordarem sobre o diretório-base ou o tipo final do membro.<sup>[[12]](#references)</sup>

## Dicas de Detecção

* **Inspeção estática** – Liste tanto os nomes dos membros quanto os targets dos links. Sinalize `../`, `..\\`, paths absolutos/enraizados, symlinks, hardlinks, arquivos especiais, nomes duplicados, alterações de tipo e colisões equivalentes por case/Unicode. Preserve a ordem das entradas durante a análise, pois o exploit pode depender de membros anteriores.<sup>[[11]](#references)</sup>
* **Canonicalização** – Garanta que o parent resolvido mais o basename final permaneçam abaixo do destino resolvido (compare componentes do path, não um prefixo de string bruto). Verifique novamente após cada membro anterior; um teste único de `realpath(join(dest, name))` é vulnerável à substituição de links e pode falhar para uma leaf ainda não criada.<sup>[[3]](#references)[[11]](#references)</sup>
* **Extração em sandbox** – Descompacte em um diretório novo e descartável usando um extractor com verificações de path/symlink (por exemplo, as verificações seguras padrão do bsdtar ou o 7-Zip ≥ 25.00) e, em seguida, verifique se a árvore resultante não contém links apontando para fora. O isolamento deve impedir que um escape já acionado alcance paths do host.<sup>[[1]](#references)[[9]](#references)</sup>
* **Leituras posteriores importam** – Um symlink ou hardlink sobrevivente pode se tornar uma primitiva de leitura arbitrária de arquivos quando um previewer, CDN, file browser ou pipeline de pacotes abrir ou servir posteriormente o nome extraído, mesmo que a extração não tenha criado nenhum arquivo externo.<sup>[[11]](#references)</sup>
* **Monitoramento de endpoints** – Gere um alerta para executáveis novos gravados em locais `Startup`/`Run`/`cron` logo após um archive ser aberto pelo WinRAR/7-Zip/etc.

## Mitigação e Hardening

1. **Atualize o extractor** – WinRAR 7.13+ e 7-Zip 25.00+ contêm correções para os problemas de path/symlink citados.<sup>[[1]](#references)[[5]](#references)</sup>
2. Extraia archives com “**Do not extract paths**” / “**Ignore paths**” quando possível. Para entradas não confiáveis, rejeite symlinks, hardlinks, devices e FIFOs, a menos que a aplicação precise explicitamente deles.<sup>[[9]](#references)[[11]](#references)</sup>
3. Extraia em um **diretório novo e vazio**. Não mescle membros não confiáveis em uma árvore que contenha paths que possam ser substituídos pelo attacker e não reutilize um diretório criado por um archive anterior.<sup>[[11]](#references)</sup>
4. No Unix, remova privilégios e isole o destino em um **chroot/mount namespace**; no Windows, use **AppContainer** ou um sandbox. Uma verificação pós-extração isolada é insuficiente, pois uma escrita fora do destino ocorre antes da verificação.<sup>[[11]](#references)</sup>
5. Em código customizado, aplique as regras de separadores, case e Unicode do sistema operacional alvo e valide tanto o membro quanto o target do link. Resolva e abra o destino sem seguir links; não separe uma verificação de contenção de uma operação posterior de criação/substituição. O validador deve usar exatamente a mesma base e a mesma semântica de emulação de links do caminho de escrita.<sup>[[11]](#references)[[12]](#references)</sup>

## Outros Casos Afetados / Históricos

* 2018 – Advisory massivo de *Zip-Slip* da Snyk afetando muitas bibliotecas Java/Go/JS.<sup>[[6]](#references)</sup>
* 2025 – `go-slug` da HashiCorp (CVE-2025-0377), traversal durante a extração de TAR em slugs (corrigido na v0.16.3).<sup>[[7]](#references)</sup>
* Qualquer lógica de extração customizada que valide strings de header, mas não os targets dos links e o path final do filesystem usado em cada escrita.<sup>[[11]](#references)[[12]](#references)</sup>



## References

- [1] [Trend Micro ZDI-25-949 – Traversal de symlink em ZIP do 7-Zip (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – Zip-Slip do mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Impedindo Zip Slip no .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – Cadeia de ZipSlip → DLL hijack do HTB Bruno](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Atualize as ferramentas do WinRAR agora: RomCom e outros explorando vulnerabilidade zero-day (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Divulgação pública de uma vulnerabilidade crítica de sobrescrita arbitrária de arquivos: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug da HashiCorp vulnerável a ataque Zip Slip (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Método Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – Flags de extração segura do bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Exploit Proof-of-Concept reportado para CVE-2025-11001 no 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – Diversão com zip-slips, tar-slips, symlinks, hardlinks, colisões e muito mais](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – Bypass do filtro de extração tarfile do CVE-2026-11940](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
{{#include ../banners/hacktricks-training.md}}
