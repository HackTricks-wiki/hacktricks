# Path Traversal na Extração de Archives ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Visão geral

Muitos formatos de archive (ZIP, RAR, TAR, 7-ZIP etc.) permitem que cada entrada contenha seu próprio **caminho interno**. Quando um utilitário de extração respeita esse caminho cegamente, um nome de arquivo criado contendo `..` ou um **caminho absoluto** (por exemplo, `C:\Windows\System32\`) será gravado fora do diretório escolhido pelo usuário.
Essa classe de vulnerabilidade é amplamente conhecida como *Zip-Slip* ou **path traversal na extração de archives**.<sup>[[6]](#references)</sup>

As consequências variam desde a sobrescrita de arquivos arbitrários até a obtenção direta de **remote code execution (RCE)** ao inserir um payload em um local de **execução automática**, como a pasta *Startup* do Windows.

## Causa raiz

1. O atacante cria um archive no qual um ou mais headers de arquivo contêm:
* Sequências de traversal relativas (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Caminhos absolutos (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ou **symlinks** criados para resolver fora do diretório-alvo (comum em ZIP/TAR em sistemas *nix).
2. A vítima extrai o archive com uma ferramenta vulnerável que confia no caminho incorporado (ou segue symlinks), em vez de sanitizá-lo ou forçar a extração dentro do diretório escolhido.
3. O arquivo é gravado no local controlado pelo atacante e executado/carregado na próxima vez que o sistema ou o usuário acionar esse caminho.

### Traversal com `.NET` `Path.Combine` + `ZipArchive`

Um anti-pattern comum em .NET consiste em combinar o destino pretendido com o `ZipArchiveEntry.FullName` **controlado pelo usuário** e realizar a extração sem normalização do caminho:<sup>[[4]](#references)[[8]](#references)</sup>
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
- Se `entry.FullName` começa com `..\\`, ele faz traversal; se for um **caminho absoluto**, o componente à esquerda é descartado completamente, resultando em uma **escrita arbitrária de arquivo** como identidade da extração.
- Archive de prova de conceito para escrever em um diretório `app` irmão monitorado por um scanner agendado:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Ao inserir esse ZIP na caixa de entrada monitorada, o resultado é `C:\samples\app\0xdf.txt`, comprovando traversal para fora de `C:\samples\queue\` e habilitando primitives subsequentes (por exemplo, DLL hijacks).

## Primitives avançadas de escape de arquivos compactados

Trate a extração como uma sequência de mutações no filesystem, não como verificações independentes de nomes de arquivos. Uma entrada que é segura quando analisada pode se tornar insegura depois que um membro anterior cria ou substitui um link; o mesmo problema aparece quando um extractor armazena em cache um diretório como seguro e depois altera o tipo dele.<sup>[[11]](#references)</sup>

### Pivôs de links e colisões de entradas

* **Symlink write-through**: crie `pivot -> /tmp` e depois extraia um membro regular como `pivot/PWNED.txt`. Se o extractor seguir o primeiro membro ao materializar o segundo, a escrita escapará sem `..` no segundo nome.
* **Colisão de cache de diretório/TOCTOU**: emita o diretório `d/sub/`, substitua `d/sub` por um symlink para `/tmp` e depois emita `d/sub/PWNED.txt`. Isso tem como alvo extractors que validam ou armazenam o diretório em cache uma vez e não o verificam novamente antes da escrita final.
* **Leitura/sobrescrita por hardlink**: TAR e RAR podem representar hardlinks. Um hardlink para um arquivo existente no host pode expor seu conteúdo se um componente posterior servir o nome extraído; uma entrada regular em colisão pode, em vez disso, sobrescrever o inode vinculado. Isso é limitado pelas regras de mesmo filesystem e pelas permissões de hardlink do sistema operacional.
* **Pivô preexistente ou entre arquivos compactados**: tente novamente com um destino não vazio. Um arquivo compactado pode plantar um link, e uma extração posterior pode escrever através dele, mesmo que cada arquivo passe por uma verificação stateless do nome no cabeçalho.<sup>[[11]](#references)</sup>

### Colisões de equivalência do filesystem

Compare os nomes usando a semântica do filesystem que os receberá. Casos diferenciais úteis incluem `LINK` versus `link` em filesystems que não diferenciam maiúsculas de minúsculas, grafias Unicode NFC versus NFD, nomes equivalentes por compatibilidade, como `ﬁle` versus `file`, membros duplicados que alteram um caminho de diretório para symlink, e barras invertidas interpretadas como separadores somente no Windows. Teste também nomes que contenham ADS no NTFS. Esses casos podem fazer o validador identificar dois caminhos enquanto o filesystem resolve apenas um.<sup>[[5]](#references)[[11]](#references)</sup>

Um corpus compacto deve, portanto, testar combinações ordenadas de **directory → symlink → child**, **symlink → colliding regular file**, **hardlink → colliding regular file**, misturas de `/` e `\`, nomes absolutos/relativos à raiz e wrappers compactados, como `.tar.gz`. Execute isso somente em uma VM/container descartável e monitore tanto o destino quanto o caminho canary externo pretendido.<sup>[[11]](#references)</sup>

A ambiguidade estrutural específica do ZIP pode fazer com que um pre-scan e o extractor real observem nomes de entradas ou árvores diferentes. Consulte [Local-header vs central-directory parser confusion](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md#local-header-vs-central-directory-parser-confusion) em vez de confiar na saída de apenas uma biblioteca ZIP.

## Exemplo no mundo real – WinRAR ≤ 7.12 (CVE-2025-8088)

O WinRAR para Windows e seus componentes Windows RAR/UnRAR não validavam os nomes dos arquivos durante a extração. A falha usava NTFS alternate data streams (ADS) para ignorar o caminho de extração selecionado e gravar arquivos em locais não pretendidos.<sup>[[5]](#references)</sup>
Um arquivo RAR malicioso contendo uma entrada como:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
acabaria **fora** do diretório de saída selecionado e dentro da pasta *Startup* do usuário. A ESET observou arquivos LNK maliciosos sendo descompactados nesse local e executados no logon do usuário, fornecendo persistência e um caminho para RCE.<sup>[[5]](#references)</sup>

### Criando um Archive PoC (Linux/Mac)

Como o CVE-2025-8088 usa um caminho de traversal em um nome de ADS, use um gerador desenvolvido especificamente para criar o RAR e teste a extração somente em um laboratório isolado com uma build vulnerável do WinRAR.<sup>[[5]](#references)</sup>

### Exploração Observada In the Wild

A ESET relatou campanhas de spear-phishing do RomCom (Storm-0978/UNC2596) que anexavam archives RAR explorando o CVE-2025-8088 para implantar backdoors personalizados e facilitar operações de ransomware.<sup>[[5]](#references)</sup>

## Casos Mais Recentes (2024–2026)

### Traversal de symlink em ZIP do 7-Zip → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: entradas ZIP que eram **symbolic links** eram desreferenciadas durante a extração, permitindo que atacantes escapassem do diretório de destino e sobrescrevessem caminhos arbitrários. A interação do usuário consiste apenas em *abrir/extrair* o archive.<sup>[[1]](#references)</sup>
* **Afetado**: builds do 7-Zip anteriores à **25.00**. A falha no processamento de symbolic links foi corrigida na versão **25.00** (julho de 2025) e posteriores.<sup>[[1]](#references)[[10]](#references)</sup>
* **Caminho de impacto**: Sobrescrever `Start Menu/Programs/Startup` ou locais executados por serviços → o código é executado no próximo logon ou reinício do serviço.
* **Fixture rápida para tratamento de symlinks (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Este archive contém uma entrada symlink apontando para fora do diretório de extração; use um destino descartável e verifique se o extractor não o segue. Um teste de write-through também precisa de uma entrada regular de arquivo abaixo do symlink.

### Colisão de symlink em `Unarchive()` do Go mholt/archiver (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` pode extrair um symlink ZIP e depois desreferenciá-lo quando um membro regular posterior tem o mesmo nome, transformando uma escrita aparentemente dentro da raiz em uma escrita fora da raiz.<sup>[[2]](#references)</sup>
* **Afetado**: `github.com/mholt/archiver` ≤ 3.5.1 (o projeto agora está deprecated).<sup>[[2]](#references)</sup>
* **Correção**: Mude para `mholt/archives` ≥ 0.1.0 ou rejeite links e reavalie cada destino imediatamente antes de abri-lo.<sup>[[2]](#references)</sup>
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

### Bypass da extração filtrada de TAR do CPython (CVE-2026-11940)

Até mesmo `tarfile.extractall(filter="data")` e `filter="tar"` tiveram bypasses relacionados à ordem dos links. Neste caso, um hardlink referenciava um symlink arquivado em um caminho mais profundo; a extração de fallback validava o symlink relativo nesse local profundo, mas o recriava no local mais superficial do hardlink, onde o mesmo target relativo escapava. Este é um teste geral útil: faça com que a validação e a materialização discordem sobre o diretório-base ou o tipo final do membro.<sup>[[12]](#references)</sup>

### Escape do target de hardlink do Node `tar` por meio de uma cadeia de symlinks (GHSA-83g3-92jg-28cx)

O package `tar` do Node.js aceitava um hardlink cujo target parecia estar contido lexicalmente, mas era resolvido para fora da raiz de extração por meio de dois symlinks anteriores. O ataque funciona com as opções padrão de extração: as verificações do parent do destino cobriam o nome do hardlink dentro da raiz, enquanto o target do hardlink era passado ao filesystem sem resolver a cadeia completa para verificar a contenção. `tar` ≤ 7.5.7 é afetado; a versão 7.5.8 corrige o problema.<sup>[[13]](#references)</sup>

A fixture de teste importante é a **relação ordenada** entre os membros, não estes nomes literais:<sup>[[13]](#references)</sup>
```text
a/b/c/up     -> ../..                          (symlink)
a/b/escape   -> c/up/../..                     (symlink)
exfil        => a/b/escape/<path-from-parent>  (hardlink)
```
Se a extração for bem-sucedida, `exfil` permanece visível dentro da árvore de saída, mas compartilha um inode com o arquivo externo escolhido; lê-lo faz o leak desse arquivo, e escrevê-lo modifica o original. Esse bypass demonstra por que verificar apenas o pathname final, remover prefixos absolutos ou bloquear `..` no header do hardlink é insuficiente: valide os alvos dos links depois de aplicar todo o estado do filesystem extraído anteriormente.<sup>[[13]](#references)</sup>

## Detection Tips

* **Inspeção estática** – Liste tanto os nomes dos membros quanto os alvos dos links. Sinalize `../`, `..\\`, caminhos absolutos/raiz, symlinks, hardlinks, arquivos especiais, nomes duplicados, mudanças de tipo e colisões equivalentes de maiúsculas/minúsculas ou Unicode. Preserve a ordem das entradas durante a revisão, pois o exploit pode depender de membros anteriores.<sup>[[11]](#references)</sup>

```bash
bsdtar -tvf suspect.tar       # membros TAR ordenados, tipos e alvos dos links
7z l -slt suspect.7z          # metadados técnicos, um campo por linha
zipinfo -v suspect.zip        # metadados e offsets do diretório central do ZIP
```

* **Canonicalização** – Garanta que o parent resolvido mais o basename final permaneça abaixo do destino resolvido (compare componentes do caminho, não um prefixo de string bruto). Verifique novamente após cada membro anterior; um teste único de `realpath(join(dest, name))` é vulnerável à substituição de links e pode falhar para uma leaf ainda não criada.<sup>[[3]](#references)[[11]](#references)</sup>
* **Extração em sandbox** – Descompacte em um diretório novo e descartável usando um extractor com verificações de caminhos/symlinks (por exemplo, as verificações seguras padrão do bsdtar ou o 7-Zip ≥ 25.00) e, em seguida, verifique se a árvore resultante não contém links para fora. O isolamento deve impedir que um escape já acionado alcance caminhos do host.<sup>[[1]](#references)[[9]](#references)</sup>
* **Leituras posteriores importam** – Um symlink ou hardlink sobrevivente pode se tornar uma primitive de arbitrary-file-read quando um previewer, CDN, file browser ou pipeline de pacotes abrir ou servir posteriormente o nome extraído, mesmo que a extração em si não tenha criado nenhum arquivo externo.<sup>[[11]](#references)</sup>
* **Monitoramento de endpoints** – Gere um alerta para novos executáveis gravados em locais `Startup`/`Run`/`cron` pouco depois de um arquivo ser aberto pelo WinRAR/7-Zip/etc.

## Mitigation & Hardening

1. **Atualize o extractor** – WinRAR 7.13+, 7-Zip 25.00+ e Node `tar` 7.5.8+ contêm correções para os problemas de path/symlink/link-target citados.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>
2. Extraia arquivos com “**Do not extract paths**” / “**Ignore paths**” quando possível. Para entradas não confiáveis, rejeite symbolic links, hardlinks, devices e FIFOs, a menos que a aplicação precise explicitamente deles.<sup>[[9]](#references)[[11]](#references)</sup>
3. Extraia em um **diretório novo e vazio**. Não faça merge de membros não confiáveis em uma árvore que contenha caminhos substituíveis pelo attacker e não reutilize um diretório criado por um arquivo anterior.<sup>[[11]](#references)</sup>
4. No Unix, remova privilégios e isole o destino em um **chroot/mount namespace**; no Windows, use **AppContainer** ou um sandbox. Uma verificação pós-extração isolada é insuficiente, pois uma gravação escapada ocorre antes da verificação.<sup>[[11]](#references)</sup>
5. Em código customizado, aplique as regras de separadores, maiúsculas/minúsculas e Unicode do sistema operacional de destino e valide tanto o membro quanto o alvo do link. Resolva e abra o destino sem seguir links; não separe uma verificação de contenção de uma operação posterior de criação/substituição. O validator deve usar exatamente a mesma base e as mesmas semânticas de emulação de links do write path.<sup>[[11]](#references)[[12]](#references)</sup>

## Additional Affected / Historical Cases

* 2018 – Advisory massivo de *Zip-Slip* da Snyk afetando muitas libraries Java/Go/JS.<sup>[[6]](#references)</sup>
* 2025 – `go-slug` da HashiCorp (CVE-2025-0377), traversal de extração TAR em slugs (corrigido na v0.16.3).<sup>[[7]](#references)</sup>
* Qualquer lógica de extração customizada que valide strings do header, mas não os alvos dos links nem o caminho final do filesystem usado em cada gravação.<sup>[[11]](#references)[[12]](#references)</sup>





## References

- [1] [Trend Micro ZDI-25-949 – traversal de symlink em ZIP no 7-Zip (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [Pesquisa da JFrog – Zip-Slip do mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevenindo Zip Slip no .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – cadeia de ZipSlip → DLL hijack no HTB Bruno](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Pesquisa da ESET – Atualize as ferramentas do WinRAR agora: RomCom e outros explorando vulnerabilidade zero-day (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Divulgação pública de uma vulnerabilidade crítica de sobrescrita arbitrária de arquivos: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug vulnerável a ataque Zip Slip (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Método Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – flags de extração segura do bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – exploit Proof-of-Concept reportado para CVE-2025-11001 no 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – Diversão com hacking usando zip-slips, tar-slips, symlinks, hardlinks, colisões e mais](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – bypass do filtro de extração tarfile para CVE-2026-11940](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
- [13] [GitHub Security Advisory – escape do alvo de hardlink do node-tar por meio de cadeia de symlinks](https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx)
{{#include ../banners/hacktricks-training.md}}
