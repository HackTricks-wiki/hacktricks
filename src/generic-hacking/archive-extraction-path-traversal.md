# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Visão geral

Muitos formatos de archive (ZIP, RAR, TAR, 7-ZIP etc.) permitem que cada entrada carregue seu próprio **internal path**. Quando um utilitário de extração segue esse caminho cegamente, um nome de arquivo criado contendo `..` ou um **absolute path** (por exemplo, `C:\Windows\System32\`) será gravado fora do diretório escolhido pelo usuário.
Essa classe de vulnerabilidade é amplamente conhecida como *Zip-Slip* ou **archive extraction path traversal**.<sup>[[6]](#references)</sup>

As consequências variam desde a sobrescrita de arquivos arbitrários até alcançar diretamente **remote code execution (RCE)** ao inserir um payload em um local de **auto-run**, como a pasta *Startup* do Windows.

## Causa raiz

1. O atacante cria um archive no qual um ou mais cabeçalhos de arquivo contêm:
* Sequências de traversal relativas (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Caminhos absolutos (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ou **symlinks** criados para resolver fora do diretório de destino (comum em ZIP/TAR no *nix*).
2. A vítima extrai o archive com uma ferramenta vulnerável que confia no caminho incorporado (ou segue symlinks), em vez de sanitizá-lo ou forçar a extração dentro do diretório escolhido.
3. O arquivo é gravado no local controlado pelo atacante e executado/carregado na próxima vez que o sistema ou o usuário acionar esse caminho.

### .NET `Path.Combine` + `ZipArchive` traversal

Um anti-pattern comum em .NET consiste em combinar o destino pretendido com o `ZipArchiveEntry.FullName` **user-controlled** e realizar a extração sem normalização de caminho:<sup>[[4]](#references)[[8]](#references)</sup>
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
- Se `entry.FullName` começar com `..\\`, ocorrerá traversal; se for um **absolute path**, o componente à esquerda será totalmente descartado, resultando em uma **escrita arbitrária de arquivo** como identidade da extração.
- Arquivo compactado de prova de conceito para escrever em um diretório `app` adjacente monitorado por um scanner agendado:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Colocar esse ZIP na inbox monitorada resulta em `C:\samples\app\0xdf.txt`, comprovando traversal para fora de `C:\samples\queue\` e habilitando primitives subsequentes (por exemplo, DLL hijacks).

## Exemplo do Mundo Real – WinRAR ≤ 7.12 (CVE-2025-8088)

O WinRAR para Windows e seus componentes Windows RAR/UnRAR não validavam os nomes de arquivos durante a extração. A falha usava NTFS alternate data streams (ADS) para ignorar o caminho de extração selecionado e gravar arquivos em locais não intencionais.<sup>[[5]](#references)</sup>
Um arquivo RAR malicioso contendo uma entrada como:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
acabaria **fora** do diretório de saída selecionado e dentro da pasta *Startup* do usuário. A ESET observou arquivos LNK maliciosos sendo extraídos nesse local e executados no logon do usuário, fornecendo persistência e um caminho para RCE.<sup>[[5]](#references)</sup>

### Criando um Archive PoC (Linux/Mac)

Como o CVE-2025-8088 usa um path de traversal em um nome de ADS, use um gerador específico para criar o RAR e, em seguida, teste a extração somente em um lab isolado com uma build vulnerável do WinRAR.<sup>[[5]](#references)</sup>

### Exploração Observada em Ambientes Reais

A ESET relatou campanhas de spear-phishing do RomCom (Storm-0978/UNC2596) que anexavam archives RAR abusando do CVE-2025-8088 para implantar backdoors personalizados e facilitar operações de ransomware.<sup>[[5]](#references)</sup>

## Casos Mais Recentes (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: Entradas ZIP que eram **symbolic links** sofriam dereference durante a extração, permitindo que atacantes escapassem do diretório de destino e sobrescrevessem paths arbitrários. A interação do usuário consiste apenas em *abrir/extrair* o archive.<sup>[[1]](#references)</sup>
* **Afetado**: Builds do 7-Zip anteriores à **25.00**. A falha no processamento de symbolic links foi corrigida na versão **25.00** (julho de 2025) e posteriores.<sup>[[1]](#references)[[10]](#references)</sup>
* **Caminho de impacto**: Sobrescrever `Start Menu/Programs/Startup` ou locais de execução de serviços → o código é executado no próximo logon ou reinício do serviço.
* **Fixture rápido para tratamento de symlinks (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Este archive contém uma entrada symlink apontando para fora do diretório de extração; use um target descartável e verifique se o extractor não o segue. Um teste de write-through também precisa de uma entrada regular-file abaixo do symlink.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` segue `../` e entradas ZIP com symlinks, gravando fora de `outputDir`.<sup>[[2]](#references)</sup>
* **Afetado**: `github.com/mholt/archiver` ≤ 3.5.1 (o projeto agora está deprecated).
* **Correção**: Mude para `mholt/archives` ≥ 0.1.0 ou implemente verificações de canonical-path antes da gravação.
* **Reprodução mínima**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Dicas de Detecção

* **Inspeção estática** – Liste as entradas do archive e sinalize qualquer nome contendo `../`, `..\\`, *absolute paths* (`/`, `C:`) ou entradas do tipo *symlink* cujo target esteja fora do diretório de extração.
* **Canonicalisation** – Garanta que `realpath(join(dest, name))` permaneça dentro de `realpath(dest)` (compare os componentes do path, não apenas um prefixo de string bruto). Rejeite caso contrário.<sup>[[3]](#references)</sup>
* **Extração em Sandbox** – Descompacte em um diretório descartável usando um extractor com verificações de path/symlink (por exemplo, as verificações seguras padrão do bsdtar ou 7-Zip ≥ 25.00) e, em seguida, verifique se os paths resultantes permanecem dentro do diretório.<sup>[[1]](#references)[[9]](#references)</sup>
* **Monitoramento de Endpoint** – Gere um alerta para executáveis novos gravados em locais `Startup`/`Run`/`cron` logo após um archive ser aberto pelo WinRAR/7-Zip/etc.

## Mitigação e Hardening

1. **Atualize o extractor** – WinRAR 7.13+ e 7-Zip 25.00+ contêm correções para os problemas de path/symlink citados.<sup>[[1]](#references)[[5]](#references)</sup>
2. Extraia archives com “**Do not extract paths**” / “**Ignore paths**” quando possível.
3. No Unix, reduza os privilégios e monte um **chroot/namespace** antes da extração; no Windows, use **AppContainer** ou uma sandbox.
4. Se estiver escrevendo código personalizado, normalize com `realpath()`/`PathCanonicalize()` **antes** de criar/gravar e rejeite qualquer entrada que escape do destino.

## Casos Adicionais Afetados / Históricos

* 2018 – Advisory massivo de *Zip-Slip* da Snyk afetando muitas libraries Java/Go/JS.<sup>[[6]](#references)</sup>
* 2025 – `go-slug` da HashiCorp (CVE-2025-0377), traversal durante a extração de TARs em slugs (corrigido na v0.16.3).<sup>[[7]](#references)</sup>
* Qualquer lógica de extração personalizada que não chame `PathCanonicalize` / `realpath` antes da gravação.

## References

- [1] [Trend Micro ZDI-25-949 – traversal de ZIP com symlink no 7-Zip (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – Zip-Slip do mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevenir Zip Slip no .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – cadeia HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Atualize as ferramentas do WinRAR agora: RomCom e outros explorando uma vulnerabilidade zero-day (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Divulgação pública de uma vulnerabilidade crítica de sobrescrita arbitrária de arquivos: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug vulnerável a um ataque Zip Slip (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Método Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – flags de extração segura do bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Exploit Proof-of-Concept reportado para CVE-2025-11001 no 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
