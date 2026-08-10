# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

## Visão geral

Muitos formatos de archive (ZIP, RAR, TAR, 7-ZIP, etc.) permitem que cada entrada contenha seu próprio **internal path**. Quando um utilitário de extração respeita cegamente esse caminho, um filename criado contendo `..` ou um **absolute path** (por exemplo, `C:\Windows\System32\`) será gravado fora do diretório escolhido pelo usuário.
Essa classe de vulnerabilidade é amplamente conhecida como *Zip-Slip* ou **archive extraction path traversal**.<sup>[[6]](#references)</sup>

As consequências variam desde a sobrescrita de arquivos arbitrários até alcançar diretamente **remote code execution (RCE)** ao colocar um payload em um local de **auto-run**, como a pasta *Startup* do Windows.

## Causa raiz

1. O atacante cria um archive no qual um ou mais file headers contêm:
* Sequências de traversal relativas (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ou **symlinks** criados para resolver fora do diretório de destino (comum em ZIP/TAR no *nix).
2. A vítima extrai o archive com uma ferramenta vulnerável que confia no caminho incorporado (ou segue symlinks), em vez de sanitizá-lo ou forçar a extração para dentro do diretório escolhido.
3. O arquivo é gravado no local controlado pelo atacante e executado/carregado na próxima vez que o sistema ou o usuário acionar esse caminho.

### .NET `Path.Combine` + `ZipArchive` traversal

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
- Se `entry.FullName` começar com `..\\`, ocorrerá traversal; se for um **caminho absoluto**, o componente à esquerda será completamente descartado, resultando em uma **gravação arbitrária de arquivo** como identidade da extração.
- Arquivo compactado de proof-of-concept para gravar em um diretório `app` irmão monitorado por um scanner agendado:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Ao colocar esse ZIP na caixa de entrada monitorada, o resultado é `C:\samples\app\0xdf.txt`, comprovando o traversal para fora de `C:\samples\queue\` e habilitando primitives subsequentes (por exemplo, DLL hijacks).

## Exemplo do mundo real – WinRAR ≤ 7.12 (CVE-2025-8088)

O WinRAR para Windows e seus componentes Windows RAR/UnRAR não validavam os nomes dos arquivos durante a extração. A falha usava NTFS alternate data streams (ADS) para contornar o caminho de extração selecionado e gravar arquivos em locais não pretendidos.<sup>[[5]](#references)</sup>
Um arquivo RAR malicioso contendo uma entrada como:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
would end up **fora** do diretório de saída selecionado e dentro da pasta *Startup* do usuário. A ESET observou arquivos LNK maliciosos sendo descompactados nesse local e executados no logon do usuário, fornecendo persistência e um caminho para RCE.<sup>[[5]](#references)</sup>

### Criando um Archive PoC (Linux/Mac)

Como o CVE-2025-8088 usa um caminho de traversal em um nome de ADS, use um gerador desenvolvido especificamente para criar o RAR e, em seguida, teste a extração somente em um lab isolado com uma build vulnerável do WinRAR.<sup>[[5]](#references)</sup>

### Exploração Observada in the Wild

A ESET relatou campanhas de spear-phishing do RomCom (Storm-0978/UNC2596) que anexavam archives RAR abusando do CVE-2025-8088 para implantar backdoors personalizados e facilitar operações de ransomware.<sup>[[5]](#references)</sup>

## Casos Mais Recentes (2024–2025)

### Traversal de symlink em ZIP do 7-Zip → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: Entradas ZIP que eram **symbolic links** eram desreferenciadas durante a extração, permitindo que attackers escapassem do diretório de destino e sobrescrevessem caminhos arbitrários. A interação do usuário consiste apenas em *abrir/extrair* o archive.<sup>[[1]](#references)</sup>
* **Afetados**: Builds do 7-Zip anteriores à **25.00**. A falha no processamento de symbolic links foi corrigida na **25.00** (julho de 2025) e posteriores.<sup>[[1]](#references)[[10]](#references)</sup>
* **Caminho de impacto**: Sobrescrever `Start Menu/Programs/Startup` ou locais de execução de serviços → o código é executado no próximo logon ou reinício do serviço.
* **Fixture rápido para tratamento de symlinks (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Este archive contém uma entrada symlink apontando para fora do diretório de extração; use um destino descartável e verifique se o extractor não o segue. Um teste de write-through também precisa de uma entrada regular de arquivo abaixo do symlink.

### Zip-Slip do Unarchive() do Go mholt/archiver (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` segue `../` e entradas ZIP com symlink, gravando fora de `outputDir`.<sup>[[2]](#references)</sup>
* **Afetado**: `github.com/mholt/archiver` ≤ 3.5.1 (o projeto agora está deprecated).
* **Correção**: Mude para `mholt/archives` ≥ 0.1.0 ou implemente verificações de caminho canônico antes da gravação.
* **Reprodução mínima**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Dicas de Detecção

* **Inspeção estática** – Liste as entradas do archive e sinalize qualquer nome contendo `../`, `..\\`, *caminhos absolutos* (`/`, `C:`) ou entradas do tipo *symlink* cujo destino esteja fora do diretório de extração.
* **Canonicalização** – Garanta que `realpath(join(dest, name))` permaneça dentro de `realpath(dest)` (compare os componentes do caminho, não apenas um prefixo de string bruto). Rejeite caso contrário.<sup>[[3]](#references)</sup>
* **Extração em sandbox** – Descompacte em um diretório descartável usando um extractor com verificações de caminho/symlink (por exemplo, as verificações seguras padrão do bsdtar ou o 7-Zip ≥ 25.00) e, em seguida, verifique se os caminhos resultantes permanecem dentro do diretório.<sup>[[1]](#references)[[9]](#references)</sup>
* **Monitoramento de endpoints** – Gere um alerta quando novos executáveis forem gravados em locais `Startup`/`Run`/`cron` pouco depois de um archive ser aberto pelo WinRAR/7-Zip/etc.

## Mitigação e Hardening

1. **Atualize o extractor** – WinRAR 7.13+ e 7-Zip 25.00+ contêm correções para os problemas de path/symlink citados.<sup>[[1]](#references)[[5]](#references)</sup>
2. Extraia archives com “**Do not extract paths**” / “**Ignore paths**” quando possível.
3. No Unix, reduza os privilégios e monte um **chroot/namespace** antes da extração; no Windows, use **AppContainer** ou uma sandbox.
4. Se estiver escrevendo código personalizado, normalize com `realpath()`/`PathCanonicalize()` **antes** de criar/gravar e rejeite qualquer entrada que escape do destino.

## Casos Adicionais / Históricos Afetados

* 2018 – Advisory massivo de *Zip-Slip* da Snyk afetando muitas bibliotecas Java/Go/JS.<sup>[[6]](#references)</sup>
* 2025 – `go-slug` da HashiCorp (CVE-2025-0377), traversal durante a extração de TAR em slugs (corrigido na v0.16.3).<sup>[[7]](#references)</sup>
* Qualquer lógica de extração personalizada que não chame `PathCanonicalize` / `realpath` antes da gravação.

## References

- [1] [Trend Micro ZDI-25-949 – Traversal de ZIP com symlink no 7-Zip (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [Pesquisa da JFrog – Zip-Slip do mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevenindo Zip Slip no .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – Cadeia de ZipSlip → sequestro de DLL no HTB Bruno](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Atualize as ferramentas do WinRAR agora: RomCom e outros explorando uma vulnerabilidade zero-day (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Divulgação pública de uma vulnerabilidade crítica de sobrescrita arbitrária de arquivos: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug vulnerável a ataque Zip Slip (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Método Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – Flags de extração segura do bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Exploit Proof-of-Concept reportado para CVE-2025-11001 no 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
