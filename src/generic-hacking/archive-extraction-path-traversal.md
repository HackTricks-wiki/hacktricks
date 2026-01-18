# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Visão geral

Muitos formatos de arquivo compactado (ZIP, RAR, TAR, 7-ZIP, etc.) permitem que cada entrada carregue seu próprio **internal path**. Quando uma ferramenta de extração honra cegamente esse caminho, um nome de arquivo manipulado contendo `..` ou um **absolute path** (ex.: `C:\Windows\System32\`) será escrito fora do diretório escolhido pelo usuário.
Essa classe de vulnerabilidade é amplamente conhecida como *Zip-Slip* ou **archive extraction path traversal**.

As consequências variam desde sobrescrever arquivos arbitrários até atingir diretamente **remote code execution (RCE)** ao deixar um payload em um local de **auto-run**, como a pasta *Startup* do Windows.

## Causa raiz

1. O atacante cria um arquivo onde um ou mais cabeçalhos de arquivo contêm:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Or crafted **symlinks** that resolve outside the target dir (common in ZIP/TAR on *nix*).
2. A vítima extrai o arquivo com uma ferramenta vulnerável que confia no caminho embutido (ou segue symlinks) em vez de sanitizá-lo ou forçar a extração dentro do diretório escolhido.
3. O arquivo é escrito no local controlado pelo atacante e é executado/carregado na próxima vez que o sistema ou o usuário acionar esse caminho.

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows (including the `rar` / `unrar` CLI, the DLL and the portable source) failed to validate filenames during extraction.
Um RAR malicioso contendo uma entrada como:
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
* `-ep`  – armazenar caminhos de arquivos exatamente como fornecidos (**não** remover o prefixo `./`).

Entregue `evil.rar` à vítima e instrua-a a extrair com uma versão vulnerável do WinRAR.

### Exploração observada no mundo real

A ESET relatou campanhas de spear-phishing do RomCom (Storm-0978/UNC2596) que anexavam arquivos RAR abusando de CVE-2025-8088 para implantar backdoors personalizados e facilitar operações de ransomware.

## Casos mais recentes (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: Entradas ZIP que são **symlinks** eram desreferenciadas durante a extração, permitindo que atacantes escapassem do diretório de destino e sobrescrevessem caminhos arbitrários. A interação do usuário é apenas *abrir/extrair* o arquivo.
* **Afetados**: 7-Zip 21.02–24.09 (Windows & Linux builds). Corrigido em **25.00** (July 2025) e posteriores.
* **Impact path**: Sobrescrever `Start Menu/Programs/Startup` ou service-run locations → o código é executado no próximo logon ou reinício do serviço.
* **PoC rápido (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Em um build corrigido `/etc/cron.d` não será tocado; o symlink é extraído como um link dentro de /tmp/target.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` segue `../` e entradas ZIP symlinked, escrevendo fora de `outputDir`.
* **Afetado**: `github.com/mholt/archiver` ≤ 3.5.1 (projeto agora obsoleto).
* **Fix**: Switch to `mholt/archives` ≥ 0.1.0 or implement canonical-path checks before write.
* **Reprodução mínima**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Dicas de Detecção

* **Inspeção estática** – Liste entradas do arquivo e sinalize qualquer nome contendo `../`, `..\\`, *caminhos absolutos* (`/`, `C:`) ou entradas do tipo *symlink* cujo alvo esteja fora do diretório de extração.
* **Canonização** – Garanta que `realpath(join(dest, name))` ainda comece com `dest`. Rejeite caso contrário.
* **Extração em sandbox** – Descompacte em um diretório descartável usando um extrator *safe* (e.g., `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) e verifique se os caminhos resultantes permanecem dentro do diretório.
* **Monitoramento de endpoint** – Alerta para novos executáveis escritos em `Startup`/`Run`/`cron` logo após um arquivo ser aberto pelo WinRAR/7-Zip/etc.

## Mitigação e Endurecimento

1. **Atualize o extractor** – WinRAR 7.13+ e 7-Zip 25.00+ implementam sanitização de caminhos/symlinks. Ambas as ferramentas ainda não possuem atualização automática.
2. Extraia arquivos com “**Do not extract paths**” / “**Ignore paths**” quando possível.
3. No Unix, reduza privilégios e monte um **chroot/namespace** antes da extração; no Windows, use **AppContainer** ou uma sandbox.
4. Se escrever código personalizado, normalize com `realpath()`/`PathCanonicalize()` **antes** de criar/escrever, e rejeite qualquer entrada que escape do destino.

## Casos adicionais afetados / históricos

* 2018 – Alerta massivo sobre *Zip-Slip* pela Snyk afetando muitas bibliotecas Java/Go/JS.
* 2023 – 7-Zip CVE-2023-4011 travessia similar durante `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) travessia na extração de TAR em slugs (patch em v1.2).
* Qualquer lógica de extração customizada que falhe ao chamar `PathCanonicalize` / `realpath` antes de escrever.

## Referências

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)

{{#include ../banners/hacktricks-training.md}}
