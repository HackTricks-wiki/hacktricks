# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Visão Geral

Muitos formatos de arquivo (ZIP, RAR, TAR, 7-ZIP, etc.) permitem que cada entrada carregue seu próprio **caminho interno**. Quando uma ferramenta de extração aceita cegamente esse caminho, um nome de arquivo elaborado contendo `..` ou um **caminho absoluto** (por exemplo, `C:\Windows\System32\`) será escrito fora do diretório escolhido pelo usuário. Essa classe de vulnerabilidade é amplamente conhecida como *Zip-Slip* ou **traversal de caminho de extração de arquivo**.

As consequências variam desde a sobrescrição de arquivos arbitrários até a obtenção direta de **execução remota de código (RCE)** ao deixar um payload em um local de **execução automática**, como a pasta *Inicialização* do Windows.

## Causa Raiz

1. O atacante cria um arquivo onde um ou mais cabeçalhos de arquivo contêm:
* Sequências de travessia relativa (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Caminhos absolutos (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
2. A vítima extrai o arquivo com uma ferramenta vulnerável que confia no caminho incorporado em vez de sanitizá-lo ou forçar a extração abaixo do diretório escolhido.
3. O arquivo é escrito na localização controlada pelo atacante e executado/carregado na próxima vez que o sistema ou o usuário acionar esse caminho.

## Exemplo do Mundo Real – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR para Windows (incluindo o CLI `rar` / `unrar`, a DLL e a fonte portátil) falhou em validar nomes de arquivos durante a extração. Um arquivo RAR malicioso contendo uma entrada como:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
acabaria **fora** do diretório de saída selecionado e dentro da *pasta de Inicialização* do usuário. Após o logon, o Windows executa automaticamente tudo o que está presente lá, proporcionando RCE *persistente*.

### Criando um PoC Archive (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Opções usadas:
* `-ep`  – armazena caminhos de arquivos exatamente como dados (não **prune** `./` inicial).

Entregue `evil.rar` à vítima e instrua-a a extraí-lo com uma versão vulnerável do WinRAR.

### Exploração Observada no Mundo Real

A ESET relatou campanhas de spear-phishing RomCom (Storm-0978/UNC2596) que anexaram arquivos RAR abusando do CVE-2025-8088 para implantar backdoors personalizados e facilitar operações de ransomware.

## Dicas de Detecção

* **Inspeção estática** – Liste as entradas do arquivo e sinalize qualquer nome contendo `../`, `..\\`, *caminhos absolutos* (`C:`) ou codificações UTF-8/UTF-16 não canônicas.
* **Extração em sandbox** – Descompacte em um diretório descartável usando um extrator *seguro* (por exemplo, `patool` do Python, 7-Zip ≥ última versão, `bsdtar`) e verifique se os caminhos resultantes permanecem dentro do diretório.
* **Monitoramento de endpoint** – Alerta sobre novos executáveis gravados em locais de `Startup`/`Run` logo após um arquivo ser aberto pelo WinRAR/7-Zip/etc.

## Mitigação e Fortalecimento

1. **Atualize o extrator** – O WinRAR 7.13 implementa a sanitização adequada de caminhos. Os usuários devem baixá-lo manualmente porque o WinRAR não possui um mecanismo de atualização automática.
2. Extraia arquivos com a opção **“Ignorar caminhos”** (WinRAR: *Extrair → "Não extrair caminhos"*) quando possível.
3. Abra arquivos não confiáveis **dentro de uma sandbox** ou VM.
4. Implemente a lista de permissões de aplicativos e restrinja o acesso de gravação do usuário a diretórios de execução automática.

## Casos Adicionais Afetados / Históricos

* 2018 – Aviso massivo de *Zip-Slip* pela Snyk afetando muitas bibliotecas Java/Go/JS.
* 2023 – CVE-2023-4011 do 7-Zip com travessia semelhante durante a mesclagem `-ao`.
* Qualquer lógica de extração personalizada que não chama `PathCanonicalize` / `realpath` antes da gravação.

## Referências

- [BleepingComputer – WinRAR zero-day explorado para plantar malware na extração de arquivos](https://www.bleepingcomputer.com/news/security/winrar-zero-day-flaw-exploited-by-romcom-hackers-in-phishing-attacks/)
- [WinRAR 7.13 Changelog](https://www.win-rar.com/singlenewsview.html?&L=0&tx_ttnews%5Btt_news%5D=283&cHash=a64b4a8f662d3639dec8d65f47bc93c5)
- [Snyk – Análise da vulnerabilidade Zip Slip](https://snyk.io/research/zip-slip-vulnerability)

{{#include ../banners/hacktricks-training.md}}
