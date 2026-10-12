# Travessia de caminho na extração de arquivos ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Visão geral

Muitos formatos de arquivo (ZIP, RAR, TAR, 7-ZIP etc.) permitem que cada entrada tenha seu próprio **caminho interno**. Quando um utilitário de extração respeita cegamente esse caminho, um nome de arquivo criado com `..` ou um **caminho absoluto** (por exemplo, `C:\Windows\System32\`) será gravado fora do diretório escolhido pelo usuário.  
Essa classe de vulnerabilidade é amplamente conhecida como *Zip-Slip* ou **travessia de caminho na extração de arquivos**.<sup>[[6]](#references)</sup>

As consequências variam desde a sobrescrita de arquivos arbitrários até a obtenção direta de **execução remota de código (RCE)**, colocando um payload em um local de **execução automática**, como a pasta *Startup* do Windows.

## Causa raiz

1. O atacante cria um arquivo compactado em que um ou mais cabeçalhos de arquivo contêm:
   * Sequências de travessia relativa (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
   * Caminhos absolutos (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
   * Ou **symlinks** criados para resolver para fora do diretório de destino (comum em ZIP/TAR no *nix*). 
2. A vítima extrai o arquivo compactado com uma ferramenta vulnerável que confia no caminho incorporado (ou segue symlinks), em vez de sanitizá-lo ou forçar a extração dentro do diretório escolhido.
3. O arquivo é gravado em um local controlado pelo atacante e executado/carregado na próxima vez que o sistema ou o usuário acionar esse caminho.

### Travessia com `Path.Combine` + `ZipArchive` no .NET

Um anti-pattern comum no .NET é combinar o destino pretendido com `ZipArchiveEntry.FullName` **controlado pelo usuário** e extrair sem normalizar o caminho:<sup>[[4]](#references)[[8]](#references)</sup>

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

- Se `entry.FullName` começa com `..\\`, ele percorre diretórios; se for um **caminho absoluto**, o componente à esquerda é descartado por completo, resultando em uma **gravação arbitrária de arquivo** como identidade da extração.
- Arquivo de prova de conceito para gravar em um diretório `app` adjacente, monitorado por um scanner agendado:

```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
    z.writestr("../app/0xdf.txt", "ABCD")
```

Colocar esse ZIP na caixa de entrada monitorada resulta em `C:\samples\app\0xdf.txt`, comprovando traversal para fora de `C:\samples\queue\` e possibilitando primitivas subsequentes (por exemplo, DLL hijacks).

### Raiz de extração controlada pelo usuário

Teste também o **diretório passado ao extrator**, não apenas os nomes dos membros do arquivo. Um aplicativo pode derivar esse diretório de um título, nome de projeto ou outro campo da solicitação. Um valor como `../../../../app/module` pode mover a raiz de extração para fora da área de upload antes que o extrator processe qualquer membro. Nesse caso, até mesmo um arquivo contendo apenas o nome de arquivo seguro `api.py` pode sobrescrever código da aplicação.<sup>[[14]](#references)[[15]](#references)</sup>

```python
# Vulnerable pattern: the ZIP entries themselves need no ../ components.
extract_root = os.path.join(site_root, "public", "files", user_title)
archive.extractall(extract_root)
```

Este é um limite de contenção separado do Zip-Slip clássico. Valide tanto a raiz de extração resolvida quanto cada caminho de membro resolvido. Uma verificação da raiz pode usar componentes do caminho em vez de um prefixo de string:<sup>[[14]](#references)</sup>

```python
base = Path(site_root, "public", "files").resolve()
dest = (base / user_title).resolve()
if not dest.is_relative_to(base):
    raise ValueError("extraction root escapes its base")
```

Para um teste seguro, envie um arquivo compactado válido contendo um arquivo canário e coloque sequências de traversal em cada campo que possa selecionar o diretório de extração. Monitore tanto o diretório pretendido quanto um caminho externo descartável. Se o destino puder alcançar um módulo importado, sobrescrevê-lo pode levar à execução de código quando os workers forem recarregados; um HTTP 500 ou uma conexão reiniciada durante esse recarregamento não prova que a gravação falhou.<sup>[[14]](#references)[[15]](#references)</sup> Veja também a [metodologia de upload de arquivos](../pentesting-web/file-upload/).

## Primitivas avançadas para escapar de arquivos compactados

Trate a extração como uma sequência de mutações no sistema de arquivos, não como verificações independentes de nomes de arquivos. Uma entrada considerada segura durante a análise pode se tornar insegura depois que um membro anterior cria ou substitui um link; o mesmo problema ocorre quando um extrator armazena em cache um diretório como seguro e depois altera seu tipo.<sup>[[11]](#references)</sup>

### Pivôs de links e colisões de entradas

* **Gravação por meio de symlink**: crie `pivot -> /tmp` e depois extraia um membro comum como `pivot/PWNED.txt`. Se o extrator seguir o primeiro membro ao materializar o segundo, a gravação escapará do diretório sem que o segundo nome contenha `..`.
* **Colisão de cache de diretório/TOCTOU**: emita o diretório `d/sub/`, substitua `d/sub` por um symlink para `/tmp` e depois emita `d/sub/PWNED.txt`. Isso tem como alvo extratores que validam ou armazenam o diretório em cache uma vez e não o verificam novamente antes da gravação final.
* **Leitura/sobrescrita por hardlink**: TAR e RAR podem representar hardlinks. Um hardlink para um arquivo existente no host pode expor seu conteúdo se um componente posterior servir o nome extraído; uma entrada comum que colida com ele pode, em vez disso, sobrescrever o inode vinculado. Isso é limitado pelas regras de sistema de arquivos e permissões de hardlink do sistema operacional.
* **Pivô preexistente ou entre arquivos compactados**: tente novamente com um destino não vazio. Um arquivo compactado pode instalar um link, e uma extração posterior pode gravar por meio dele, mesmo que cada arquivo compactado passe por uma verificação stateless do nome no cabeçalho.<sup>[[11]](#references)</sup>

### Colisões por equivalência do sistema de arquivos

Compare os nomes de acordo com a semântica do sistema de arquivos que os receberá. Casos diferenciais úteis incluem `LINK` versus `link` em sistemas de arquivos que não diferenciam maiúsculas de minúsculas, grafias Unicode NFC versus NFD, nomes equivalentes por compatibilidade, como `ﬁle` versus `file`, membros duplicados que alteram um caminho de diretório para symlink e barras invertidas interpretadas como separadores somente no Windows. Teste também nomes com ADS no NTFS. Esses casos podem fazer o validador identificar dois caminhos enquanto o sistema de arquivos resolve apenas um.<sup>[[5]](#references)[[11]](#references)</sup>

Portanto, um corpus compacto deve testar combinações ordenadas de **diretório → symlink → filho**, **symlink → arquivo comum em colisão**, **hardlink → arquivo comum em colisão**, `/` e `\` misturados, nomes absolutos/com raiz e wrappers compactados, como `.tar.gz`. Execute os testes somente em uma VM/container descartável e monitore tanto o destino quanto o caminho externo canário pretendido.<sup>[[11]](#references)</sup>

Uma ambiguidade estrutural específica de ZIP pode fazer uma pré-análise e o extrator real observarem nomes de entradas ou árvores diferentes. Consulte [Confusão entre o parser do cabeçalho local e o do diretório central](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md#local-header-vs-central-directory-parser-confusion), em vez de confiar na saída de apenas uma biblioteca ZIP.

## Exemplo do mundo real – WinRAR ≤ 7.12 (CVE-2025-8088)

O WinRAR para Windows e seus componentes Windows RAR/UnRAR não validavam os nomes dos arquivos durante a extração. A falha usava alternate data streams (ADS) do NTFS para contornar o caminho de extração selecionado e gravar arquivos em locais não pretendidos.<sup>[[5]](#references)</sup>
Um arquivo RAR malicioso contendo uma entrada como:

```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```

acabaria **fora** do diretório de saída selecionado e dentro da pasta *Startup* do usuário. A ESET observou arquivos LNK maliciosos sendo descompactados nesse local e executados no logon do usuário, garantindo persistência e um caminho para RCE.<sup>[[5]](#references)</sup>

### Criando um arquivo PoC (Linux/Mac)

Como o CVE-2025-8088 usa um caminho de traversal em um nome ADS, use um gerador específico para criar o RAR e teste a extração apenas em um laboratório isolado com uma versão vulnerável do WinRAR.<sup>[[5]](#references)</sup>

### Exploração observada em ambiente real

A ESET relatou campanhas de spear-phishing do RomCom (Storm-0978/UNC2596) que anexavam arquivos RAR explorando o CVE-2025-8088 para implantar backdoors personalizados e facilitar operações de ransomware.<sup>[[5]](#references)</sup>

## Casos mais recentes (2024–2026)

### Traversal por symlink em ZIP do 7-Zip → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: entradas ZIP que eram **links simbólicos** eram desreferenciadas durante a extração, permitindo que atacantes escapassem do diretório de destino e sobrescrevessem caminhos arbitrários. A interação do usuário se limita a *abrir/extrair* o arquivo.<sup>[[1]](#references)</sup>
* **Afetado**: versões do 7-Zip anteriores à **25.00**. A falha no processamento de links simbólicos foi corrigida na versão **25.00** (julho de 2025) e nas posteriores.<sup>[[1]](#references)[[10]](#references)</sup>
* **Caminho de impacto**: sobrescrever `Start Menu/Programs/Startup` ou locais de execução de serviços → o código é executado no próximo logon ou reinício do serviço.
* **Exemplo básico de tratamento de symlink (Linux)**:
  ```bash
  mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
  ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
  cd /tmp/archive-slip-test
  zip -y exploit.zip evil   # -y preserves symlinks
  7z x exploit.zip -o/tmp/archive-slip-target
  ```
  Este archive contém uma entrada de symlink que aponta para fora do diretório de extração; use um destino descartável e verifique se o extractor não o segue. Um teste de escrita através do symlink também precisa de uma entrada de arquivo regular abaixo dele.

### Colisão de symlink em `Unarchive()` do Go mholt/archiver (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` pode extrair um symlink de ZIP e depois desreferenciá-lo quando um membro regular posterior tem o mesmo nome, transformando uma gravação aparentemente dentro do diretório em uma gravação fora dele.<sup>[[2]](#references)</sup>
* **Afetado**: `github.com/mholt/archiver` ≤ 3.5.1 (o projeto agora está obsoleto).<sup>[[2]](#references)</sup>
* **Correção**: Migre para `mholt/archives` ≥ 0.1.0 ou rejeite links e resolva novamente cada destino imediatamente antes de abri-lo.<sup>[[2]](#references)</sup>
* **Gerador mínimo de colisão** (depois, chame `archiver.Unarchive("exploit.zip", "/tmp/safe")`):<sup>[[2]](#references)</sup>
  ```python
  import zipfile

  with zipfile.ZipFile("exploit.zip", "w") as z:
      link = zipfile.ZipInfo("./x")
      link.create_system = 3
      link.external_attr = 0o120777 << 16
      z.writestr(link, "../../../tmp/PWNED")
      z.writestr("./x", b"owned\n")
  ```

### Bypass de extração filtrada de TAR no CPython (CVE-2026-11940)

Até mesmo `tarfile.extractall(filter="data")` e `filter="tar"` tiveram bypasses envolvendo a ordem dos links. Neste caso, um hardlink apontava para um symlink arquivado em um caminho mais profundo; a extração de fallback validava o symlink relativo nesse local mais profundo, mas o recriava no local mais superficial do hardlink, onde o mesmo destino relativo escapava. Este é um teste geral útil: faça com que a validação e a materialização discordem sobre o diretório base ou o tipo final do membro.<sup>[[12]](#references)</sup>

### Escape do destino de hardlink no `tar` do Node por meio de uma cadeia de symlinks (GHSA-83g3-92jg-28cx)

O pacote `tar` do Node.js aceitava em `tar.extract()` um hardlink cujo destino parecia estar lexicalmente contido, mas que resolvia para fora da raiz de extração por meio de dois symlinks anteriores. O ataque funciona com as opções de extração padrão: as verificações do diretório pai do destino cobriam o nome do hardlink dentro da raiz, enquanto o destino do hardlink era passado ao sistema de arquivos sem resolver a cadeia completa para verificar se permanecia contido. `tar` ≤ 7.5.7 é afetado; a versão 7.5.8 corrige o problema.<sup>[[13]](#references)</sup>

O elemento importante do fixture de teste é a **relação ordenada** entre os membros, não estes nomes literais:<sup>[[13]](#references)</sup>

```text
a/b/c/up     -> ../..                          (symlink)
a/b/escape   -> c/up/../..                     (symlink)
exfil        => a/b/escape/<path-from-parent>  (hardlink)
```

Se a extração for bem-sucedida, `exfil` permanece visivelmente dentro da árvore de saída, mas compartilha um inode com o arquivo externo escolhido; lê-lo causa leak desse arquivo, e gravá-lo modifica o original. Esse bypass ilustra por que verificar apenas o caminho final, remover prefixos absolutos ou bloquear `..` no cabeçalho do hardlink não é suficiente: valide os alvos dos links depois de aplicar todo o estado do sistema de arquivos extraído anteriormente.<sup>[[13]](#references)</sup>

## Dicas de detecção

* **Inspeção estática** – Liste os nomes dos membros e os alvos dos links. Sinalize `../`, `..\\`, caminhos absolutos/enraizados, symlinks, hardlinks, arquivos especiais, nomes duplicados, alterações de tipo e colisões equivalentes por maiúsculas/minúsculas ou Unicode. Preserve a ordem das entradas durante a análise, pois o exploit pode depender de membros anteriores.<sup>[[11]](#references)</sup>

  ```bash
  bsdtar -tvf suspect.tar       # ordered TAR members, types and link targets
  7z l -slt suspect.7z          # technical metadata, one field per line
  zipinfo -v suspect.zip        # ZIP central-directory metadata and offsets
  ```

* **Canonicalização** – Garanta que o diretório pai resolvido mais o nome base final permaneçam dentro do destino resolvido (compare os componentes do caminho, não um prefixo de string bruto). Verifique novamente após cada membro anterior; um teste único de `realpath(join(dest, name))` é vulnerável à substituição de links e pode falhar quando a folha ainda não foi criada.<sup>[[3]](#references)[[11]](#references)</sup>
* **Extração em sandbox** – Descomprima em um diretório novo e descartável usando um extrator com verificações de caminho/symlink (por exemplo, as verificações seguras padrão do bsdtar ou 7-Zip ≥ 25.00) e, em seguida, verifique se a árvore resultante não contém links para fora. O isolamento precisa impedir que uma fuga já acionada alcance caminhos do host.<sup>[[1]](#references)[[9]](#references)</sup>
* **Leituras posteriores também importam** – Um symlink ou hardlink que permaneça pode se tornar um primitivo de leitura arbitrária de arquivos quando um visualizador de prévias, CDN, navegador de arquivos ou pipeline de pacotes abrir ou servir posteriormente o nome extraído, mesmo que a extração em si não tenha criado nenhum arquivo fora do destino.<sup>[[11]](#references)</sup>
* **Monitoramento de endpoints** – Gere alertas para novos executáveis gravados em locais `Startup`/`Run`/`cron` pouco depois de um arquivo ser aberto pelo WinRAR/7-Zip/etc.

## Mitigação e reforço da segurança

1. **Atualize o extrator** – WinRAR 7.13+, 7-Zip 25.00+ e Node `tar` 7.5.8+ incluem correções para os problemas de caminho/symlink/destino de link citados.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>
2. Quando possível, extraia arquivos usando “**Do not extract paths**” / “**Ignore paths**”. Para entradas não confiáveis, rejeite symbolic links, hardlinks, dispositivos e FIFOs, a menos que a aplicação precise deles explicitamente.<sup>[[9]](#references)[[11]](#references)</sup>
3. Extraia em um **diretório novo e vazio**. Não mescle membros não confiáveis em uma árvore que contenha caminhos que o atacante possa substituir, nem reutilize um diretório criado por um arquivo anterior.<sup>[[11]](#references)</sup>
4. No Unix, reduza privilégios e isole o destino em um **chroot/namespace de montagem**; no Windows, use **AppContainer** ou um sandbox. Uma verificação após a extração, por si só, é insuficiente, pois uma gravação fora do destino ocorre antes da verificação.<sup>[[11]](#references)</sup>
5. Em código personalizado, aplique as regras de separadores, maiúsculas/minúsculas e Unicode do sistema operacional de destino e valide tanto o membro quanto o destino do link. Resolva e abra o destino sem seguir links; não separe uma verificação de contenção de uma operação posterior de criação/substituição. O validador deve usar exatamente a mesma base e a mesma semântica de emulação de links que o caminho de gravação.<sup>[[11]](#references)[[12]](#references)</sup>

## Outros casos afetados / históricos

* 2018 – Aviso em larga escala sobre *Zip-Slip*, da Snyk, afetando muitas bibliotecas Java/Go/JS.<sup>[[6]](#references)</sup>
* 2025 – `go-slug` da HashiCorp (CVE-2025-0377): traversal durante a extração de TAR em slugs (corrigido na v0.16.3).<sup>[[7]](#references)</sup>
* Qualquer lógica de extração personalizada que valide strings de cabeçalho, mas não os destinos de links e o caminho final do sistema de arquivos usado em cada gravação.<sup>[[11]](#references)[[12]](#references)</sup>





## References

- [1] [Trend Micro ZDI-25-949 – traversal de ZIP com symlink no 7-Zip (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [Pesquisa da JFrog – Zip-Slip no mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Como evitar Zip Slip no .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – cadeia HTB Bruno ZipSlip → sequestro de DLL](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Pesquisa da ESET – Atualize as ferramentas WinRAR agora: RomCom e outros exploram vulnerabilidade zero-day (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Divulgação pública de uma vulnerabilidade crítica de sobrescrita arbitrária de arquivos: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug vulnerável a ataque Zip Slip (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Método Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – sinalizadores de extração segura do bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Exploit de prova de conceito relatado para CVE-2025-11001 no 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – Diversão com zip-slips, tar-slips, symlinks, hardlinks, colisões e muito mais](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – desvio do filtro de extração tarfile CVE-2026-11940](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
- [13] [Aviso de segurança do GitHub – escape do destino de hardlink no node-tar por meio de cadeia de symlinks](https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx)
- [14] [PoC de CVE da Rhino Security Labs – raiz de extração SCORM controlada pelo usuário](https://raw.githubusercontent.com/RhinoSecurityLabs/CVEs/master/CVE-2026-39405/README.md)
- [15] [Rhino Security Labs – Múltiplas vulnerabilidades no Frappe LMS levam à execução remota de código](https://rhinosecuritylabs.com/research/multiple-vulnerabilities-in-frappe-lms-leading-to-remote-code-execution/)
{{#include ../banners/hacktricks-training.md}}
