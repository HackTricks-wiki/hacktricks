# Segurança e Escalada de Privilégios no macOS

{{#include ../../banners/hacktricks-training.md}}

## MacOS Básico

Se você não está familiarizado com o macOS, deve começar aprendendo o básico do macOS:

- **Arquivos e permissões** especiais do macOS:


{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- **Usuários** comuns do macOS


{{#ref}}
macos-users.md
{{#endref}}

- **AppleFS**


{{#ref}}
macos-applefs.md
{{#endref}}

- A **arquitetura** do k**ernel**


{{#ref}}
mac-os-architecture/
{{#endref}}

- **Serviços e protocolos de n**etwork** comuns do macOS


{{#ref}}
macos-protocols.md
{{#endref}}

- macOS **Opensource**: [https://opensource.apple.com/](https://opensource.apple.com/)
- Para baixar um `tar.gz`, altere uma URL como [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) para [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

Nas empresas, os sistemas **macOS** provavelmente serão **gerenciados com um MDM**. Portanto, da perspectiva de um atacante, é interessante saber **como isso funciona**:


{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - Inspeção, Debugging e Fuzzing


{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## Proteções de Segurança do MacOS


{{#ref}}
macos-security-protections/
{{#endref}}

## Superfície de Ataque

### Permissões de Arquivos

Se um **processo executado como root grava** um arquivo que pode ser controlado por um usuário, o usuário pode abusar disso para **escalar privilégios**.\
Isso pode ocorrer nas seguintes situações:

- O arquivo usado já foi criado por um usuário (pertence ao usuário)
- O arquivo usado pode ser gravado pelo usuário por causa de um grupo
- O arquivo usado está dentro de um diretório pertencente ao usuário (o usuário pode criar o arquivo)
- O arquivo usado está dentro de um diretório pertencente ao root, mas o usuário tem acesso de gravação sobre ele por causa de um grupo (o usuário pode criar o arquivo)

Ser capaz de **criar um arquivo** que será **usado pelo root** permite que um usuário **se aproveite do conteúdo dele** ou até mesmo crie **symlinks/hardlinks** para apontá-lo para outro local.

Para esse tipo de vulnerabilidade, não se esqueça de **verificar instaladores `.pkg` vulneráveis**:


{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### Extensão de Arquivo e Manipuladores de esquemas de URL

Aplicativos estranhos registrados por extensões de arquivo podem ser abusados, e diferentes aplicativos podem ser registrados para abrir protocolos específicos


{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## Escalada de Privilégios no macOS TCC / SIP

No macOS, **aplicativos e binários podem ter permissões** para acessar pastas ou configurações que os tornam mais privilegiados que outros.

Portanto, um atacante que deseja comprometer com sucesso uma máquina macOS precisará **escalar seus privilégios no TCC** (ou até mesmo **bypassar o SIP**, dependendo de suas necessidades).

Esses privilégios geralmente são concedidos na forma de **entitlements** com os quais o aplicativo é assinado, ou o aplicativo pode ter solicitado determinados acessos e, após a **aprovação do usuário**, eles podem ser encontrados nos **bancos de dados do TCC**. Outra forma de um processo obter esses privilégios é sendo **filho de um processo** com esses **privilégios**, pois eles geralmente são **herdados**.<sup>[[5]](#references)</sup>

Siga estes links para encontrar diferentes formas de [**escalar privilégios no TCC**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses), [**bypassar o TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/index.html) e saber como, no passado, o [**SIP foi bypassado**](macos-security-protections/macos-sip.md#sip-bypasses).

## Escalada de Privilégios Tradicional no macOS

É claro que, da perspectiva de red teams, você também deve estar interessado em escalar para root. Consulte o post a seguir para obter algumas dicas:


{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## Conformidade do macOS

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## Referências

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis (Patrick Wardle)](https://taomm.org/vol1/analysis.html)
- [3] [NicolasGrimonpont/Cheatsheet — macOS/Linux/Windows commands & security tools cheatsheet](https://github.com/NicolasGrimonpont/Cheatsheet)
- [4] [SentinelOne — macOS Security Resource](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [5] [2022 - macOS local security: escaping the sandbox and bypassing TCC (YouTube)](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
