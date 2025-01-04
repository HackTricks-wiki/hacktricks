# Segurança e Escalação de Privilégios no macOS

{{#include ../../banners/hacktricks-training.md}}

## MacOS Básico

Se você não está familiarizado com o macOS, deve começar aprendendo o básico do macOS:

- **Arquivos e permissões especiais do macOS:**

{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- **Usuários comuns do macOS**

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

- **Serviços e protocolos de rede comuns do macOS**

{{#ref}}
macos-protocols.md
{{#endref}}

- **Open source** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
- Para baixar um `tar.gz`, mude uma URL como [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) para [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MDM do MacOS

Em empresas, sistemas **macOS** provavelmente serão **gerenciados com um MDM**. Portanto, do ponto de vista de um atacante, é interessante saber **como isso funciona**:

{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - Inspecionando, Depurando e Fuzzing

{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## Proteções de Segurança do MacOS

{{#ref}}
macos-security-protections/
{{#endref}}

## Superfície de Ataque

### Permissões de Arquivo

Se um **processo executado como root escreve** um arquivo que pode ser controlado por um usuário, o usuário pode abusar disso para **escalar privilégios**.\
Isso pode ocorrer nas seguintes situações:

- O arquivo usado já foi criado por um usuário (pertencente ao usuário)
- O arquivo usado é gravável pelo usuário devido a um grupo
- O arquivo usado está dentro de um diretório pertencente ao usuário (o usuário poderia criar o arquivo)
- O arquivo usado está dentro de um diretório pertencente ao root, mas o usuário tem acesso de gravação sobre ele devido a um grupo (o usuário poderia criar o arquivo)

Ser capaz de **criar um arquivo** que será **usado pelo root** permite que um usuário **tire proveito de seu conteúdo** ou até mesmo crie **symlinks/hardlinks** para apontá-lo para outro lugar.

Para esse tipo de vulnerabilidades, não se esqueça de **verificar instaladores `.pkg` vulneráveis**:

{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### Manipuladores de Aplicativos de Extensão de Arquivo e Esquema de URL

Aplicativos estranhos registrados por extensões de arquivo podem ser abusados e diferentes aplicativos podem ser registrados para abrir protocolos específicos

{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## Escalação de Privilégios TCC / SIP do macOS

No macOS, **aplicativos e binários podem ter permissões** para acessar pastas ou configurações que os tornam mais privilegiados do que outros.

Portanto, um atacante que deseja comprometer com sucesso uma máquina macOS precisará **escalar seus privilégios TCC** (ou até mesmo **burlar o SIP**, dependendo de suas necessidades).

Esses privilégios geralmente são concedidos na forma de **direitos** com os quais o aplicativo é assinado, ou o aplicativo pode solicitar alguns acessos e, após o **usuário aprová-los**, eles podem ser encontrados nos **bancos de dados TCC**. Outra maneira de um processo obter esses privilégios é sendo um **filho de um processo** com esses **privilégios**, pois eles geralmente são **herdados**.

Siga esses links para encontrar diferentes maneiras de [**escalar privilégios no TCC**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses), para [**burlar o TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) e como no passado [**o SIP foi burlado**](macos-security-protections/macos-sip.md#sip-bypasses).

## Escalação Tradicional de Privilégios no macOS

Claro, do ponto de vista de uma equipe vermelha, você também deve estar interessado em escalar para root. Confira o seguinte post para algumas dicas:

{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## Conformidade do macOS

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## Referências

- [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
- [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
