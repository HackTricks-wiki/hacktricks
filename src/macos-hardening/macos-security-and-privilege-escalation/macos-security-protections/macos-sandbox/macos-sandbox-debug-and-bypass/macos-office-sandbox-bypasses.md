# Bypasses do Sandbox do Office no macOS

{{#include ../../../../../banners/hacktricks-training.md}}

### Bypass do Sandbox do Word via Launch Agents

O aplicativo usa um **Sandbox personalizado** com o entitlement **`com.apple.security.temporary-exception.sbpl`**, e esse Sandbox personalizado permite escrever arquivos em qualquer lugar, desde que o nome do arquivo comece com `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Portanto, escapar era tão simples quanto **escrever um `plist`** LaunchAgent em `~/Library/LaunchAgents/~$escape.plist`.

Confira o [**relatório original aqui**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Bypass do Sandbox do Word via Login Items e zip

Lembre-se de que, desde o primeiro escape, o Word pode escrever arquivos arbitrários cujo nome comece com `~$`, embora, após o patch da vulnerabilidade anterior, não fosse possível escrever em `/Library/Application Scripts` ou em `/Library/LaunchAgents`.

Foi descoberto que, de dentro do Sandbox, é possível criar um **Login Item** (aplicativos que serão executados quando o usuário fizer login). No entanto, esses aplicativos **não serão executados a menos que** sejam **notarizados**, e **não é possível adicionar argumentos** (portanto, não é possível simplesmente executar um reverse shell usando **`bash`**).

No bypass anterior do Sandbox, a Microsoft desabilitou a opção de escrever arquivos em `~/Library/LaunchAgents`. Porém, foi descoberto que, se você colocar um **arquivo zip como Login Item**, o `Archive Utility` simplesmente o **descompactará** em sua localização atual. Portanto, como, por padrão, a pasta `LaunchAgents` de `~/Library` não é criada, era possível **compactar um plist em `LaunchAgents/~$escape.plist`** e **colocar** o arquivo zip em **`~/Library`**, para que, ao ser descompactado, ele alcançasse o destino de persistence.

Confira o [**relatório original aqui**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Bypass do Sandbox do Word via Login Items e .zshenv

(Lembre-se de que, desde o primeiro escape, o Word pode escrever arquivos arbitrários cujo nome comece com `~$`.)

No entanto, a técnica anterior tinha uma limitação: se a pasta **`~/Library/LaunchAgents`** existisse porque algum outro software a tivesse criado, ela falharia. Por isso, foi descoberta uma chain diferente de Login Items.

Um atacante poderia criar os arquivos **`.bash_profile`** e **`.zshenv`** com o payload a ser executado e, em seguida, compactá-los e **escrever o zip na** pasta do usuário vítima: **`~/~$escape.zip`**.

Depois, deveria adicionar o arquivo zip aos **Login Items** e, em seguida, o aplicativo **`Terminal`**. Quando o usuário fizesse login novamente, o arquivo zip seria descompactado na pasta do usuário, sobrescrevendo **`.bash_profile`** e **`.zshenv`**; portanto, o terminal executaria um desses arquivos (dependendo de bash ou zsh ser usado).

Confira o [**relatório original aqui**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Bypass do Sandbox do Word com Open e variáveis env

A partir de processos em Sandbox, ainda é possível invocar outros processos usando o utilitário **`open`**. Além disso, esses processos serão executados **dentro de seu próprio Sandbox**.

Foi descoberto que o utilitário open possui a opção **`--env`** para executar um aplicativo com variáveis **env específicas**. Portanto, era possível criar o arquivo **`.zshenv`** dentro de uma pasta **dentro do** **Sandbox** e usar `open` com **`--env`**, definindo a variável **`HOME`** para essa pasta e abrindo o aplicativo `Terminal`, que executaria o arquivo `.zshenv` (por algum motivo, também era necessário definir a variável `__OSINSTALL_ENVIROMENT`).

Confira o [**relatório original aqui**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Bypass do Sandbox do Word com Open e stdin

O utilitário **`open`** também suportava o parâmetro **`--stdin`** (e, após o bypass anterior, não era mais possível usar `--env`).

O fato é que, embora **`python`** fosse assinado pela Apple, ele **não executaria** um script com o atributo **`quarantine`**. No entanto, era possível passar um script a ele por stdin, evitando que verificasse se estava em quarantine ou não:

1. Solte um arquivo **`~$exploit.py`** com comandos Python arbitrários.
2. Execute _open_ **`–stdin='~$exploit.py' -a Python`**, o que executa o aplicativo Python com o arquivo criado servindo como sua entrada padrão. O Python executa nosso código normalmente e, como é um processo filho do _launchd_, não está sujeito às regras do Sandbox do Word.<sup>[[5]](#references)</sup>

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)
- [5] [Uncovering a macOS App Sandbox escape vulnerability: A deep dive into CVE-2022-26706 - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/)

{{#include ../../../../../banners/hacktricks-training.md}}
