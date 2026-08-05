# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

### Word Sandbox bypass via Launch Agents

A aplicação usa um **custom Sandbox** utilizando o entitlement **`com.apple.security.temporary-exception.sbpl`**, e esse custom sandbox permite escrever arquivos em qualquer lugar, desde que o nome do arquivo comece com `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Portanto, escapar era tão simples quanto **escrever um `plist`** LaunchAgent em `~/Library/LaunchAgents/~$escape.plist`.

Consulte o [**relatório original aqui**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Word Sandbox bypass via Login Items and zip

Lembre-se de que, desde o primeiro escape, o Word pode escrever arquivos arbitrários cujo nome começa com `~$`, embora, após o patch da vulnerabilidade anterior, não fosse possível escrever em `/Library/Application Scripts` ou em `/Library/LaunchAgents`.

Foi descoberto que, de dentro do sandbox, é possível criar um **Login Item** (apps que serão executados quando o usuário fizer login). No entanto, esses apps **não serão executados a menos que** sejam **notarizados**, e **não é possível adicionar argumentos** (portanto, você não pode simplesmente executar um reverse shell usando **`bash`**).

No bypass anterior do Sandbox, a Microsoft desabilitou a opção de escrever arquivos em `~/Library/LaunchAgents`. No entanto, foi descoberto que, se você colocar um **arquivo zip como Login Item**, o `Archive Utility` simplesmente o **descompactará** em sua localização atual. Assim, como, por padrão, a pasta `LaunchAgents` de `~/Library` não é criada, foi possível **compactar um plist em `LaunchAgents/~$escape.plist`** e **colocar** o arquivo zip em **`~/Library`**, para que, ao ser descompactado, ele chegasse ao destino de persistência.

Consulte o [**relatório original aqui**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Word Sandbox bypass via Login Items and .zshenv

(Lembre-se de que, desde o primeiro escape, o Word pode escrever arquivos arbitrários cujo nome começa com `~$`.)

No entanto, a técnica anterior tinha uma limitação: se a pasta **`~/Library/LaunchAgents`** existisse porque algum outro software a criou, ela falharia. Portanto, foi descoberta uma chain diferente de Login Items para isso.

Um attacker poderia criar os arquivos **`.bash_profile`** e **`.zshenv`** com o payload a ser executado, compactá-los e então **escrever o zip na** pasta do usuário **da vítima**: **`~/~$escape.zip`**.

Em seguida, adicionar o arquivo zip aos **Login Items** e depois o app **`Terminal`**. Quando o usuário fizesse login novamente, o arquivo zip seria descompactado na pasta do usuário, sobrescrevendo **`.bash_profile`** e **`.zshenv`** e, portanto, o terminal executaria um desses arquivos (dependendo de bash ou zsh ser utilizado).

Consulte o [**relatório original aqui**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Word Sandbox Bypass with Open and env variables

De processos sandboxed, ainda é possível invocar outros processos usando o utilitário **`open`**. Além disso, esses processos serão executados **dentro de seu próprio sandbox**.

Foi descoberto que o utilitário open possui a opção **`--env`** para executar um app com variáveis **env** específicas. Portanto, foi possível criar o arquivo **`.zshenv`** dentro de uma pasta **dentro** do **sandbox** e usar `open` com `--env`, definindo a variável **`HOME`** para essa pasta e abrindo o app `Terminal`, que executará o arquivo `.zshenv` (por algum motivo, também foi necessário definir a variável `__OSINSTALL_ENVIROMENT`).

Consulte o [**relatório original aqui**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Word Sandbox Bypass with Open and stdin

O utilitário **`open`** também suportava o parâmetro **`--stdin`** (e, após o bypass anterior, não era mais possível usar `--env`).

A questão é que, mesmo que **`python`** fosse assinado pela Apple, ele **não executaria** um script com o atributo **`quarantine`**. No entanto, era possível fornecer um script por stdin, para que ele não verificasse se estava em quarantine ou não:

1. Criar um arquivo **`~$exploit.py`** com comandos Python arbitrários.
2. Executar _open_ **`–stdin='~$exploit.py' -a Python`**, o que executa o app Python com o arquivo criado servindo como sua entrada padrão. O Python executa nosso código normalmente e, como é um processo filho do **`launchd`**, não está sujeito às regras do sandbox do Word.

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)

{{#include ../../../../../banners/hacktricks-training.md}}
