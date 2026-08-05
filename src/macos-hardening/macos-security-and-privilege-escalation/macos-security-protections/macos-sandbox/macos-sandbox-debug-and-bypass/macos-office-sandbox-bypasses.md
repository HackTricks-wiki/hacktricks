# Bypasses do Sandbox do macOS Office

{{#include ../../../../../banners/hacktricks-training.md}}

### Word Sandbox bypass via Launch Agents

O aplicativo usa um **Sandbox personalizado** utilizando o entitlement **`com.apple.security.temporary-exception.sbpl`**, e esse Sandbox personalizado permite escrever arquivos em qualquer lugar, desde que o nome do arquivo comece com `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Portanto, escapar era tão simples quanto **escrever um `plist`** LaunchAgent em `~/Library/LaunchAgents/~$escape.plist`.

Confira o [**original report here**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[1]</sup>

### Word Sandbox bypass via Login Items and zip

Lembre-se de que, desde o primeiro escape, o Word pode escrever arquivos arbitrários cujo nome começa com `~$`, embora, após o patch da vulnerabilidade anterior, não fosse possível escrever em `/Library/Application Scripts` ou em `/Library/LaunchAgents`.

Foi descoberto que, de dentro do Sandbox, é possível criar um **Login Item** (aplicativos que serão executados quando o usuário fizer login). No entanto, esses aplicativos **não serão executados a menos que** sejam **notarized**, e **não é possível adicionar args** (portanto, não é possível simplesmente executar um reverse shell usando **`bash`**).

Após o bypass anterior do Sandbox, a Microsoft desativou a opção de escrever arquivos em `~/Library/LaunchAgents`. Porém, foi descoberto que, se você colocar um **arquivo zip como Login Item**, o `Archive Utility` simplesmente o **descompactará** em sua localização atual. Como, por padrão, a pasta `LaunchAgents` de `~/Library` não é criada, foi possível **compactar um plist em `LaunchAgents/~$escape.plist`** e **colocar** o arquivo zip em **`~/Library`**, para que, ao ser descompactado, ele alcançasse o destino de persistência.

Confira o [**original report here**](https://objective-see.org/blog/blog_0x4B.html).<sup>[2]</sup>

### Word Sandbox bypass via Login Items and .zshenv

(Lembre-se de que, desde o primeiro escape, o Word pode escrever arquivos arbitrários cujo nome começa com `~$`.)

No entanto, a técnica anterior tinha uma limitação: se a pasta **`~/Library/LaunchAgents`** existisse porque algum outro software a criou, ela falharia. Portanto, uma cadeia diferente de Login Items foi descoberta para isso.

Um atacante poderia criar os arquivos **`.bash_profile`** e **`.zshenv`** com o payload a ser executado, compactá-los e então **escrever o zip na** pasta do usuário vítima: **`~/~$escape.zip`**.

Em seguida, adicionar o arquivo zip aos **Login Items** e depois o aplicativo **`Terminal`**. Quando o usuário fizer login novamente, o arquivo zip será descompactado na pasta do usuário, sobrescrevendo **`.bash_profile`** e **`.zshenv`** e, portanto, o terminal executará um desses arquivos (dependendo de bash ou zsh ser utilizado).

Confira o [**original report here**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[3]</sup>

### Word Sandbox Bypass with Open and env variables

Ainda é possível, a partir de processos dentro do Sandbox, invocar outros processos usando o utilitário `open`. Além disso, esses processos serão executados **dentro de seu próprio Sandbox**.

Foi descoberto que o utilitário open possui a opção **`--env`** para executar um aplicativo com variáveis **env específicas**. Portanto, foi possível criar o arquivo **`.zshenv`** dentro de uma pasta **dentro** do **Sandbox** e usar `open` com `--env`, definindo a variável **`HOME`** para essa pasta e abrindo o aplicativo `Terminal`, que executará o arquivo `.zshenv` (por algum motivo, também foi necessário definir a variável `__OSINSTALL_ENVIROMENT`).

Confira o [**original report here**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[4]</sup>

### Word Sandbox Bypass with Open and stdin

O utilitário **`open`** também suportava o parâmetro **`--stdin`** (e, após o bypass anterior, já não era possível usar `--env`).

O fato é que, mesmo que **`python`** fosse assinado pela Apple, ele **não executaria** um script com o atributo **`quarantine`**. No entanto, era possível passar um script a partir do stdin, para que ele não verificasse se estava em quarentena:

1. Solte um arquivo **`~$exploit.py`** com comandos Python arbitrários.
2. Execute _open_ **`–stdin='~$exploit.py' -a Python`**, o que executa o aplicativo Python com o arquivo fornecido servindo como sua entrada padrão. O Python executa nosso código normalmente e, como é um processo filho de _launchd_, não está sujeito às regras do Sandbox do Word.

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)

{{#include ../../../../../banners/hacktricks-training.md}}
