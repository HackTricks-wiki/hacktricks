# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

### Bypass do Sandbox do Word via Launch Agents

O aplicativo usa um **Sandbox personalizado** usando a permissão **`com.apple.security.temporary-exception.sbpl`** e esse sandbox personalizado permite escrever arquivos em qualquer lugar, desde que o nome do arquivo comece com `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Portanto, escapar foi tão fácil quanto **escrever um `plist`** LaunchAgent em `~/Library/LaunchAgents/~$escape.plist`.

Verifique o [**relatório original aqui**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Bypass do Sandbox do Word via Itens de Login e zip

Lembre-se de que, a partir da primeira fuga, o Word pode escrever arquivos arbitrários cujo nome comece com `~$`, embora após o patch da vulnerabilidade anterior não fosse mais possível escrever em `/Library/Application Scripts` ou em `/Library/LaunchAgents`.

Foi descoberto que, de dentro do sandbox, é possível criar um **Item de Login** (aplicativos que serão executados quando o usuário fizer login). No entanto, esses aplicativos **não serão executados a menos que** sejam **notarizados** e **não é possível adicionar args** (então você não pode apenas executar um shell reverso usando **`bash`**).

A partir do bypass anterior do Sandbox, a Microsoft desativou a opção de escrever arquivos em `~/Library/LaunchAgents`. No entanto, foi descoberto que, se você colocar um **arquivo zip como um Item de Login**, o `Archive Utility` simplesmente **descompactará** no local atual. Assim, como por padrão a pasta `LaunchAgents` de `~/Library` não é criada, foi possível **zipar um plist em `LaunchAgents/~$escape.plist`** e **colocar** o arquivo zip em **`~/Library`**, para que, ao descompactá-lo, ele chegasse ao destino de persistência.

Verifique o [**relatório original aqui**](https://objective-see.org/blog/blog_0x4B.html).

### Bypass do Sandbox do Word via Itens de Login e .zshenv

(Lembre-se de que, a partir da primeira fuga, o Word pode escrever arquivos arbitrários cujo nome comece com `~$`).

No entanto, a técnica anterior tinha uma limitação, se a pasta **`~/Library/LaunchAgents`** existir porque algum outro software a criou, falharia. Portanto, uma cadeia diferente de Itens de Login foi descoberta para isso.

Um atacante poderia criar os arquivos **`.bash_profile`** e **`.zshenv`** com o payload a ser executado e, em seguida, zipá-los e **escrever o zip na** pasta do usuário da vítima: **`~/~$escape.zip`**.

Em seguida, adicione o arquivo zip aos **Itens de Login** e depois ao aplicativo **`Terminal`**. Quando o usuário fizer login novamente, o arquivo zip seria descompactado na pasta do usuário, sobrescrevendo **`.bash_profile`** e **`.zshenv`** e, portanto, o terminal executará um desses arquivos (dependendo se bash ou zsh for usado).

Verifique o [**relatório original aqui**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Bypass do Sandbox do Word com Open e variáveis de ambiente

A partir de processos em sandbox, ainda é possível invocar outros processos usando a utilidade **`open`**. Além disso, esses processos serão executados **dentro de seu próprio sandbox**.

Foi descoberto que a utilidade open tem a opção **`--env`** para executar um aplicativo com **variáveis de ambiente específicas**. Portanto, foi possível criar o **arquivo `.zshenv`** dentro de uma pasta **dentro** do **sandbox** e usar `open` com `--env` definindo a **variável `HOME`** para essa pasta, abrindo o aplicativo `Terminal`, que executará o arquivo `.zshenv` (por algum motivo, também foi necessário definir a variável `__OSINSTALL_ENVIROMENT`).

Verifique o [**relatório original aqui**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Bypass do Sandbox do Word com Open e stdin

A utilidade **`open`** também suportava o parâmetro **`--stdin`** (e após o bypass anterior, não era mais possível usar `--env`).

A questão é que, mesmo que **`python`** tenha sido assinado pela Apple, ele **não executará** um script com o atributo **`quarantine`**. No entanto, foi possível passar um script do stdin, então ele não verificaria se estava em quarentena ou não:

1. Crie um arquivo **`~$exploit.py`** com comandos Python arbitrários.
2. Execute _open_ **`–stdin='~$exploit.py' -a Python`**, que executa o aplicativo Python com nosso arquivo criado servindo como sua entrada padrão. O Python executa nosso código, e como é um processo filho do _launchd_, não está vinculado às regras do sandbox do Word.

{{#include ../../../../../banners/hacktricks-training.md}}
