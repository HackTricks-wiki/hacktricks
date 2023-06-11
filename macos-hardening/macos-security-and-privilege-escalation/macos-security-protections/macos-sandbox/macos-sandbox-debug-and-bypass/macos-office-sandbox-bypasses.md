# Bypasses do Sandbox do Office no macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### Bypass do Sandbox do Word via Launch Agents

A aplicação usa um **Sandbox personalizado** usando a permissão **`com.apple.security.temporary-exception.sbpl`** e esse Sandbox personalizado permite escrever arquivos em qualquer lugar, desde que o nome do arquivo comece com `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Portanto, escapar foi tão fácil quanto **escrever um arquivo `plist`** LaunchAgent em `~/Library/LaunchAgents/~$escape.plist`.

Confira o [**relatório original aqui**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Bypass do Sandbox do Word via Login Items e zip

(Lembre-se de que, a partir da primeira fuga, o Word pode gravar arquivos arbitrários cujo nome começa com `~$`).

Foi descoberto que, de dentro do Sandbox, é possível criar um **Login Item** (aplicativos que serão executados quando o usuário fizer login). No entanto, esses aplicativos **não serão executados a menos que** eles sejam **notarizados** e não é possível adicionar argumentos (portanto, você não pode simplesmente executar um shell reverso usando **`bash`**).

A partir da fuga anterior do Sandbox, a Microsoft desativou a opção de gravar arquivos em `~/Library/LaunchAgents`. No entanto, foi descoberto que, se você colocar um **arquivo zip como um Login Item**, o `Archive Utility` simplesmente o **descompactará** em sua localização atual. Portanto, como por padrão a pasta `LaunchAgents` de `~/Library` não é criada, foi possível **compactar um plist em `LaunchAgents/~$escape.plist`** e **colocar** o arquivo zip em **`~/Library`** para que, ao descompactá-lo, ele alcance o destino de persistência.

Confira o [**relatório original aqui**](https://objective-see.org/blog/blog\_0x4B.html).

### Bypass do Sandbox do Word via Login Items e .zshenv

(Lembre-se de que, a partir da primeira fuga, o Word pode gravar arquivos arbitrários cujo nome começa com `~$`).

No entanto, a técnica anterior tinha uma limitação: se a pasta **`~/Library/LaunchAgents`** existir porque algum outro software a criou, ela falhará. Então, uma cadeia diferente de Login Items foi descoberta para isso.

Um atacante poderia criar os arquivos **`.bash_profile`** e **`.zshenv`** com a carga útil para executar e, em seguida, compactá-los e **gravar o arquivo zip na pasta do usuário** da vítima: \~/\~$escape.zip.

Em seguida, adicione o arquivo zip aos **Login Items** e, em seguida, o aplicativo **`Terminal`**. Quando o usuário fizer login novamente, o arquivo zip será descompactado nos arquivos do usuário, sobrescrevendo **`.bash_profile`** e **`.zshenv`** e, portanto, o terminal executará um desses arquivos (dependendo se o bash ou o zsh são usados).

Confira o [**relatório original aqui**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Bypass do Sandbox do Word com Open e variáveis env

De processos em Sandbox, ainda é possível invocar outros processos usando o utilitário **`open`**. Além disso, esses processos serão executados **dentro de seu próprio Sandbox**.

Foi descoberto que o utilitário open tem a opção **`--env`** para executar um aplicativo com **variáveis env específicas**. Portanto, foi possível criar o arquivo **`.zshenv`** dentro de uma pasta **dentro** do **Sandbox** e usar `open` com `--env` definindo a variável **`HOME`** para essa pasta, abrindo o aplicativo `Terminal`, que executará o arquivo `.zshenv` (por algum motivo, também foi necessário definir a variável `__OSINSTALL_ENVIROMENT`).

Confira o [**relatório original aqui**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Bypass do Sandbox do Word com Open e stdin

O utilitário **`open`** também suportava o parâmetro **`--stdin`** (e após a fuga anterior, não era mais possível usar `--env`).

A questão é que mesmo que o **`python`** tenha sido assinado pela Apple, ele **não executará** um script com o atributo **`quarantine`**. No entanto, foi possível passar um script para ele a partir do stdin, para que ele não verificasse se estava em quarentena ou não:&#x20;

1. Solte um arquivo **`~$exploit.py`** com comandos Python arbitrários.
2. Execute _open_ **`–stdin='~$exploit.py' -a Python`**, que executa o aplicativo Python com nosso arquivo descartado servindo como sua entrada padrão. O Python executa nosso código com prazer e, como é um processo filho do _launchd_, não está vinculado às regras do Sandbox do Word.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️
