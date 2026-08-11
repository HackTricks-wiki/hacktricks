# Bypasses do Sandbox do Office no macOS

{{#include ../../../../../banners/hacktricks-training.md}}

Os seguintes são **escapes históricos do sandbox do Microsoft Office para Mac**. Eles documentam erros reutilizáveis de trust boundary, mas não se deve presumir que combinações corrigidas do Office/macOS sejam vulneráveis sem reproduzir a versão e a política exatas.

### Bypass do sandbox do Word via LaunchAgents

O aplicativo afetado usava uma regra de sandbox personalizada por meio de `com.apple.security.temporary-exception.sbpl`. Ela permitia arquivos regulares cujo basename começasse com `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`.<sup>[[1]](#references)</sup>

Portanto, escapar era tão simples quanto **escrever um** `plist` **LaunchAgent** em `~/Library/LaunchAgents/~$escape.plist`.

Confira o [**relatório original aqui**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Bypass do sandbox do Word via Login Items e zip

Lembre-se de que, a partir do primeiro escape, o Word pode escrever arquivos arbitrários cujo nome comece com `~$`, embora, após o patch da vulnerabilidade anterior, não fosse possível escrever em `/Library/Application Scripts` ou em `/Library/LaunchAgents`.

O sandbox afetado permitia a criação de um **Login Item**, que é executado quando o usuário faz login. O caminho demonstrado exigia um aplicativo aceitavelmente assinado/notarizado e não permitia argumentos arbitrários; portanto, adicionar `bash` com um argumento de reverse shell era insuficiente.<sup>[[2]](#references)</sup>

A partir do bypass de Sandbox anterior, a Microsoft desabilitou a opção de escrever arquivos em `~/Library/LaunchAgents`. No entanto, descobriu-se que, se você colocar um **arquivo zip como Login Item**, o `Archive Utility` simplesmente irá **descompactá-lo** em sua localização atual. Assim, como, por padrão, a pasta `LaunchAgents` de `~/Library` não é criada, era possível **compactar um plist em `LaunchAgents/~$escape.plist`** e **colocar** o arquivo zip em **`~/Library`**; quando fosse descompactado, ele chegaria ao destino de persistência.

Confira o [**relatório original aqui**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Bypass do sandbox do Word via Login Items e .zshenv

(Lembre-se de que, a partir do primeiro escape, o Word pode escrever arquivos arbitrários cujo nome comece com `~$`.)

No entanto, a técnica anterior tinha uma limitação: se a pasta **`~/Library/LaunchAgents`** existisse porque outro software a criou, ela falharia. Por isso, uma cadeia diferente de Login Items foi descoberta.

Um atacante poderia criar **`.bash_profile`** e **`.zshenv`** contendo o payload, arquivá-los e escrever o ZIP no diretório home da **vítima** como **`~/~$escape.zip`**.

Em seguida, adicionaria o ZIP e o **Terminal** como Login Items. No próximo login, o Archive Utility extrairia os dotfiles no diretório home do usuário, e o shell do Terminal avaliaria o arquivo de inicialização aplicável (`.bash_profile` para o caminho demonstrado com Bash ou `.zshenv` para Zsh).<sup>[[3]](#references)</sup>

Confira o [**relatório original aqui**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Bypass do Sandbox do Word com Open e variáveis env

Processos em sandbox ainda podiam solicitar o lançamento de aplicativos por meio de **`open`**. O aplicativo lançado era executado em seu próprio contexto de segurança, em vez de herdar o perfil exato de sandbox do Word.<sup>[[4]](#references)</sup>

O utilitário `open` afetado tinha uma opção **`--env`** para fornecer variáveis de ambiente. O exploit criava `.zshenv` dentro do sandbox, definia `HOME` como esse diretório e lançava o Terminal para que o Zsh o avaliasse. A cadeia reportada também definia a variável privada escrita incorretamente `__OSINSTALL_ENVIROMENT`; preserve essa grafia exata ao reproduzir o PoC histórico.<sup>[[4]](#references)</sup>

Confira o [**relatório original aqui**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Bypass do Sandbox do Word com Open e stdin

O utilitário **`open`** também aceitava o parâmetro **`--stdin`** (e, após o bypass anterior, já não era possível usar `--env`).

Embora o aplicativo Python da Apple rejeitasse um arquivo de script em quarentena, o fluxo vulnerável podia fornecer o mesmo script por meio da entrada padrão, evitando a verificação de quarentena baseada em arquivo:<sup>[[5]](#references)</sup>

1. Solte um arquivo **`~$exploit.py`** contendo comandos Python arbitrários.
2. Execute `open --stdin='~$exploit.py' -a Python`. O aplicativo Python lançado recebe o código fornecido na entrada padrão e, nas versões vulneráveis, é executado fora do sandbox do Word porque o LaunchServices o cria sob o `launchd`.<sup>[[5]](#references)</sup>

## References

- [1] [Escapando do Sandbox – Microsoft Office no macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Drama do Office no macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Escape do Sandbox do Office365 no MacOS](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Análise técnica da CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)
- [5] [Revelando uma vulnerabilidade de escape do App Sandbox do macOS: uma análise detalhada da CVE-2022-26706 - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/)
{{#include ../../../../../banners/hacktricks-training.md}}
