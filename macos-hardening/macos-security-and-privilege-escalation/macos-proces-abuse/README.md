# Abuso de Processos no macOS

O macOS, como qualquer outro sistema operacional, fornece uma variedade de métodos e mecanismos para que os processos interajam, comuniquem-se e compartilhem dados. Embora essas técnicas sejam essenciais para o funcionamento eficiente do sistema, elas também podem ser abusadas por atores mal-intencionados para realizar atividades maliciosas.

### Injeção de Biblioteca

A Injeção de Biblioteca é uma técnica em que um atacante força um processo a carregar uma biblioteca maliciosa. Uma vez injetada, a biblioteca é executada no contexto do processo alvo, fornecendo ao atacante as mesmas permissões e acesso do processo.

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### Hooking de Função

O Hooking de Função envolve a interceptação de chamadas de função ou mensagens dentro de um código de software. Ao enganchar funções, um atacante pode modificar o comportamento de um processo, observar dados sensíveis ou até mesmo obter controle sobre o fluxo de execução.

{% content-ref url="../mac-os-architecture/macos-function-hooking.md" %}
[macos-function-hooking.md](../mac-os-architecture/macos-function-hooking.md)
{% endcontent-ref %}

### Comunicação Interprocesso

A Comunicação Interprocesso (IPC) refere-se a diferentes métodos pelos quais processos separados compartilham e trocam dados. Embora a IPC seja fundamental para muitas aplicações legítimas, ela também pode ser mal utilizada para subverter o isolamento de processos, vazar informações sensíveis ou realizar ações não autorizadas.

{% content-ref url="../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Injeção de Aplicativos Electron

Os aplicativos Electron executados com variáveis de ambiente específicas podem ser vulneráveis à injeção de processos:

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### Injeção de Aplicativos .Net

É possível injetar código em aplicativos .Net abusando da funcionalidade de depuração do .Net (não protegida pelas proteções do macOS, como o endurecimento em tempo de execução).

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

## Detecção

### Shield

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) é um aplicativo de código aberto que pode detectar e bloquear ações de injeção de processos:

* Usando **Variáveis de Ambiente**: ele monitorará a presença de qualquer uma das seguintes variáveis de ambiente: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** e **`ELECTRON_RUN_AS_NODE`**
* Usando chamadas **`task_for_pid`**: para encontrar quando um processo deseja obter a porta de tarefa de outro, o que permite injetar código no processo.
* **Parâmetros de aplicativos Electron**: Alguém pode usar os argumentos de linha de comando **`--inspect`**, **`--inspect-brk`** e **`--remote-debugging-port`** para iniciar um aplicativo Electron no modo de depuração e, assim, injetar código nele.
* Usando **links simbólicos** ou **hardlinks**: Tipicamente, o abuso mais comum é colocar um link com nossos privilégios de usuário e apontá-lo para um local de privilégio mais alto. A detecção é muito simples para ambos os hardlinks e symlinks. Se o processo que cria o link tiver um **nível de privilégio diferente** do arquivo de destino, criamos um **alerta**. Infelizmente, no caso de symlinks, o bloqueio não é possível, pois não temos informações sobre o destino do link antes da criação. Esta é uma limitação do framework EndpointSecuriy da Apple.

### Chamadas feitas por outros processos

Neste [**post de blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html), você pode descobrir como é possível usar a função **`task_name_for_pid`** para obter informações sobre outros processos injetando código em um processo e, em seguida, obter informações sobre esse outro processo.

Observe que, para chamar essa função, você precisa ser **o mesmo uid** que o processo em execução ou **root** (e ela retorna informações sobre o processo, não uma maneira de injetar código).
## Referências

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
