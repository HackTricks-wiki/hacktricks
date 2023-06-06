## Namespace de PID

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informações básicas

O namespace de PID (Process IDentifier) é um recurso no kernel do Linux que fornece isolamento de processos, permitindo que um grupo de processos tenha seu próprio conjunto de PIDs exclusivos, separados dos PIDs em outros namespaces. Isso é particularmente útil na containerização, onde o isolamento de processos é essencial para a segurança e gerenciamento de recursos.

Quando um novo namespace de PID é criado, o primeiro processo nesse namespace é atribuído ao PID 1. Esse processo se torna o processo "init" do novo namespace e é responsável por gerenciar outros processos dentro do namespace. Cada processo subsequente criado dentro do namespace terá um PID exclusivo dentro desse namespace, e esses PIDs serão independentes dos PIDs em outros namespaces.

Do ponto de vista de um processo dentro de um namespace de PID, ele só pode ver outros processos no mesmo namespace. Ele não está ciente de processos em outros namespaces e não pode interagir com eles usando ferramentas tradicionais de gerenciamento de processos (por exemplo, `kill`, `wait`, etc.). Isso fornece um nível de isolamento que ajuda a evitar que processos interfiram uns com os outros.

### Como funciona:

1. Quando um novo processo é criado (por exemplo, usando a chamada de sistema `clone()`), o processo pode ser atribuído a um namespace de PID novo ou existente. **Se um novo namespace for criado, o processo se torna o processo "init" desse namespace**.
2. O **kernel** mantém um **mapeamento entre os PIDs no novo namespace e os PIDs correspondentes** no namespace pai (ou seja, o namespace do qual o novo namespace foi criado). Esse mapeamento **permite que o kernel traduza PIDs quando necessário**, como ao enviar sinais entre processos em diferentes namespaces.
3. **Processos dentro de um namespace de PID só podem ver e interagir com outros processos no mesmo namespace**. Eles não estão cientes de processos em outros namespaces e seus PIDs são exclusivos dentro de seu namespace.
4. Quando um **namespace de PID é destruído** (por exemplo, quando o processo "init" do namespace sai), **todos os processos dentro desse namespace são encerrados**. Isso garante que todos os recursos associados ao namespace sejam limpos corretamente.

## Laboratório:

### Criar diferentes Namespaces

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Erro: bash: fork: Não é possível alocar memória</summary>

Se você executar a linha anterior sem `-f`, você receberá esse erro.\
O erro é causado pelo processo PID 1 sair no novo namespace.

Depois que o bash começa a ser executado, ele bifurca vários novos sub-processos para fazer algumas coisas. Se você executar o unshare sem -f, o bash terá o mesmo pid que o processo "unshare" atual. O processo "unshare" atual chama o sistema unshare, cria um novo namespace de pid, mas o processo "unshare" atual não está no novo namespace de pid. É o comportamento desejado do kernel do Linux: o processo A cria um novo namespace, o próprio processo A não será colocado no novo namespace, apenas os sub-processos do processo A serão colocados no novo namespace. Então, quando você executa:
```
unshare -p /bin/bash
```
O processo unshare executará /bin/bash, e /bin/bash criará vários sub-processos. O primeiro sub-processo do bash se tornará o PID 1 do novo namespace e o subprocesso sairá após concluir seu trabalho. Portanto, o PID 1 do novo namespace sairá.

O processo PID 1 tem uma função especial: ele deve se tornar o processo pai de todos os processos órfãos. Se o processo PID 1 no namespace raiz sair, o kernel entrará em pânico. Se o processo PID 1 em um sub-namespace sair, o kernel Linux chamará a função disable\_pid\_allocation, que limpará a flag PIDNS\_HASH\_ADDING nesse namespace. Quando o kernel Linux cria um novo processo, ele chama a função alloc\_pid para alocar um PID em um namespace e, se a flag PIDNS\_HASH\_ADDING não estiver definida, a função alloc\_pid retornará um erro -ENOMEM. É por isso que você recebeu o erro "Cannot allocate memory".

Você pode resolver esse problema usando a opção '-f':
```
unshare -fp /bin/bash
```
Se você executar o comando unshare com a opção '-f', o unshare irá criar um novo processo após criar o novo namespace pid. E executará /bin/bash no novo processo. O novo processo será o pid 1 do novo namespace pid. Em seguida, o bash também irá criar vários sub-processos para realizar algumas tarefas. Como o próprio bash é o pid 1 do novo namespace pid, seus sub-processos podem ser encerrados sem nenhum problema.

Copiado de [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

Ao montar uma nova instância do sistema de arquivos `/proc`, se você usar o parâmetro `--mount-proc`, você garante que o novo namespace de montagem tenha uma **visão precisa e isolada das informações de processo específicas para aquele namespace**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Verificar em qual namespace está o seu processo

Para verificar em qual namespace está o seu processo, você pode executar o seguinte comando:

```bash
ls -l /proc/$$/ns
```

Onde `$$` é o PID do seu processo. Isso mostrará uma lista de namespaces e seus identificadores de inode. O namespace PID é o namespace de ID de processo.
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Encontre todos os namespaces PID

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
{% endcode %}

Observe que o usuário root do namespace PID inicial (padrão) pode ver todos os processos, inclusive os que estão em novos namespaces PID, é por isso que podemos ver todos os namespaces PID.

### Entrando em um namespace PID
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Quando você entra em um namespace PID a partir do namespace padrão, ainda é possível ver todos os processos. E o processo desse PID ns será capaz de ver o novo bash no PID ns.

Além disso, você só pode **entrar em outro namespace PID se você for root**. E você **não pode entrar** em outro namespace **sem um descritor** apontando para ele (como `/proc/self/ns/pid`).
