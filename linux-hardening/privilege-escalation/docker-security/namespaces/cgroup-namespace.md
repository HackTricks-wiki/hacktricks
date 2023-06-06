# Namespace de CGroup

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informações básicas

Um namespace de cgroup é um recurso do kernel Linux que fornece **isolamento de hierarquias de cgroup para processos em execução dentro de um namespace**. Cgroups, abreviação de **control groups**, são um recurso do kernel que permite organizar processos em grupos hierárquicos para gerenciar e impor **limites em recursos do sistema** como CPU, memória e I/O.

Embora os namespaces de cgroup não sejam um tipo de namespace separado como os outros que discutimos anteriormente (PID, mount, network, etc.), eles estão relacionados ao conceito de isolamento de namespace. **Os namespaces de cgroup virtualizam a visão da hierarquia de cgroup**, de modo que os processos em execução dentro de um namespace de cgroup têm uma visão diferente da hierarquia em comparação com os processos em execução no host ou em outros namespaces.

### Como funciona:

1. Quando um novo namespace de cgroup é criado, **ele começa com uma visão da hierarquia de cgroup com base no cgroup do processo criador**. Isso significa que os processos em execução no novo namespace de cgroup verão apenas um subconjunto da hierarquia de cgroup inteira, limitado à subárvore de cgroup enraizada no cgroup do processo criador.
2. Os processos dentro de um namespace de cgroup **verão seu próprio cgroup como a raiz da hierarquia**. Isso significa que, do ponto de vista dos processos dentro do namespace, seu próprio cgroup aparece como a raiz e eles não podem ver ou acessar cgroups fora de sua própria subárvore.
3. Os namespaces de cgroup não fornecem isolamento direto de recursos; **eles fornecem apenas isolamento da visão da hierarquia de cgroup**. **O controle e isolamento de recursos ainda são aplicados pelos subsistemas de cgroup** (por exemplo, cpu, memória, etc.) em si.

Para obter mais informações sobre CGroups, consulte:

{% content-ref url="../cgroups.md" %}
[cgroups.md](../cgroups.md)
{% endcontent-ref %}

## Laboratório:

### Criar diferentes Namespaces

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
Ao montar uma nova instância do sistema de arquivos `/proc` usando o parâmetro `--mount-proc`, você garante que o novo namespace de montagem tenha uma **visão precisa e isolada das informações de processo específicas daquele namespace**.

<details>

<summary>Erro: bash: fork: Não é possível alocar memória</summary>

Se você executar a linha anterior sem `-f`, você receberá esse erro.\
O erro é causado pelo processo PID 1 sair no novo namespace.

Depois que o bash começa a ser executado, ele bifurca vários novos sub-processos para fazer algumas coisas. Se você executar o unshare sem -f, o bash terá o mesmo pid que o processo "unshare" atual. O processo "unshare" atual chama o sistema de chamada unshare, cria um novo namespace de pid, mas o processo "unshare" atual não está no novo namespace de pid. É o comportamento desejado do kernel do Linux: o processo A cria um novo namespace, o próprio processo A não será colocado no novo namespace, apenas os sub-processos do processo A serão colocados no novo namespace. Então, quando você executa:
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

Traduzido de [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Verifique em qual namespace está o seu processo

Para verificar em qual namespace está o seu processo, você pode executar o seguinte comando:

```bash
ls -l /proc/$$/ns/
```

Onde `$$` é o PID do seu processo.
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### Encontre todos os namespaces CGroup

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Entrando em um namespace CGroup
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
Também, você só pode **entrar em outro namespace de processo se você for root**. E você **não pode** **entrar** em outro namespace **sem um descritor** apontando para ele (como `/proc/self/ns/cgroup`).
