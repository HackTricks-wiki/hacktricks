## Namespace de Rede

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informações Básicas

Um namespace de rede é um recurso do kernel Linux que fornece isolamento da pilha de rede, permitindo que **cada namespace de rede tenha sua própria configuração de rede independente**, interfaces, endereços IP, tabelas de roteamento e regras de firewall. Este isolamento é útil em vários cenários, como a containerização, onde cada contêiner deve ter sua própria configuração de rede, independente de outros contêineres e do sistema host.

### Como funciona:

1. Quando um novo namespace de rede é criado, ele começa com uma **pilha de rede completamente isolada**, sem **interfaces de rede** além da interface loopback (lo). Isso significa que processos em execução no novo namespace de rede não podem se comunicar com processos em outros namespaces ou com o sistema host por padrão.
2. **Interfaces de rede virtuais**, como pares veth, podem ser criadas e movidas entre namespaces de rede. Isso permite estabelecer conectividade de rede entre namespaces ou entre um namespace e o sistema host. Por exemplo, uma extremidade de um par veth pode ser colocada no namespace de rede de um contêiner e a outra extremidade pode ser conectada a uma **ponte** ou outra interface de rede no namespace do host, fornecendo conectividade de rede ao contêiner.
3. Interfaces de rede dentro de um namespace podem ter seus **próprios endereços IP, tabelas de roteamento e regras de firewall**, independentes de outros namespaces. Isso permite que processos em diferentes namespaces de rede tenham diferentes configurações de rede e operem como se estivessem sendo executados em sistemas de rede separados.
4. Processos podem se mover entre namespaces usando a chamada de sistema `setns()`, ou criar novos namespaces usando as chamadas de sistema `unshare()` ou `clone()` com a flag `CLONE_NEWNET`. Quando um processo se move para um novo namespace ou cria um, ele começará a usar a configuração de rede e interfaces associadas a esse namespace.

## Laboratório:

### Criar diferentes Namespaces

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
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
Se você executar o comando unshare com a opção '-f', o unshare irá criar um novo processo após criar o novo namespace pid. E executará /bin/bash no novo processo. O novo processo será o pid 1 do novo namespace pid. Em seguida, o bash também criará vários sub-processos para realizar algumas tarefas. Como o próprio bash é o pid 1 do novo namespace pid, seus sub-processos podem ser encerrados sem nenhum problema.

Traduzido de [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
# Run ifconfig or ip -a
```
### Verificar em qual namespace está o seu processo

Para verificar em qual namespace está o seu processo, execute o seguinte comando:

```bash
ls -l /proc/$$/ns/
```

Onde `$$` é o PID do seu processo.
```bash
ls -l /proc/self/ns/net
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/net -> 'net:[4026531840]'
```
### Encontrar todos os namespaces de rede

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name net -exec readlink {} \; 2>/dev/null | sort -u | grep "net:"
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name net -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entrando em um namespace de rede

{% endcode %}
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
Também, você só pode **entrar em outro namespace de processo se você for root**. E você **não pode** **entrar** em outro namespace **sem um descritor** apontando para ele (como `/proc/self/ns/net`).
