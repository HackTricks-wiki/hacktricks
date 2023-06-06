# Namespace UTS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informações Básicas

Um namespace UTS (UNIX Time-Sharing System) é um recurso do kernel Linux que fornece **isolamento de dois identificadores do sistema**: o **nome do host** e o **domínio NIS** (Serviço de Informações de Rede). Este isolamento permite que cada namespace UTS tenha seu **próprio nome de host e domínio NIS independentes**, o que é particularmente útil em cenários de containerização onde cada contêiner deve aparecer como um sistema separado com seu próprio nome de host.

### Como funciona:

1. Quando um novo namespace UTS é criado, ele começa com uma **cópia do nome do host e do domínio NIS do namespace pai**. Isso significa que, na criação, o novo namespace **compartilha os mesmos identificadores que seu pai**. No entanto, quaisquer alterações subsequentes no nome do host ou no domínio NIS dentro do namespace não afetarão outros namespaces.
2. Processos dentro de um namespace UTS **podem alterar o nome do host e o domínio NIS** usando as chamadas de sistema `sethostname()` e `setdomainname()`, respectivamente. Essas alterações são locais para o namespace e não afetam outros namespaces ou o sistema host.
3. Os processos podem se mover entre namespaces usando a chamada de sistema `setns()` ou criar novos namespaces usando as chamadas de sistema `unshare()` ou `clone()` com a flag `CLONE_NEWUTS`. Quando um processo se move para um novo namespace ou cria um, ele começará a usar o nome do host e o domínio NIS associados a esse namespace.

## Laboratório:

### Criar diferentes Namespaces

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
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
O processo unshare executará /bin/bash, e /bin/bash criará vários sub-processos. O primeiro sub-processo do bash se tornará o PID 1 do novo namespace e o subprocesso sairá após concluir seu trabalho. Portanto, o PID 1 do novo namespace será encerrado.

O processo PID 1 tem uma função especial: ele deve se tornar o processo pai de todos os processos órfãos. Se o processo PID 1 no namespace raiz for encerrado, o kernel entrará em pânico. Se o processo PID 1 em um sub-namespace for encerrado, o kernel Linux chamará a função disable\_pid\_allocation, que limpará a flag PIDNS\_HASH\_ADDING nesse namespace. Quando o kernel Linux cria um novo processo, ele chama a função alloc\_pid para alocar um PID em um namespace e, se a flag PIDNS\_HASH\_ADDING não estiver definida, a função alloc\_pid retornará um erro -ENOMEM. É por isso que você recebeu o erro "Cannot allocate memory".

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
### Verificar em qual namespace está o seu processo

Para verificar em qual namespace está o seu processo, execute o seguinte comando:

```bash
ls -l /proc/$$/ns/
```

Onde `$$` é o PID do seu processo.
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Encontre todos os namespaces UTS

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Entrando em um namespace UTS
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
### Alterar o nome do host

Toda máquina possui um nome de host que a identifica na rede. É possível alterar o nome do host de um contêiner Docker através do namespace UTS. Para isso, é necessário criar um novo namespace UTS e alterar o nome do host dentro dele.

Para criar um novo namespace UTS, podemos utilizar o seguinte comando:

```
$ unshare --uts /bin/bash
```

Isso criará um novo namespace UTS e abrirá um shell dentro dele. Agora, podemos alterar o nome do host utilizando o seguinte comando:

```
$ hostname novo_nome_do_host
```

Dessa forma, o nome do host do contêiner será alterado para "novo_nome_do_host".
```bash
unshare -u /bin/bash
hostname newhostname # Hostname won't be changed inside the host UTS ns
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
