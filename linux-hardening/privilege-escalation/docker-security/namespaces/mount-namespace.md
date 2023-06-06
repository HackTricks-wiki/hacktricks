# Namespace de Montagem

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informações Básicas

Um namespace de montagem é um recurso do kernel Linux que fornece isolamento dos pontos de montagem do sistema de arquivos vistos por um grupo de processos. Cada namespace de montagem tem seu próprio conjunto de pontos de montagem do sistema de arquivos, e **as alterações nos pontos de montagem em um namespace não afetam outros namespaces**. Isso significa que processos em diferentes namespaces de montagem podem ter visões diferentes da hierarquia do sistema de arquivos.

Os namespaces de montagem são particularmente úteis na containerização, onde cada contêiner deve ter seu próprio sistema de arquivos e configuração, isolado de outros contêineres e do sistema host.

### Como funciona:

1. Quando um novo namespace de montagem é criado, ele é inicializado com uma **cópia dos pontos de montagem do namespace pai**. Isso significa que, na criação, o novo namespace compartilha a mesma visão do sistema de arquivos que seu pai. No entanto, quaisquer alterações subsequentes nos pontos de montagem dentro do namespace não afetarão o pai ou outros namespaces.
2. Quando um processo modifica um ponto de montagem dentro de seu namespace, como montar ou desmontar um sistema de arquivos, a **alteração é local para esse namespace** e não afeta outros namespaces. Isso permite que cada namespace tenha sua própria hierarquia de sistema de arquivos independente.
3. Os processos podem se mover entre namespaces usando a chamada de sistema `setns()`, ou criar novos namespaces usando as chamadas de sistema `unshare()` ou `clone()` com a flag `CLONE_NEWNS`. Quando um processo se move para um novo namespace ou cria um, ele começará a usar os pontos de montagem associados a esse namespace.
4. **Os descritores de arquivos e inodes são compartilhados entre namespaces**, o que significa que se um processo em um namespace tiver um descritor de arquivo aberto apontando para um arquivo, ele pode **passar esse descritor de arquivo** para um processo em outro namespace, e **ambos os processos acessarão o mesmo arquivo**. No entanto, o caminho do arquivo pode não ser o mesmo em ambos os namespaces devido a diferenças nos pontos de montagem.

## Laboratório:

### Criar diferentes Namespaces

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
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
Se você executar o comando unshare com a opção '-f', o unshare irá criar um novo processo após criar o novo namespace pid. E executará /bin/bash no novo processo. O novo processo será o pid 1 do novo namespace pid. Então, o bash também irá criar vários sub-processos para realizar algumas tarefas. Como o próprio bash é o pid 1 do novo namespace pid, seus sub-processos podem ser encerrados sem nenhum problema.

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
ls -l /proc/self/ns/mnt
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/mnt -> 'mnt:[4026531841]'
```
### Encontre todos os namespaces de montagem

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Entrando em um namespace de montagem
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
Também, você só pode **entrar em outro namespace de processo se você for root**. E você **não pode** **entrar** em outro namespace **sem um descritor** apontando para ele (como `/proc/self/ns/mnt`).

Porque novos mounts só são acessíveis dentro do namespace, é possível que um namespace contenha informações sensíveis que só podem ser acessíveis a partir dele.

### Montando algo
```bash
# Generate new mount ns
unshare -m /bin/bash
mkdir /tmp/mount_ns_example
mount -t tmpfs tmpfs /tmp/mount_ns_example
mount | grep tmpfs # "tmpfs on /tmp/mount_ns_example"
echo test > /tmp/mount_ns_example/test
ls /tmp/mount_ns_example/test # Exists

# From the host
mount | grep tmpfs # Cannot see "tmpfs on /tmp/mount_ns_example"
ls /tmp/mount_ns_example/test # Doesn't exist
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
