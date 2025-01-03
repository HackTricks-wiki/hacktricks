# Network Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Informações Básicas

Um namespace de rede é um recurso do kernel Linux que fornece isolamento da pilha de rede, permitindo que **cada namespace de rede tenha sua própria configuração de rede independente**, interfaces, endereços IP, tabelas de roteamento e regras de firewall. Esse isolamento é útil em vários cenários, como a containerização, onde cada contêiner deve ter sua própria configuração de rede, independente de outros contêineres e do sistema host.

### Como funciona:

1. Quando um novo namespace de rede é criado, ele começa com uma **pilha de rede completamente isolada**, com **nenhuma interface de rede** exceto pela interface de loopback (lo). Isso significa que os processos em execução no novo namespace de rede não podem se comunicar com processos em outros namespaces ou com o sistema host por padrão.
2. **Interfaces de rede virtuais**, como pares veth, podem ser criadas e movidas entre namespaces de rede. Isso permite estabelecer conectividade de rede entre namespaces ou entre um namespace e o sistema host. Por exemplo, uma extremidade de um par veth pode ser colocada no namespace de rede de um contêiner, e a outra extremidade pode ser conectada a uma **ponte** ou outra interface de rede no namespace do host, fornecendo conectividade de rede ao contêiner.
3. Interfaces de rede dentro de um namespace podem ter seus **próprios endereços IP, tabelas de roteamento e regras de firewall**, independentes de outros namespaces. Isso permite que processos em diferentes namespaces de rede tenham diferentes configurações de rede e operem como se estivessem sendo executados em sistemas de rede separados.
4. Processos podem se mover entre namespaces usando a chamada de sistema `setns()`, ou criar novos namespaces usando as chamadas de sistema `unshare()` ou `clone()` com a flag `CLONE_NEWNET`. Quando um processo se move para um novo namespace ou cria um, ele começará a usar a configuração de rede e as interfaces associadas a esse namespace.

## Laboratório:

### Criar diferentes Namespaces

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
```
Ao montar uma nova instância do sistema de arquivos `/proc` se você usar o parâmetro `--mount-proc`, você garante que o novo namespace de montagem tenha uma **visão precisa e isolada das informações do processo específicas para aquele namespace**.

<details>

<summary>Erro: bash: fork: Não é possível alocar memória</summary>

Quando `unshare` é executado sem a opção `-f`, um erro é encontrado devido à forma como o Linux lida com novos namespaces de PID (ID do Processo). Os detalhes principais e a solução estão descritos abaixo:

1. **Explicação do Problema**:

- O kernel do Linux permite que um processo crie novos namespaces usando a chamada de sistema `unshare`. No entanto, o processo que inicia a criação de um novo namespace de PID (referido como o processo "unshare") não entra no novo namespace; apenas seus processos filhos entram.
- Executar `%unshare -p /bin/bash%` inicia `/bin/bash` no mesmo processo que `unshare`. Consequentemente, `/bin/bash` e seus processos filhos estão no namespace de PID original.
- O primeiro processo filho de `/bin/bash` no novo namespace se torna PID 1. Quando esse processo sai, ele aciona a limpeza do namespace se não houver outros processos, já que PID 1 tem o papel especial de adotar processos órfãos. O kernel do Linux então desabilitará a alocação de PID nesse namespace.

2. **Consequência**:

- A saída de PID 1 em um novo namespace leva à limpeza da flag `PIDNS_HASH_ADDING`. Isso resulta na falha da função `alloc_pid` em alocar um novo PID ao criar um novo processo, produzindo o erro "Não é possível alocar memória".

3. **Solução**:
- O problema pode ser resolvido usando a opção `-f` com `unshare`. Esta opção faz com que `unshare` fork um novo processo após criar o novo namespace de PID.
- Executar `%unshare -fp /bin/bash%` garante que o comando `unshare` se torne PID 1 no novo namespace. `/bin/bash` e seus processos filhos são então contidos com segurança dentro deste novo namespace, prevenindo a saída prematura de PID 1 e permitindo a alocação normal de PID.

Ao garantir que `unshare` seja executado com a flag `-f`, o novo namespace de PID é mantido corretamente, permitindo que `/bin/bash` e seus subprocessos operem sem encontrar o erro de alocação de memória.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
# Run ifconfig or ip -a
```
### &#x20;Verifique em qual namespace seu processo está
```bash
ls -l /proc/self/ns/net
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/net -> 'net:[4026531840]'
```
### Encontre todos os namespaces de rede
```bash
sudo find /proc -maxdepth 3 -type l -name net -exec readlink {} \; 2>/dev/null | sort -u | grep "net:"
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name net -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entrar dentro de um namespace de rede
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
Além disso, você só pode **entrar em outro namespace de processo se for root**. E você **não pode** **entrar** em outro namespace **sem um descritor** apontando para ele (como `/proc/self/ns/net`).

## Referências

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
