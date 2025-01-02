# CGroup Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Informações Básicas

Um cgroup namespace é um recurso do kernel Linux que fornece **isolamento de hierarquias de cgroup para processos em execução dentro de um namespace**. Cgroups, abreviação de **control groups**, são um recurso do kernel que permite organizar processos em grupos hierárquicos para gerenciar e impor **limites nos recursos do sistema** como CPU, memória e I/O.

Embora os cgroup namespaces não sejam um tipo de namespace separado como os outros que discutimos anteriormente (PID, mount, network, etc.), eles estão relacionados ao conceito de isolamento de namespace. **Cgroup namespaces virtualizam a visão da hierarquia de cgroup**, de modo que os processos em execução dentro de um cgroup namespace têm uma visão diferente da hierarquia em comparação com os processos em execução no host ou em outros namespaces.

### Como funciona:

1. Quando um novo cgroup namespace é criado, **ele começa com uma visão da hierarquia de cgroup baseada no cgroup do processo criador**. Isso significa que os processos em execução no novo cgroup namespace verão apenas um subconjunto de toda a hierarquia de cgroup, limitado à subárvore de cgroup enraizada no cgroup do processo criador.
2. Processos dentro de um cgroup namespace **verão seu próprio cgroup como a raiz da hierarquia**. Isso significa que, da perspectiva dos processos dentro do namespace, seu próprio cgroup aparece como a raiz, e eles não podem ver ou acessar cgroups fora de sua própria subárvore.
3. Cgroup namespaces não fornecem diretamente isolamento de recursos; **eles apenas fornecem isolamento da visão da hierarquia de cgroup**. **O controle e isolamento de recursos ainda são impostos pelos subsistemas de cgroup** (por exemplo, cpu, memória, etc.) em si.

Para mais informações sobre CGroups, consulte:

{{#ref}}
../cgroups.md
{{#endref}}

## Laboratório:

### Criar diferentes Namespaces

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
Ao montar uma nova instância do sistema de arquivos `/proc` se você usar o parâmetro `--mount-proc`, você garante que o novo namespace de montagem tenha uma **visão precisa e isolada das informações do processo específicas para aquele namespace**.

<details>

<summary>Erro: bash: fork: Não é possível alocar memória</summary>

Quando `unshare` é executado sem a opção `-f`, um erro é encontrado devido à forma como o Linux lida com novos namespaces de PID (ID do Processo). Os detalhes principais e a solução estão descritos abaixo:

1. **Explicação do Problema**:

- O kernel do Linux permite que um processo crie novos namespaces usando a chamada de sistema `unshare`. No entanto, o processo que inicia a criação de um novo namespace de PID (referido como o processo "unshare") não entra no novo namespace; apenas seus processos filhos o fazem.
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
```
### &#x20;Verifique em qual namespace seu processo está
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### Encontre todos os namespaces CGroup
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entrar dentro de um namespace CGroup
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
Além disso, você só pode **entrar em outro namespace de processo se for root**. E você **não pode** **entrar** em outro namespace **sem um descritor** apontando para ele (como `/proc/self/ns/cgroup`).

## Referências

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
