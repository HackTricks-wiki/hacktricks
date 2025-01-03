# IPC Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Informações Básicas

Um namespace IPC (Comunicação Inter-Processos) é um recurso do kernel Linux que fornece **isolamento** de objetos IPC do System V, como filas de mensagens, segmentos de memória compartilhada e semáforos. Esse isolamento garante que processos em **diferentes namespaces IPC não possam acessar ou modificar diretamente os objetos IPC uns dos outros**, proporcionando uma camada adicional de segurança e privacidade entre grupos de processos.

### Como funciona:

1. Quando um novo namespace IPC é criado, ele começa com um **conjunto completamente isolado de objetos IPC do System V**. Isso significa que processos executando no novo namespace IPC não podem acessar ou interferir nos objetos IPC em outros namespaces ou no sistema host por padrão.
2. Objetos IPC criados dentro de um namespace são visíveis e **acessíveis apenas para processos dentro desse namespace**. Cada objeto IPC é identificado por uma chave única dentro de seu namespace. Embora a chave possa ser idêntica em diferentes namespaces, os objetos em si estão isolados e não podem ser acessados entre namespaces.
3. Processos podem se mover entre namespaces usando a chamada de sistema `setns()` ou criar novos namespaces usando as chamadas de sistema `unshare()` ou `clone()` com a flag `CLONE_NEWIPC`. Quando um processo se move para um novo namespace ou cria um, ele começará a usar os objetos IPC associados a esse namespace.

## Laboratório:

### Criar diferentes Namespaces

#### CLI
```bash
sudo unshare -i [--mount-proc] /bin/bash
```
Ao montar uma nova instância do sistema de arquivos `/proc` se você usar o parâmetro `--mount-proc`, você garante que o novo namespace de montagem tenha uma **visão precisa e isolada das informações do processo específicas para aquele namespace**.

<details>

<summary>Erro: bash: fork: Não é possível alocar memória</summary>

Quando `unshare` é executado sem a opção `-f`, um erro é encontrado devido à forma como o Linux lida com novos namespaces de PID (Identificação de Processo). Os detalhes principais e a solução estão descritos abaixo:

1. **Explicação do Problema**:

- O kernel do Linux permite que um processo crie novos namespaces usando a chamada de sistema `unshare`. No entanto, o processo que inicia a criação de um novo namespace de PID (referido como o processo "unshare") não entra no novo namespace; apenas seus processos filhos o fazem.
- Executar `%unshare -p /bin/bash%` inicia `/bin/bash` no mesmo processo que `unshare`. Consequentemente, `/bin/bash` e seus processos filhos estão no namespace de PID original.
- O primeiro processo filho de `/bin/bash` no novo namespace se torna PID 1. Quando esse processo sai, ele aciona a limpeza do namespace se não houver outros processos, já que PID 1 tem o papel especial de adotar processos órfãos. O kernel do Linux então desabilitará a alocação de PID nesse namespace.

2. **Consequência**:

- A saída de PID 1 em um novo namespace leva à limpeza da flag `PIDNS_HASH_ADDING`. Isso resulta na falha da função `alloc_pid` em alocar um novo PID ao criar um novo processo, produzindo o erro "Não é possível alocar memória".

3. **Solução**:
- O problema pode ser resolvido usando a opção `-f` com `unshare`. Esta opção faz com que `unshare` fork um novo processo após criar o novo namespace de PID.
- Executar `%unshare -fp /bin/bash%` garante que o comando `unshare` em si se torne PID 1 no novo namespace. `/bin/bash` e seus processos filhos são então contidos com segurança dentro deste novo namespace, prevenindo a saída prematura de PID 1 e permitindo a alocação normal de PID.

Ao garantir que `unshare` seja executado com a flag `-f`, o novo namespace de PID é mantido corretamente, permitindo que `/bin/bash` e seus subprocessos operem sem encontrar o erro de alocação de memória.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Verifique em qual namespace seu processo está
```bash
ls -l /proc/self/ns/ipc
lrwxrwxrwx 1 root root 0 Apr  4 20:37 /proc/self/ns/ipc -> 'ipc:[4026531839]'
```
### Encontre todos os namespaces IPC
```bash
sudo find /proc -maxdepth 3 -type l -name ipc -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name ipc -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entrar em um namespace IPC
```bash
nsenter -i TARGET_PID --pid /bin/bash
```
Além disso, você só pode **entrar em outro namespace de processo se for root**. E você **não pode** **entrar** em outro namespace **sem um descritor** apontando para ele (como `/proc/self/ns/net`).

### Criar objeto IPC
```bash
# Container
sudo unshare -i /bin/bash
ipcmk -M 100
Shared memory id: 0
ipcs -m

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status
0x2fba9021 0          root       644        100        0

# From the host
ipcs -m # Nothing is seen
```
## Referências

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
