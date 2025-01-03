# PID Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Informações Básicas

O namespace PID (Identificador de Processo) é um recurso no kernel do Linux que fornece isolamento de processos, permitindo que um grupo de processos tenha seu próprio conjunto de PIDs únicos, separado dos PIDs em outros namespaces. Isso é particularmente útil na containerização, onde o isolamento de processos é essencial para segurança e gerenciamento de recursos.

Quando um novo namespace PID é criado, o primeiro processo nesse namespace é atribuído ao PID 1. Esse processo se torna o processo "init" do novo namespace e é responsável por gerenciar outros processos dentro do namespace. Cada processo subsequente criado dentro do namespace terá um PID único dentro desse namespace, e esses PIDs serão independentes dos PIDs em outros namespaces.

Do ponto de vista de um processo dentro de um namespace PID, ele só pode ver outros processos no mesmo namespace. Ele não está ciente de processos em outros namespaces e não pode interagir com eles usando ferramentas tradicionais de gerenciamento de processos (por exemplo, `kill`, `wait`, etc.). Isso fornece um nível de isolamento que ajuda a evitar que os processos interfiram uns com os outros.

### Como funciona:

1. Quando um novo processo é criado (por exemplo, usando a chamada de sistema `clone()`), o processo pode ser atribuído a um novo ou existente namespace PID. **Se um novo namespace for criado, o processo se torna o processo "init" desse namespace**.
2. O **kernel** mantém um **mapeamento entre os PIDs no novo namespace e os PIDs correspondentes** no namespace pai (ou seja, o namespace do qual o novo namespace foi criado). Esse mapeamento **permite que o kernel traduza PIDs quando necessário**, como ao enviar sinais entre processos em diferentes namespaces.
3. **Processos dentro de um namespace PID só podem ver e interagir com outros processos no mesmo namespace**. Eles não estão cientes de processos em outros namespaces, e seus PIDs são únicos dentro de seu namespace.
4. Quando um **namespace PID é destruído** (por exemplo, quando o processo "init" do namespace sai), **todos os processos dentro desse namespace são terminados**. Isso garante que todos os recursos associados ao namespace sejam devidamente limpos.

## Laboratório:

### Criar diferentes Namespaces

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
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

Ao montar uma nova instância do sistema de arquivos `/proc` se você usar o parâmetro `--mount-proc`, você garante que o novo namespace de montagem tenha uma **visão precisa e isolada das informações do processo específicas para aquele namespace**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Verifique em qual namespace seu processo está
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Encontre todos os namespaces PID
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
Observe que o usuário root do namespace PID inicial (padrão) pode ver todos os processos, mesmo aqueles em novos namespaces PID, é por isso que podemos ver todos os namespaces PID.

### Entrar em um namespace PID
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Quando você entra em um namespace PID a partir do namespace padrão, ainda será capaz de ver todos os processos. E o processo desse namespace PID poderá ver o novo bash no namespace PID.

Além disso, você só pode **entrar em outro namespace PID de processo se for root**. E você **não pode** **entrar** em outro namespace **sem um descritor** apontando para ele (como `/proc/self/ns/pid`)

## Referências

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
