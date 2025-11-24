# PID Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Informações Básicas

O namespace PID (Process IDentifier) é uma funcionalidade do kernel Linux que fornece isolamento de processos ao permitir que um grupo de processos tenha seu próprio conjunto de PIDs únicos, separado dos PIDs em outros namespaces. Isso é particularmente útil em containerização, onde o isolamento de processos é essencial para segurança e gerenciamento de recursos.

Quando um novo namespace PID é criado, o primeiro processo nesse namespace recebe PID 1. Esse processo se torna o processo "init" do novo namespace e é responsável por gerenciar outros processos dentro do namespace. Cada processo subsequente criado dentro do namespace terá um PID único dentro desse namespace, e esses PIDs serão independentes dos PIDs em outros namespaces.

Do ponto de vista de um processo dentro de um namespace PID, ele só consegue ver outros processos no mesmo namespace. Não está ciente de processos em outros namespaces e não pode interagir com eles usando ferramentas tradicionais de gerenciamento de processos (por exemplo, `kill`, `wait`, etc.). Isso fornece um nível de isolamento que ajuda a evitar que os processos interfiram uns nos outros.

### Como funciona:

1. Quando um novo processo é criado (por exemplo, usando a chamada de sistema `clone()`), o processo pode ser atribuído a um namespace PID novo ou existente. **Se um novo namespace for criado, o processo torna-se o processo "init" desse namespace**.
2. O **kernel** mantém um **mapeamento entre os PIDs no novo namespace e os PIDs correspondentes** no namespace pai (ou seja, o namespace do qual o novo namespace foi criado). Esse mapeamento **permite que o kernel traduza os PIDs quando necessário**, como ao enviar sinais entre processos em namespaces diferentes.
3. **Processos dentro de um namespace PID só podem ver e interagir com outros processos no mesmo namespace**. Eles não estão cientes de processos em outros namespaces, e seus PIDs são únicos dentro de seu namespace.
4. Quando um **PID namespace é destruído** (por exemplo, quando o processo "init" do namespace sai), **todos os processos dentro desse namespace são terminados**. Isso garante que todos os recursos associados ao namespace sejam adequadamente liberados.

## Laboratório:

### Criar diferentes Namespaces

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Erro: bash: fork: Cannot allocate memory</summary>

Quando `unshare` é executado sem a opção `-f`, ocorre um erro devido à forma como o Linux lida com novos namespaces de PID (Process ID). Os principais detalhes e a solução estão descritos abaixo:

1. **Explicação do problema**:

- O kernel Linux permite que um processo crie novos namespaces usando a chamada de sistema `unshare`. Contudo, o processo que inicia a criação de um novo namespace de PID (referido como o processo "unshare") não entra no novo namespace; apenas seus processos filhos entram.
- A execução de %unshare -p /bin/bash% inicia `/bin/bash` no mesmo processo que `unshare`. Consequentemente, `/bin/bash` e seus processos filhos estão no namespace de PID original.
- O primeiro processo filho de `/bin/bash` no novo namespace torna-se PID 1. Quando esse processo sai, ele aciona a limpeza do namespace se não houver outros processos, já que o PID 1 tem o papel especial de adotar processos órfãos. O kernel Linux então desabilita a alocação de PIDs nesse namespace.

2. **Consequência**:

- A saída do PID 1 em um novo namespace leva à limpeza da flag `PIDNS_HASH_ADDING`. Isso faz com que a função `alloc_pid` falhe ao alocar um novo PID ao criar um novo processo, produzindo o erro "Cannot allocate memory".

3. **Solução**:
- O problema pode ser resolvido usando a opção `-f` com `unshare`. Essa opção faz com que `unshare` faça fork de um novo processo após criar o novo namespace de PID.
- Executar %unshare -fp /bin/bash% garante que o comando `unshare` em si se torne PID 1 no novo namespace. `/bin/bash` e seus processos filhos ficam então contidos com segurança nesse novo namespace, evitando a saída prematura do PID 1 e permitindo a alocação normal de PIDs.

Ao garantir que `unshare` seja executado com a flag `-f`, o novo namespace de PID é mantido corretamente, permitindo que `/bin/bash` e seus sub-processos operem sem encontrar o erro de alocação de memória.

</details>

Ao montar uma nova instância do sistema de arquivos `/proc` usando o parâmetro `--mount-proc`, você garante que o novo mount namespace tenha uma **visão precisa e isolada das informações de processo específicas desse namespace**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Verifique em qual namespace seus processos estão
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Encontrar todos os namespaces PID
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
Observe que o usuário root do namespace PID inicial (default) pode ver todos os processos, inclusive os que estão em novos PID namespaces, por isso conseguimos ver todos os PID namespaces.

### Entrar em um PID namespace
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
When you enter inside a PID namespace from the default namespace, you will still be able to see all the processes. And the process from that PID ns will be able to see the new bash on the PID ns.

Also, you can only **enter in another process PID namespace if you are root**. And you **cannot** **enter** in other namespace **without a descriptor** pointing to it (like `/proc/self/ns/pid`)

## Recent Exploitation Notes

### CVE-2025-31133: abusing `maskedPaths` to reach host PIDs

runc ≤1.2.7 allowed attackers that control container images or `runc exec` workloads to replace the container-side `/dev/null` just before the runtime masked sensitive procfs entries. When the race succeeds, `/dev/null` can be turned into a symlink pointing at any host path (for example `/proc/sys/kernel/core_pattern`), so the new container PID namespace suddenly inherits read/write access to host-global procfs knobs even though it never left its own namespace. Once `core_pattern` or `/proc/sysrq-trigger` is writable, generating a coredump or triggering SysRq yields code execution or denial of service in the host PID namespace.

Practical workflow:

1. Build an OCI bundle whose rootfs replaces `/dev/null` with a link to the host path you want (`ln -sf /proc/sys/kernel/core_pattern rootfs/dev/null`).
2. Start the container before the fix so runc bind-mounts the host procfs target over the link.
3. Inside the container namespace, write to the now-exposed procfs file (e.g., point `core_pattern` to a reverse shell helper) and crash any process to force the host kernel to execute your helper as PID 1 context.

You can quickly audit whether a bundle is masking the right files before starting it:
```bash
jq '.linux.maskedPaths' config.json | tr -d '"'
```
Se o runtime estiver sem uma entrada de mascaramento que você espera (ou a pular porque `/dev/null` desapareceu), trate o container como tendo potencial visibilidade do PID do host.

### Namespace injection with `insject`

NCC Group’s `insject` é carregado como um payload LD_PRELOAD que intercepta uma etapa tardia no programa alvo (padrão `main`) e emite uma sequência de chamadas `setns()` após `execve()`. Isso permite que você se anexe a partir do host (ou de outro container) ao PID namespace da vítima *depois* que seu runtime inicializou, preservando a visualização de `/proc/<pid>` sem precisar copiar binários para o sistema de arquivos do container. Porque `insject` pode adiar a entrada no PID namespace até ocorrer o `fork`, você pode manter uma thread no namespace do host (com CAP_SYS_PTRACE) enquanto outra thread executa no PID namespace alvo, criando primitivas poderosas de depuração ou ofensivas.

Example usage:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Principais pontos ao abusar ou defender-se contra namespace injection:

- Use `-S/--strict` para forçar o `insject` a abortar se threads já existirem ou se namespace joins falharem, caso contrário você pode deixar threads parcialmente migradas atravessando os espaços PID do host e do container.
- Nunca anexe ferramentas que ainda mantenham writable host file descriptors a menos que você também entre no mount namespace — caso contrário qualquer processo dentro do PID namespace pode ptrace seu helper e reutilizar esses descriptors para adulterar recursos do host.

## Referências

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [container escape via "masked path" abuse due to mount race conditions (GitHub Security Advisory)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [Tool Release – insject: A Linux Namespace Injector (NCC Group)](https://www.nccgroup.com/us/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../banners/hacktricks-training.md}}
