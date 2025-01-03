# Mount Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Informações Básicas

Um mount namespace é um recurso do kernel Linux que fornece isolamento dos pontos de montagem do sistema de arquivos vistos por um grupo de processos. Cada mount namespace tem seu próprio conjunto de pontos de montagem do sistema de arquivos, e **mudanças nos pontos de montagem em um namespace não afetam outros namespaces**. Isso significa que processos executando em diferentes mount namespaces podem ter visões diferentes da hierarquia do sistema de arquivos.

Os mount namespaces são particularmente úteis na containerização, onde cada contêiner deve ter seu próprio sistema de arquivos e configuração, isolados de outros contêineres e do sistema host.

### Como funciona:

1. Quando um novo mount namespace é criado, ele é inicializado com uma **cópia dos pontos de montagem de seu namespace pai**. Isso significa que, na criação, o novo namespace compartilha a mesma visão do sistema de arquivos que seu pai. No entanto, quaisquer mudanças subsequentes nos pontos de montagem dentro do namespace não afetarão o pai ou outros namespaces.
2. Quando um processo modifica um ponto de montagem dentro de seu namespace, como montar ou desmontar um sistema de arquivos, a **mudança é local a esse namespace** e não afeta outros namespaces. Isso permite que cada namespace tenha sua própria hierarquia de sistema de arquivos independente.
3. Processos podem se mover entre namespaces usando a chamada de sistema `setns()`, ou criar novos namespaces usando as chamadas de sistema `unshare()` ou `clone()` com a flag `CLONE_NEWNS`. Quando um processo se move para um novo namespace ou cria um, ele começará a usar os pontos de montagem associados a esse namespace.
4. **Descritores de arquivo e inodes são compartilhados entre namespaces**, o que significa que se um processo em um namespace tiver um descritor de arquivo aberto apontando para um arquivo, ele pode **passar esse descritor de arquivo** para um processo em outro namespace, e **ambos os processos acessarão o mesmo arquivo**. No entanto, o caminho do arquivo pode não ser o mesmo em ambos os namespaces devido a diferenças nos pontos de montagem.

## Laboratório:

### Criar diferentes Namespaces

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
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
ls -l /proc/self/ns/mnt
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/mnt -> 'mnt:[4026531841]'
```
### Encontre todos os namespaces de montagem
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```

```bash
findmnt
```
### Entrar dentro de um namespace de montagem
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
Além disso, você só pode **entrar em outro namespace de processo se for root**. E você **não pode** **entrar** em outro namespace **sem um descritor** apontando para ele (como `/proc/self/ns/mnt`).

Como novos montagens são acessíveis apenas dentro do namespace, é possível que um namespace contenha informações sensíveis que só podem ser acessadas a partir dele.

### Montar algo
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

```
# findmnt # List existing mounts
TARGET                                SOURCE                                                                                                           FSTYPE     OPTIONS
/                                     /dev/mapper/web05--vg-root

# unshare --mount  # run a shell in a new mount namespace
# mount --bind /usr/bin/ /mnt/
# ls /mnt/cp
/mnt/cp
# exit  # exit the shell, and hence the mount namespace
# ls /mnt/cp
ls: cannot access '/mnt/cp': No such file or directory

## Notice there's different files in /tmp
# ls /tmp
revshell.elf

# ls /mnt/tmp
krb5cc_75401103_X5yEyy
systemd-private-3d87c249e8a84451994ad692609cd4b6-apache2.service-77w9dT
systemd-private-3d87c249e8a84451994ad692609cd4b6-systemd-resolved.service-RnMUhT
systemd-private-3d87c249e8a84451994ad692609cd4b6-systemd-timesyncd.service-FAnDql
vmware-root_662-2689143848

```
## Referências

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [https://unix.stackexchange.com/questions/464033/understanding-how-mount-namespaces-work-in-linux](https://unix.stackexchange.com/questions/464033/understanding-how-mount-namespaces-work-in-linux)

{{#include ../../../../banners/hacktricks-training.md}}
