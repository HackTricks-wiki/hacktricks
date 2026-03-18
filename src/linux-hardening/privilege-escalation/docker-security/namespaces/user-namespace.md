# Namespace de Usuário

{{#include ../../../../banners/hacktricks-training.md}}

{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## Referências

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)



## Informações Básicas

Um namespace de usuário é um recurso do kernel Linux que **fornece isolamento no mapeamento de IDs de usuário e grupo**, permitindo que cada namespace de usuário tenha seu **próprio conjunto de IDs de usuário e grupo**. Esse isolamento possibilita que processos executando em diferentes namespaces de usuário **tenham privilégios e propriedade diferentes**, mesmo que compartilhem numericamente os mesmos IDs de usuário e grupo.

Namespaces de usuário são particularmente úteis em containerização, onde cada container deve ter seu próprio conjunto independente de IDs de usuário e grupo, proporcionando maior segurança e isolamento entre containers e o sistema host.

### Como funciona:

1. Quando um novo namespace de usuário é criado, ele **começa com um conjunto vazio de mapeamentos de IDs de usuário e grupo**. Isso significa que qualquer processo executando no novo namespace de usuário **inicialmente não terá privilégios fora do namespace**.
2. Mapeamentos de IDs podem ser estabelecidos entre os IDs de usuário e grupo no novo namespace e aqueles no namespace pai (ou host). Isso **permite que processos no novo namespace tenham privilégios e propriedade correspondentes aos IDs de usuário e grupo no namespace pai**. Entretanto, os mapeamentos de IDs podem ser restritos a faixas específicas e subconjuntos de IDs, permitindo controle granular sobre os privilégios concedidos aos processos no novo namespace.
3. Dentro de um namespace de usuário, **processos podem ter privilégios completos de root (UID 0) para operações dentro do namespace**, enquanto ainda têm privilégios limitados fora do namespace. Isso permite que **containers rodem com capacidades semelhantes às de root dentro do próprio namespace sem possuir privilégios completos de root no sistema host**.
4. Processos podem se mover entre namespaces usando a chamada de sistema `setns()` ou criar novos namespaces usando as chamadas de sistema `unshare()` ou `clone()` com a flag `CLONE_NEWUSER`. Quando um processo se move para um novo namespace ou cria um, ele começará a usar os mapeamentos de IDs de usuário e grupo associados àquele namespace.

## Laboratório:

### Criar Namespaces diferentes

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **accurate and isolated view of the process information specific to that namespace**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **Explicação do problema**:

- O kernel Linux permite que um processo crie novos namespaces usando a chamada de sistema `unshare`. Entretanto, o processo que inicia a criação de um novo PID namespace (referido como o processo "unshare") não entra no novo namespace; apenas seus processos filhos entram.
- Running `%unshare -p /bin/bash%` starts `/bin/bash` in the same process as `unshare`. Consequently, `/bin/bash` and its child processes are in the original PID namespace.
- O primeiro processo filho de `/bin/bash` no novo namespace torna-se PID 1. Quando esse processo encerra, ele aciona a limpeza do namespace se não houver outros processos, já que PID 1 tem o papel especial de adotar processos órfãos. O kernel Linux então desabilitará a alocação de PID nesse namespace.

2. **Consequência**:

- A saída do PID 1 em um novo namespace resulta na limpeza da flag `PIDNS_HASH_ADDING`. Isso faz com que a função `alloc_pid` falhe ao alocar um novo PID ao criar um novo processo, produzindo o erro "Cannot allocate memory".

3. **Solução**:
- O problema pode ser resolvido usando a opção `-f` com `unshare`. Essa opção faz com que o `unshare` faça fork de um novo processo após criar o novo PID namespace.
- Executar `%unshare -fp /bin/bash%` garante que o próprio comando `unshare` se torne PID 1 no novo namespace. `/bin/bash` e seus processos filhos ficam então contidos com segurança nesse novo namespace, evitando a saída prematura do PID 1 e permitindo a alocação normal de PIDs.

Ao garantir que o `unshare` execute com a flag `-f`, o novo PID namespace é mantido corretamente, permitindo que `/bin/bash` e seus subprocessos operem sem encontrar o erro de alocação de memória.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Para usar user namespace, o Docker daemon precisa ser iniciado com **`--userns-remap=default`**(No ubuntu 14.04, isso pode ser feito modificando `/etc/default/docker` e então executando `sudo service docker restart`)

### Verifique em qual namespace seu processo está
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
É possível verificar o user map do docker container com:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
Ou a partir do host com:
```bash
cat /proc/<pid>/uid_map
```
### Encontrar todos os namespaces de usuário
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entrar em um User namespace
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Além disso, você só pode **entrar em outro namespace de processo se for root**. E você **não pode** **entrar** em outro namespace **sem um descritor** apontando para ele (como `/proc/self/ns/user`).

### Criar novo User namespace (com mapeamentos)
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```

```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### Regras de mapeamento de UID/GID sem privilégios

Quando o processo que escreve em `uid_map`/`gid_map` **não tem CAP_SETUID/CAP_SETGID no namespace de usuário pai**, o kernel aplica regras mais restritivas: apenas um **mapeamento único** é permitido para o UID/GID efetivo do chamador, e para `gid_map` você **deve primeiro desabilitar `setgroups(2)`** escrevendo `deny` em `/proc/<pid>/setgroups`.
```bash
# Check whether setgroups is allowed in this user namespace
cat /proc/self/setgroups   # allow|deny

# For unprivileged gid_map writes, disable setgroups first
echo deny > /proc/self/setgroups
```
### ID-mapped Mounts (MOUNT_ATTR_IDMAP)

ID-mapped mounts **anexam um mapeamento de user namespace a um mount**, de modo que a propriedade dos arquivos é remapeada quando acessada através desse mount. Isso é comumente usado por container runtimes (especialmente rootless) para **compartilhar host paths sem `chown` recursivo**, enquanto ainda aplica a tradução de UID/GID do user namespace.

Do ponto de vista ofensivo, **se você puder criar um mount namespace e manter `CAP_SYS_ADMIN` dentro do seu user namespace**, e o sistema de arquivos suportar ID-mapped mounts, você pode remapear *visões* de propriedade de bind mounts. Isso **não altera a propriedade no disco**, mas pode fazer com que arquivos normalmente não graváveis apareçam como pertencentes ao seu UID/GID mapeado dentro do namespace.

### Recuperando Capacidades

No caso de user namespaces, **quando um novo user namespace é criado, o processo que entra no namespace recebe um conjunto completo de capabilities dentro desse namespace**. Essas capabilities permitem ao processo executar operações privilegiadas, como **mounting filesystems**, criar dispositivos ou alterar a propriedade de arquivos, mas **apenas no contexto do seu user namespace**.

Por exemplo, quando você tem a capability `CAP_SYS_ADMIN` dentro de um user namespace, você pode executar operações que normalmente requerem essa capability, como montar filesystems, mas somente dentro do contexto do seu user namespace. Quaisquer operações que você executar com essa capability não afetarão o sistema host ou outros namespaces.

> [!WARNING]
> Portanto, mesmo que obter um novo processo dentro de um novo User namespace **te dê todas as capabilities de volta** (CapEff: 000001ffffffffff), na prática você só pode **usar aquelas relacionadas ao namespace** (mount, por exemplo) e não todas. Então, isso por si só não é suficiente para escapar de um container Docker.
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
```
{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## Referências

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)

{{#include ../../../../banners/hacktricks-training.md}}
