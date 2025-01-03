# User Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Informações Básicas

Um namespace de usuário é um recurso do kernel Linux que **fornece isolamento de mapeamentos de ID de usuário e grupo**, permitindo que cada namespace de usuário tenha seu **próprio conjunto de IDs de usuário e grupo**. Esse isolamento permite que processos em diferentes namespaces de usuário **tenham privilégios e propriedade diferentes**, mesmo que compartilhem os mesmos IDs de usuário e grupo numericamente.

Namespaces de usuário são particularmente úteis na containerização, onde cada contêiner deve ter seu próprio conjunto independente de IDs de usuário e grupo, permitindo melhor segurança e isolamento entre contêineres e o sistema host.

### Como funciona:

1. Quando um novo namespace de usuário é criado, ele **começa com um conjunto vazio de mapeamentos de ID de usuário e grupo**. Isso significa que qualquer processo executando no novo namespace de usuário **inicialmente não terá privilégios fora do namespace**.
2. Mapeamentos de ID podem ser estabelecidos entre os IDs de usuário e grupo no novo namespace e aqueles no namespace pai (ou host). Isso **permite que processos no novo namespace tenham privilégios e propriedade correspondentes aos IDs de usuário e grupo no namespace pai**. No entanto, os mapeamentos de ID podem ser restritos a intervalos e subconjuntos específicos de IDs, permitindo um controle mais detalhado sobre os privilégios concedidos aos processos no novo namespace.
3. Dentro de um namespace de usuário, **processos podem ter privilégios de root completos (UID 0) para operações dentro do namespace**, enquanto ainda têm privilégios limitados fora do namespace. Isso permite que **contêineres sejam executados com capacidades semelhantes a root dentro de seu próprio namespace sem ter privilégios de root completos no sistema host**.
4. Processos podem se mover entre namespaces usando a chamada de sistema `setns()` ou criar novos namespaces usando as chamadas de sistema `unshare()` ou `clone()` com a flag `CLONE_NEWUSER`. Quando um processo se move para um novo namespace ou cria um, ele começará a usar os mapeamentos de ID de usuário e grupo associados a esse namespace.

## Laboratório:

### Criar diferentes Namespaces

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
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
```
Para usar o user namespace, o daemon do Docker precisa ser iniciado com **`--userns-remap=default`** (No ubuntu 14.04, isso pode ser feito modificando `/etc/default/docker` e depois executando `sudo service docker restart`)

### &#x20;Verifique em qual namespace seu processo está
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
É possível verificar o mapa de usuários do contêiner docker com:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
Ou do host com:
```bash
cat /proc/<pid>/uid_map
```
### Encontre todos os namespaces de usuário
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entrar em um namespace de usuário
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Além disso, você só pode **entrar em outro namespace de processo se for root**. E você **não pode** **entrar** em outro namespace **sem um descritor** apontando para ele (como `/proc/self/ns/user`).

### Criar novo namespace de usuário (com mapeamentos)
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
### Recuperando Capacidades

No caso de namespaces de usuário, **quando um novo namespace de usuário é criado, o processo que entra no namespace recebe um conjunto completo de capacidades dentro desse namespace**. Essas capacidades permitem que o processo execute operações privilegiadas, como **montar** **sistemas de arquivos**, criar dispositivos ou alterar a propriedade de arquivos, mas **apenas dentro do contexto do seu namespace de usuário**.

Por exemplo, quando você tem a capacidade `CAP_SYS_ADMIN` dentro de um namespace de usuário, você pode realizar operações que normalmente exigem essa capacidade, como montar sistemas de arquivos, mas apenas dentro do contexto do seu namespace de usuário. Quaisquer operações que você realizar com essa capacidade não afetarão o sistema host ou outros namespaces.

> [!WARNING]
> Portanto, mesmo que obter um novo processo dentro de um novo namespace de usuário **te dará todas as capacidades de volta** (CapEff: 000001ffffffffff), você na verdade **só pode usar as relacionadas ao namespace** (montar, por exemplo), mas não todas. Portanto, isso por si só não é suficiente para escapar de um contêiner Docker.
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
{{#include ../../../../banners/hacktricks-training.md}}
