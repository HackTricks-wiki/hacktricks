# Namespace UTS

{{#include ../../../../banners/hacktricks-training.md}}

## Informações Básicas

Um namespace UTS (UNIX Time-Sharing System) é um recurso do kernel Linux que fornece **isolamento de dois identificadores do sistema**: o **hostname** e o **NIS** (Network Information Service) nome de domínio. Esse isolamento permite que cada namespace UTS tenha seu **próprio hostname independente e nome de domínio NIS**, o que é particularmente útil em cenários de containerização onde cada container deve aparecer como um sistema separado com seu próprio hostname.

### Como funciona:

1. Quando um novo namespace UTS é criado, ele começa com uma **cópia do hostname e do nome de domínio NIS do seu namespace pai**. Isso significa que, na criação, o novo namespace **compartilha os mesmos identificadores que seu namespace pai**. No entanto, quaisquer alterações subsequentes no hostname ou no nome de domínio NIS dentro do namespace não afetarão outros namespaces.
2. Processos dentro de um namespace UTS **podem alterar o hostname e o nome de domínio NIS** usando as chamadas de sistema `sethostname()` e `setdomainname()`, respectivamente. Essas alterações são locais ao namespace e não afetam outros namespaces ou o sistema host.
3. Processos podem mover-se entre namespaces usando a chamada de sistema `setns()` ou criar novos namespaces usando as chamadas de sistema `unshare()` ou `clone()` com a flag `CLONE_NEWUTS`. Quando um processo se move para um novo namespace ou cria um, ele começará a usar o hostname e o nome de domínio NIS associados a esse namespace.

## Laboratório:

### Criar diferentes Namespaces

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
Ao montar uma nova instância do sistema de arquivos `/proc` usando o parâmetro `--mount-proc`, você garante que o novo mount namespace tenha uma **visão precisa e isolada das informações de processos específicas desse namespace**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

Quando `unshare` é executado sem a opção `-f`, ocorre um erro devido à forma como o Linux lida com novos namespaces de PID (Process ID). Os detalhes principais e a solução estão descritos abaixo:

1. **Explicação do problema**:

- O kernel Linux permite que um processo crie novos namespaces usando a chamada de sistema `unshare`. No entanto, o processo que inicia a criação de um novo namespace de PID (referido como o processo "unshare") não entra no novo namespace; apenas seus processos-filho entram.
- Executar %unshare -p /bin/bash% inicia `/bin/bash` no mesmo processo que `unshare`. Consequentemente, `/bin/bash` e seus processos-filho ficam no namespace de PID original.
- O primeiro processo-filho de `/bin/bash` no novo namespace torna-se PID 1. Quando esse processo sai, ele aciona a limpeza do namespace se não houver outros processos, já que o PID 1 tem o papel especial de adotar processos órfãos. O kernel Linux então desativará a alocação de PIDs nesse namespace.

2. **Consequência**:

- A saída do PID 1 em um novo namespace leva à limpeza da flag `PIDNS_HASH_ADDING`. Isso faz com que a função `alloc_pid` falhe ao alocar um novo PID ao criar um processo, produzindo o erro "Cannot allocate memory".

3. **Solução**:
- O problema pode ser resolvido usando a opção `-f` com `unshare`. Essa opção faz com que `unshare` faça fork de um novo processo após criar o novo namespace de PID.
- Executar %unshare -fp /bin/bash% garante que o próprio comando `unshare` se torne PID 1 no novo namespace. `/bin/bash` e seus processos-filho ficam então contidos com segurança nesse novo namespace, evitando a saída prematura do PID 1 e permitindo a alocação normal de PIDs.

Garantindo que `unshare` seja executado com a flag `-f`, o novo namespace de PID é mantido corretamente, permitindo que `/bin/bash` e seus subprocessos operem sem encontrar o erro de alocação de memória.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Verificar em qual namespace está o seu processo
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Encontrar todos os namespaces UTS
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entrar em um UTS namespace
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
## Abusar do compartilhamento UTS do host

Se um container for iniciado com `--uts=host`, ele entra no host UTS namespace em vez de obter um isolado. Com capacidades como `--cap-add SYS_ADMIN`, código no container pode alterar o hostname/NIS do host via `sethostname()`/`setdomainname()`:
```bash
docker run --rm -it --uts=host --cap-add SYS_ADMIN alpine sh -c "hostname hacked-host && exec sh"
# Hostname on the host will immediately change to "hacked-host"
```
Alterar o nome do host pode adulterar logs/alertas, confundir a descoberta do cluster ou quebrar configurações TLS/SSH que fixam o nome do host.

### Detectar contêineres que compartilham o UTS com o host
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
# Shows "host" when the container uses the host UTS namespace
```
{{#include ../../../../banners/hacktricks-training.md}}
