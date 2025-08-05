# Time Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Informações Básicas

O namespace de tempo no Linux permite offsets por namespace para os relógios monotônicos e de tempo de inicialização do sistema. É comumente usado em contêineres Linux para alterar a data/hora dentro de um contêiner e ajustar relógios após a restauração de um ponto de verificação ou instantâneo.

## Laboratório:

### Criar diferentes Namespaces

#### CLI
```bash
sudo unshare -T [--mount-proc] /bin/bash
```
Ao montar uma nova instância do sistema de arquivos `/proc` se você usar o parâmetro `--mount-proc`, você garante que o novo namespace de montagem tenha uma **visão precisa e isolada das informações do processo específicas para aquele namespace**.

<details>

<summary>Erro: bash: fork: Não é possível alocar memória</summary>

Quando `unshare` é executado sem a opção `-f`, um erro é encontrado devido à forma como o Linux lida com novos namespaces de PID (Identificação de Processo). Os detalhes principais e a solução estão descritos abaixo:

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
### Verifique em qual namespace seu processo está
```bash
ls -l /proc/self/ns/time
lrwxrwxrwx 1 root root 0 Apr  4 21:16 /proc/self/ns/time -> 'time:[4026531834]'
```
### Encontre todos os namespaces de tempo
```bash
sudo find /proc -maxdepth 3 -type l -name time -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name time -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entrar dentro de um namespace de tempo
```bash
nsenter -T TARGET_PID --pid /bin/bash
```
## Manipulando Deslocamentos de Tempo

A partir do Linux 5.6, dois relógios podem ser virtualizados por namespace de tempo:

* `CLOCK_MONOTONIC`
* `CLOCK_BOOTTIME`

Seus deltas por namespace são expostos (e podem ser modificados) através do arquivo `/proc/<PID>/timens_offsets`:
```
$ sudo unshare -Tr --mount-proc bash   # -T creates a new timens, -r drops capabilities
$ cat /proc/$$/timens_offsets
monotonic 0
boottime  0
```
O arquivo contém duas linhas - uma por relógio - com o deslocamento em **nanosegundos**. Processos que possuem **CAP_SYS_TIME** _no namespace de tempo_ podem alterar o valor:
```
# advance CLOCK_MONOTONIC by two days (172 800 s)
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
# verify
$ cat /proc/$$/uptime   # first column uses CLOCK_MONOTONIC
172801.37  13.57
```
Se você precisar que o relógio de parede (`CLOCK_REALTIME`) também mude, você ainda terá que depender de mecanismos clássicos (`date`, `hwclock`, `chronyd`, …); ele **não** é namespace.

### `unshare(1)` flags auxiliares (util-linux ≥ 2.38)
```
sudo unshare -T \
--monotonic="+24h"  \
--boottime="+7d"    \
--mount-proc         \
bash
```
As opções longas escrevem automaticamente os deltas escolhidos em `timens_offsets` logo após o namespace ser criado, salvando um `echo` manual.

---

## Suporte OCI & Runtime

* A **Especificação de Runtime OCI v1.1** (Nov 2023) adicionou um tipo de namespace `time` dedicado e o campo `linux.timeOffsets` para que os motores de contêiner possam solicitar virtualização de tempo de maneira portátil.
* **runc >= 1.2.0** implementa essa parte da especificação. Um fragmento mínimo de `config.json` se parece com:
```json
{
"linux": {
"namespaces": [
{"type": "time"}
],
"timeOffsets": {
"monotonic": 86400,
"boottime": 600
}
}
}
```
Então execute o contêiner com `runc run <id>`.

>  NOTA: runc **1.2.6** (Fev 2025) corrigiu um bug de "execução em contêiner com timens privado" que poderia levar a um travamento e potencial DoS. Certifique-se de que você está na versão ≥ 1.2.6 em produção.

---

## Considerações de segurança

1. **Capacidade necessária** – Um processo precisa de **CAP_SYS_TIME** dentro de seu namespace de usuário/tempo para alterar os offsets. Remover essa capacidade no contêiner (padrão no Docker & Kubernetes) impede manipulações.
2. **Sem alterações no relógio** – Como `CLOCK_REALTIME` é compartilhado com o host, atacantes não podem falsificar a duração dos certificados, expiração de JWT, etc. apenas via timens.
3. **Evasão de log/detecção** – Software que depende de `CLOCK_MONOTONIC` (por exemplo, limitadores de taxa baseados em tempo de atividade) pode ser confundido se o usuário do namespace ajustar o offset. Prefira `CLOCK_REALTIME` para timestamps relevantes à segurança.
4. **Superfície de ataque do kernel** – Mesmo com `CAP_SYS_TIME` removido, o código do kernel permanece acessível; mantenha o host atualizado. Linux 5.6 → 5.12 recebeu várias correções de bugs timens (NULL-deref, problemas de sinalização).

### Lista de verificação de hardening

* Remova `CAP_SYS_TIME` no perfil padrão do seu runtime de contêiner.
* Mantenha os runtimes atualizados (runc ≥ 1.2.6, crun ≥ 1.12).
* Fixe util-linux ≥ 2.38 se você depender dos auxiliares `--monotonic/--boottime`.
* Audite o software dentro do contêiner que lê **uptime** ou **CLOCK_MONOTONIC** para lógica crítica de segurança.

## Referências

* man7.org – Página do manual de namespaces de tempo: <https://man7.org/linux/man-pages/man7/time_namespaces.7.html>
* Blog OCI – "OCI v1.1: novos namespaces de tempo e RDT" (15 de Nov 2023): <https://opencontainers.org/blog/2023/11/15/oci-spec-v1.1>

{{#include ../../../../banners/hacktricks-training.md}}
