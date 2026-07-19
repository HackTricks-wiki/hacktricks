# Linux ptrace exit-race `pidfd_getfd()` FD theft

{{#include ../../../banners/hacktricks-training.md}}

Um padrão útil de **Linux kernel privesc** consiste em transformar um **bug de autorização do ptrace** em **file descriptor theft** de um processo privilegiado.

No estudo de caso da Qualys sobre `__ptrace_may_access()` (CVE-2026-46333), o atacante cria uma race com um **processo privilegiado que está encerrando ou removendo credenciais** e usa `pidfd_getfd()` para duplicar um FD no processo do atacante.

## Ideia central

`pidfd_getfd()` duplica um file descriptor de outro processo, mas primeiro verifica permissões no estilo do ptrace em relação ao alvo. Se essa autorização for concedida incorretamente durante uma **janela de teardown**, um atacante sem privilégios pode copiar:

- FDs de **arquivos sensíveis** já abertos por um helper privilegiado
- FDs de **canais IPC autenticados** já autorizados como root

Isso transforma um bug de autorização no kernel em uma primitive de userspace muito prática.

## Por que a primitive é perigosa

O ataque **não** precisa de um bug no próprio helper privilegiado. O helper só precisa manter temporariamente algo valioso:

- `/etc/shadow`
- `/etc/ssh/*_key`
- uma conexão privilegiada com D-Bus / systemd
- qualquer outro secret já aberto ou canal autorizado

Depois de ser duplicado no processo do atacante, o kernel aplica as operações ao **FD roubado**, e não ao pathname original nem a um novo fluxo de autenticação.

## Padrão de exploração

1. Identifique um **setuid / setgid / binary com file-capability** ou um **root daemon** que abra arquivos sensíveis ou mantenha conexões IPC úteis.
2. Obtenha uma relação que satisfaça as verificações relevantes da política do ptrace para o caminho do alvo (por exemplo, sendo o **parent** de um child privilegiado criado sob configurações permissivas do YAMA).
3. Crie uma race com o processo enquanto ele está **encerrando**, **removendo credenciais** ou entrando de outra forma em um estado no qual o acesso via ptrace deveria ter sido revogado.
4. Use `pidfd_open()` + `pidfd_getfd()` para duplicar o FD do alvo durante a estreita janela de autorização.
5. Reutilize o FD roubado no contexto sem privilégios:
- `read()` secrets de um file descriptor privilegiado
- envie requests por um canal IPC autenticado roubado para obter **ações do lado do root**

Formato mínimo da primitive:
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Alvos práticos para auditar

Priorize binários e daemons que, mesmo que brevemente, façam uma destas ações:

- abram arquivos acessíveis apenas pelo root antes de concluir as transições de privilégios
- conectem-se ao **system bus** e mantenham um canal já autorizado
- passem FDs privilegiados entre helpers
- realizem operações sensíveis à segurança durante a desmontagem adjacente a `do_exit()`

Bons candidatos para hunting:

- helpers de gerenciamento de senhas / contas
- helpers de SSH
- helpers mediados por PolicyKit / D-Bus
- daemons de desktop executados como root que exponham métodos D-Bus

## YAMA como gate de exploit

`kernel.yama.ptrace_scope` é um gate prático importante para abuso da família ptrace:

- `0`: comportamento clássico de ptrace para o mesmo UID
- `1`: normalmente permite tracing de pai -> filho, o que pode manter alguns caminhos públicos de exploit acessíveis
- `2`: exige `CAP_SYS_PTRACE` para acesso no estilo attach e bloqueia o abuso não privilegiado de `pidfd_getfd()` neste caminho
- `3`: desabilita completamente o ptrace attach até a reinicialização

Para esta técnica, `ptrace_scope=2` é uma **mitigação temporária** forte, pois interrompe o caminho público de exploitation do `pidfd_getfd()` com `-EPERM` para usuários não privilegiados.

## Ideias de detecção / revisão

Ao auditar software Linux privilegiado, procure estas combinações:

- **processo filho privilegiado** + **processo pai controlado pelo atacante**
- acesso temporário a **arquivos abertos valiosos**
- acesso temporário a **canais autenticados de D-Bus/systemd**
- decisões de segurança que reutilizem **autorização no estilo ptrace** fora do `ptrace(2)` clássico
- APIs do kernel que possam **duplicar, herdar ou reexportar** FDs privilegiados existentes

Ao auditar o kernel, trate qualquer caminho que faça **autorização equivalente a ptrace** durante a **desmontagem de uma task** como de alto risco, especialmente se o sucesso fornecer acesso direto a `task->files` ou a outros recursos de processo já autorizados.

## Referências

- [Qualys blog: CVE-2026-46333](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)

{{#include ../../../banners/hacktricks-training.md}}
