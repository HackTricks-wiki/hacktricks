# Linux ptrace exit-race `pidfd_getfd()` FD theft

{{#include ../../../banners/hacktricks-training.md}}

Um padrão útil de **privesc no kernel Linux** é transformar um **bug de autorização do ptrace** em **file descriptor theft** de um processo privilegiado.

No estudo de caso da Qualys sobre `__ptrace_may_access()` (CVE-2026-46333), o atacante faz race com um **processo privilegiado que está encerrando ou removendo credenciais** e usa `pidfd_getfd()` para duplicar um FD no processo do atacante.<sup>[[1]](#references)[[2]](#references)</sup>

## Ideia central

`pidfd_getfd()` duplica um file descriptor de outro processo, mas primeiro verifica permissões no estilo ptrace contra o alvo. Se essa autorização for concedida incorretamente durante uma **janela de teardown**, um atacante sem privilégios pode copiar:

- FDs de **arquivos sensíveis** já abertos por um helper privilegiado
- FDs de **canais IPC autenticados** já autorizados como root

Isso transforma um bug de autorização no kernel em uma primitiva muito prática no userspace.<sup>[[1]](#references)</sup>

## Por que a primitiva é perigosa

O ataque **não** precisa de um bug no próprio helper privilegiado. O helper só precisa manter temporariamente algo valioso aberto:

- `/etc/shadow`
- `/etc/ssh/*_key`
- uma conexão privilegiada com D-Bus / systemd
- qualquer outro segredo já aberto ou canal autorizado

Depois de duplicado no processo do atacante, o kernel aplica as operações sobre o **FD roubado**, e não sobre o pathname original ou sobre um novo fluxo de autenticação.<sup>[[1]](#references)</sup>

## Padrão de exploração

1. Identifique um **binário setuid / setgid / com file-capability** ou um **daemon root** que abra arquivos sensíveis ou mantenha conexões IPC úteis.
2. Obtenha uma relação que satisfaça as verificações relevantes da política do ptrace para o caminho até o alvo (por exemplo, sendo o **parent** de um processo filho privilegiado criado sob configurações permissivas do YAMA).
3. Faça race com o processo enquanto ele está **encerrando**, **removendo credenciais** ou entrando de outra forma em um estado no qual o acesso via ptrace deveria ter sido desabilitado.
4. Use `pidfd_open()` + `pidfd_getfd()` para duplicar o FD do alvo durante a estreita janela de autorização.
5. Reutilize o FD roubado a partir do contexto sem privilégios:
- `read()` secrets de um file descriptor privilegiado
- envie requests por um canal IPC autenticado roubado para obter **ações do lado root**<sup>[[1]](#references)</sup>

Formato mínimo da primitiva:<sup>[[1]](#references)[[3]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Alvos práticos para auditar

Priorize binários e daemons que, mesmo que brevemente, façam uma destas coisas:<sup>[[1]](#references)</sup>

- abrir arquivos exclusivos do root antes de concluir as transições de privilégios
- conectar-se ao **system bus** e manter um canal já autorizado
- passar FDs privilegiados entre helpers
- realizar operações sensíveis à segurança durante a desmontagem adjacente a `do_exit()`

Bons candidatos para investigação:<sup>[[1]](#references)</sup>

- helpers de gerenciamento de contas / senhas
- helpers de SSH
- helpers mediados por PolicyKit / D-Bus
- daemons de desktop executados como root que expõem métodos D-Bus

## YAMA como barreira de exploit

`kernel.yama.ptrace_scope` é uma barreira prática importante contra abuso da família ptrace:<sup>[[4]](#references)</sup>

- `0`: comportamento clássico de ptrace com o mesmo UID
- `1`: normalmente permite tracing do processo pai -> filho, o que pode manter alguns caminhos públicos de exploit acessíveis
- `2`: requer `CAP_SYS_PTRACE` para acesso no estilo attach e bloqueia o abuso não privilegiado de `pidfd_getfd()` neste caminho
- `3`: desativa completamente o ptrace attach até a reinicialização

Para esta técnica, `ptrace_scope=2` é uma **mitigação temporária** forte, pois interrompe o caminho público de exploração de `pidfd_getfd()` com `-EPERM` para usuários não privilegiados.<sup>[[1]](#references)</sup>

## Ideias de detecção / revisão

Ao auditar software Linux privilegiado, procure estas combinações:

- **processo filho privilegiado** + **processo pai controlado pelo atacante**
- acesso temporário a **arquivos abertos valiosos**
- acesso temporário a **canais autenticados de D-Bus/systemd**
- decisões de segurança que reutilizam **autorização no estilo ptrace** fora do `ptrace(2)` clássico
- APIs do kernel que podem **duplicar, herdar ou reexportar** FDs privilegiados existentes

Ao auditar o kernel, trate qualquer caminho que faça **autorização equivalente à do ptrace** durante a **desmontagem de uma task** como de alto risco, especialmente se o sucesso fornecer acesso direto a `task->files` ou a outros recursos de processo já autorizados.

## References

- [1] [CVE-2026-46333: Local Root Privilege Escalation and Credential Disclosure in the Linux Kernel ptrace Path (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)

{{#include ../../../banners/hacktricks-training.md}}
