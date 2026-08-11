# Linux ptrace exit-race `pidfd_getfd()` roubo de FD

{{#include ../../../banners/hacktricks-training.md}}

Um **padrão de privesc no kernel Linux** útil consiste em transformar um **bug de autorização do ptrace** em **roubo de descritor de arquivo** de um processo privilegiado.

No estudo de caso da Qualys sobre `__ptrace_may_access()` (CVE-2026-46333), o atacante explora uma condição de corrida com um **processo privilegiado que está encerrando ou removendo credenciais** e usa `pidfd_getfd()` para duplicar um FD no processo do atacante.<sup>[[1]](#references)[[2]](#references)</sup>

## Ideia central

`pidfd_getfd()` duplica um descritor de arquivo de outro processo, mas primeiro verifica permissões no estilo do ptrace em relação ao alvo.<sup>[[3]](#references)</sup> Se essa autorização for concedida incorretamente durante uma **janela de teardown**, um atacante sem privilégios pode copiar:

- FDs de **arquivos sensíveis** já abertos por um helper privilegiado
- FDs de **canais IPC autenticados** já autorizados como root

Isso transforma um bug de autorização no kernel em uma primitiva de userspace muito prática.<sup>[[1]](#references)</sup>

## Por que a primitiva é perigosa

O ataque **não** precisa de um bug no próprio helper privilegiado. O helper só precisa manter temporariamente algo valioso aberto:

- `/etc/shadow`
- `/etc/ssh/*_key`
- uma conexão privilegiada de D-Bus / systemd
- qualquer outro segredo já aberto ou canal autorizado

Depois de duplicada no processo do atacante, a cópia aponta para a mesma descrição de arquivo aberta; portanto, leituras ou solicitações IPC subsequentes usam o FD já aberto, em vez de reabrir o pathname original ou iniciar um novo fluxo de autenticação.<sup>[[2]](#references)[[3]](#references)</sup>

## Padrão de exploração

1. Identifique um **binário setuid / setgid / com capacidade de arquivo** ou um **daemon root** que abra arquivos sensíveis ou mantenha conexões IPC úteis.<sup>[[2]](#references)</sup>
2. Obtenha uma relação que satisfaça as verificações de política relevantes do ptrace para o caminho até o alvo (por exemplo, sendo o **pai** de um processo filho privilegiado criado sob configurações permissivas do YAMA).<sup>[[2]](#references)[[4]](#references)</sup>
3. Explore uma condição de corrida no processo enquanto ele está **encerrando**, **removendo credenciais** ou entrando de outra forma em um estado no qual o acesso via ptrace deveria ter sido revogado.<sup>[[2]](#references)</sup>
4. Use `pidfd_open()` + `pidfd_getfd()` para duplicar o FD do alvo durante a estreita janela de autorização.<sup>[[2]](#references)[[3]](#references)[[5]](#references)</sup>
5. Reutilize o FD roubado a partir do contexto sem privilégios.<sup>[[2]](#references)</sup>
- use `read()` para ler segredos de um descritor de arquivo privilegiado
- envie solicitações por um canal IPC autenticado roubado para obter **ações do lado do root**

Formato mínimo da primitiva.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Alvos práticos para auditar

Priorize binários e daemons que, mesmo que brevemente, façam uma destas coisas:<sup>[[1]](#references)[[2]](#references)</sup>

- abrir arquivos exclusivos do root antes de concluir as transições de privilégios
- conectar-se ao **system bus** e manter um canal já autorizado
- passar FDs privilegiados entre limites de helpers
- realizar operações sensíveis à segurança durante a desmontagem adjacente a `do_exit()`

Bons candidatos para hunting:<sup>[[1]](#references)</sup>

- helpers de gerenciamento de senhas / contas
- helpers de SSH
- helpers mediados por PolicyKit / D-Bus
- daemons de desktop do root que expõem métodos D-Bus

## YAMA como barreira de exploit

`kernel.yama.ptrace_scope` é uma barreira prática importante contra abuso da família ptrace:<sup>[[3]](#references)[[4]](#references)</sup>

- `0`: comportamento clássico de ptrace para o mesmo UID
- `1`: normalmente permite tracing de pai -> filho, o que pode manter alguns public exploit paths acessíveis
- `2`: exige `CAP_SYS_PTRACE` para acesso no estilo attach e bloqueia o abuso não privilegiado de `pidfd_getfd()` neste caminho
- `3`: desativa completamente o ptrace attach até a reinicialização

Para esta técnica, `ptrace_scope=2` é uma **mitigação temporária** forte, pois interrompe o public `pidfd_getfd()` exploitation path com `-EPERM` para usuários não privilegiados.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Ideias para detecção / revisão

Ao auditar software Linux privilegiado, procure estas combinações:

- **processo filho privilegiado** + **processo pai controlado pelo atacante**.<sup>[[2]](#references)[[4]](#references)</sup>
- acesso temporário a **arquivos abertos valiosos**
- acesso temporário a **canais D-Bus/systemd autenticados**.<sup>[[2]](#references)</sup>
- decisões de segurança que reutilizam **autorização no estilo ptrace** fora do `ptrace(2)` clássico
- APIs do kernel que podem **duplicar, herdar ou reexportar** FDs privilegiados existentes

Ao auditar o kernel, trate qualquer caminho que faça **autorização equivalente à do ptrace** durante a **desmontagem de uma task** como de alto risco, especialmente se o sucesso conceder acesso direto a `task->files` ou a outros recursos de processo já autorizados.<sup>[[2]](#references)</sup>

## References

- [1] [CVE-2026-46333: Escalonamento local de privilégios para root e divulgação de credenciais no caminho ptrace do Linux Kernel (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [TXT do aviso da Qualys](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [Página de manual de pidfd_getfd(2)](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Documentação do Yama do Linux kernel](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [5] [Página de manual de pidfd_open(2)](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
{{#include ../../../banners/hacktricks-training.md}}
