# Container Protections Overview

{{#include ../../../../banners/hacktricks-training.md}}

A ideia mais importante no hardening de containers é que não existe um único controle chamado "container security". O que as pessoas chamam de isolamento de container é na verdade o resultado de vários mecanismos de segurança e gerenciamento de recursos do Linux trabalhando em conjunto. Se a documentação descreve apenas um deles, os leitores tendem a superestimar sua força. Se a documentação lista todos sem explicar como interagem, os leitores recebem um catálogo de nomes, mas sem um modelo real. Esta seção tenta evitar ambos os erros.

No centro do modelo estão os **namespaces**, que isolam o que o workload pode ver. Eles dão ao processo uma visão privada ou parcialmente privada de mounts do filesystem, PIDs, networking, objetos IPC, hostnames, mapeamentos de usuário/grupo, caminhos de cgroup e alguns clocks. Mas os namespaces sozinhos não decidem o que um processo tem permissão para fazer. É aí que as próximas camadas entram.

**cgroups** governam o uso de recursos. Eles não são primariamente uma fronteira de isolamento no mesmo sentido que mount ou PID namespaces, mas são cruciais operacionalmente porque restringem memória, CPU, PIDs, I/O e acesso a dispositivos. Também têm relevância de segurança porque técnicas históricas de escape abusavam de features de cgroup graváveis, especialmente em ambientes cgroup v1.

**Capabilities** dividem o antigo modelo root todo-poderoso em unidades menores de privilégio. Isso é fundamental para containers porque muitas cargas ainda rodam como UID 0 dentro do container. A questão, portanto, não é meramente "o processo é root?", mas sim "quais capabilities sobreviveram, dentro de quais namespaces, sob quais restrições seccomp e MAC?" É por isso que um processo root em um container pode estar relativamente restrito enquanto um processo root em outro container pode ser quase indistinguível do root do host na prática.

**seccomp** filtra syscalls e reduz a superfície de ataque do kernel exposta ao workload. Esse é frequentemente o mecanismo que bloqueia chamadas obviamente perigosas como `unshare`, `mount`, `keyctl`, ou outras syscalls usadas em cadeias de breakout. Mesmo que um processo tenha uma capability que permitiria uma operação, o seccomp ainda pode bloquear a via da syscall antes do kernel processá-la completamente.

**AppArmor** e **SELinux** adicionam Mandatory Access Control além das checagens normais de filesystem e privilégios. Esses são particularmente importantes porque continuam a importar mesmo quando um container tem mais capabilities do que deveria. Um workload pode possuir o privilégio teórico para tentar uma ação, mas ainda ser impedido de realizá-la porque seu label ou profile proíbe o acesso ao caminho, objeto ou operação relevante.

Finalmente, há camadas adicionais de hardening que recebem menos atenção mas regularmente importam em ataques reais: `no_new_privs`, caminhos do `procfs` mascarados, system paths em modo read-only, root filesystems em modo read-only, e defaults de runtime cuidadosos. Esses mecanismos frequentemente impedem a "última milha" de uma comprometimento, especialmente quando um atacante tenta transformar execução de código em um ganho de privilégio mais amplo.

O resto desta pasta explica cada um desses mecanismos com mais detalhe, incluindo o que o primitivo do kernel realmente faz, como observá-lo localmente, como runtimes comuns o usam, e como operadores acidentalmente o enfraquecem.

## Read Next

{{#ref}}
namespaces/
{{#endref}}

{{#ref}}
cgroups.md
{{#endref}}

{{#ref}}
capabilities.md
{{#endref}}

{{#ref}}
seccomp.md
{{#endref}}

{{#ref}}
apparmor.md
{{#endref}}

{{#ref}}
selinux.md
{{#endref}}

{{#ref}}
no-new-privileges.md
{{#endref}}

{{#ref}}
masked-paths.md
{{#endref}}

{{#ref}}
read-only-paths.md
{{#endref}}

Many real escapes also depend on what host content was mounted into the workload, so after reading the core protections it is useful to continue with:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
{{#include ../../../../banners/hacktricks-training.md}}
