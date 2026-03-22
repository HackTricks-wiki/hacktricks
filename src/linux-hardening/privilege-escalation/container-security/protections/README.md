# Visão Geral das Proteções de Containers

{{#include ../../../../banners/hacktricks-training.md}}

A ideia mais importante em hardening de containers é que não existe um único controle chamado "container security". O que se chama isolamento de container é, na verdade, o resultado da cooperação de vários mecanismos de segurança e gerenciamento de recursos do Linux. Se a documentação descreve apenas um deles, os leitores tendem a superestimar sua força. Se a documentação lista todos sem explicar como eles interagem, os leitores ficam com um catálogo de nomes, mas sem um modelo real. Esta seção tenta evitar ambos os erros.

No centro do modelo estão os **namespaces**, que isolam o que a workload pode ver. Eles dão ao processo uma visão privada ou parcialmente privada de mounts do filesystem, PIDs, networking, objetos IPC, hostnames, mapeamentos de usuário/grupo, caminhos de cgroup e alguns clocks. Mas namespaces sozinhos não decidem o que um processo tem permissão para fazer. É aí que entram as próximas camadas.

**cgroups** governam o uso de recursos. Eles não são primariamente um limite de isolamento no mesmo sentido que mount ou PID namespaces, mas são cruciais operacionalmente porque restringem memória, CPU, PIDs, I/O e acesso a dispositivos. Também têm relevância de segurança porque técnicas históricas de breakout abusaram de features de cgroup graváveis, especialmente em ambientes cgroup v1.

**Capabilities** dividem o antigo modelo de root todo-poderoso em unidades menores de privilégio. Isso é fundamental para containers porque muitas workloads ainda rodam como UID 0 dentro do container. A questão, portanto, não é apenas "o processo é root?", mas sim "quais capabilities sobreviveram, dentro de quais namespaces, sob quais restrições de seccomp e MAC?" É por isso que um processo root em um container pode ser relativamente limitado enquanto um root em outro container pode, na prática, ser quase indistinguível do root do host.

**seccomp** filtra syscalls e reduz a superfície de ataque do kernel exposta à workload. Frequentemente é o mecanismo que bloqueia chamadas obviamente perigosas como `unshare`, `mount`, `keyctl` ou outras syscalls usadas em cadeias de breakout. Mesmo que um processo tenha uma capability que, de outra forma, permitiria uma operação, seccomp ainda pode bloquear o caminho da syscall antes que o kernel a processe totalmente.

**AppArmor** e **SELinux** adicionam Mandatory Access Control além das verificações normais de filesystem e privilégios. Estes são particularmente importantes porque continuam a importar mesmo quando um container tem mais capabilities do que deveria. Uma workload pode possuir o privilégio teórico para tentar uma ação, mas ainda assim ser impedida de executá-la porque seu label ou profile proíbe o acesso ao caminho, objeto ou operação relevante.

Finalmente, existem camadas adicionais de hardening que recebem menos atenção, mas que regularmente importam em ataques reais: `no_new_privs`, masked procfs paths, read-only system paths, read-only root filesystems, e defaults cuidadosos de runtime. Esses mecanismos frequentemente impedem a "última milha" de um comprometimento, especialmente quando um atacante tenta transformar execução de código em um ganho de privilégio mais amplo.

O restante desta pasta explica cada um desses mecanismos em mais detalhe, incluindo o que o primitivo do kernel realmente faz, como observá-lo localmente, como runtimes comuns o usam e como operadores acidentalmente o enfraquecem.

## Leia a seguir

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

Muitos escapes reais também dependem do conteúdo do host que foi montado na workload, então após ler as proteções centrais é útil continuar com:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
{{#include ../../../../banners/hacktricks-training.md}}
