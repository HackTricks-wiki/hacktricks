# Visão geral das proteções de containers

{{#include ../../../../banners/hacktricks-training.md}}

A ideia mais importante no hardening de containers é que não existe um único controle chamado "container security". O que as pessoas chamam de isolamento de containers é, na verdade, o resultado de vários mecanismos de segurança e gerenciamento de recursos do Linux trabalhando em conjunto. Se a documentação descreve apenas um deles, os leitores tendem a superestimar sua força. Se a documentação lista todos eles sem explicar como interagem, os leitores obtêm um catálogo de nomes, mas nenhum modelo real. Esta seção tenta evitar ambos os erros.

No centro do modelo estão os **namespaces**, que isolam o que o workload pode ver. Eles fornecem ao processo uma visão privada ou parcialmente privada dos mounts do filesystem, PIDs, rede, objetos IPC, hostnames, mapeamentos de usuários/grupos, caminhos de cgroups e alguns clocks. Mas os namespaces, por si só, não decidem o que um processo pode fazer. É nesse ponto que entram as próximas camadas.

Os **cgroups** controlam o uso de recursos. Eles não são principalmente uma fronteira de isolamento no mesmo sentido que os namespaces de mount ou PID, mas são operacionalmente cruciais porque restringem memória, CPU, PIDs, I/O e acesso a dispositivos. Eles também são relevantes para a segurança porque técnicas históricas de breakout abusaram de recursos de cgroups com permissão de escrita, especialmente em ambientes com cgroup v1.

As **Capabilities** dividem o antigo modelo de root onipotente em unidades menores de privilégio. Isso é fundamental para containers porque muitos workloads ainda são executados como UID 0 dentro do container. Portanto, a questão não é apenas "o processo é root?", mas sim "quais capabilities sobreviveram, dentro de quais namespaces e sob quais restrições de seccomp e MAC?" É por isso que um processo root em um container pode ser relativamente limitado, enquanto um processo root em outro container pode ser, na prática, quase indistinguível de root no host.

O **seccomp** filtra syscalls e reduz a attack surface do kernel exposta ao workload. Esse mecanismo frequentemente bloqueia chamadas obviamente perigosas, como `unshare`, `mount`, `keyctl` ou outras syscalls usadas em cadeias de breakout. Mesmo que um processo tenha uma capability que, de outra forma, permitiria uma operação, o seccomp ainda pode bloquear o caminho da syscall antes que o kernel a processe completamente.

O **AppArmor** e o **SELinux** adicionam Mandatory Access Control sobre as verificações normais do filesystem e de privilégios. Eles são particularmente importantes porque continuam sendo relevantes mesmo quando um container possui mais capabilities do que deveria. Um workload pode ter o privilégio teórico para tentar uma ação, mas ainda assim ser impedido de executá-la porque sua label ou profile proíbe o acesso ao caminho, objeto ou operação relevante.

Por fim, existem camadas adicionais de hardening que recebem menos atenção, mas que frequentemente são importantes em ataques reais: `no_new_privs`, caminhos do procfs mascarados, caminhos do sistema somente leitura, root filesystems somente leitura e defaults cuidadosos do runtime. Esses mecanismos frequentemente impedem a "última etapa" de um comprometimento, especialmente quando um atacante tenta transformar a execução de código em um ganho de privilégio mais amplo.

O restante desta pasta explica cada um desses mecanismos com mais detalhes, incluindo o que a primitiva do kernel realmente faz, como observá-la localmente, como runtimes comuns a utilizam e como operadores a enfraquecem acidentalmente.

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

Muitos escapes reais também dependem do conteúdo do host que foi montado no workload. Portanto, depois de ler as proteções principais, é útil continuar com:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}

{{#include ../../../../banners/hacktricks-training.md}}
