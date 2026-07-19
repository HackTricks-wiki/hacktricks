# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` é um recurso de hardening do kernel que impede um processo de obter mais privilégios através de `execve()`. Em termos práticos, uma vez que a flag é definida, executar um binário setuid, um binário setgid ou um arquivo com Linux file capabilities não concede privilégios adicionais além daqueles que o processo já possuía. Em ambientes containerizados, isso é importante porque muitas cadeias de privilege-escalation dependem da descoberta de um executável dentro da image que altera privilégios quando iniciado.

Do ponto de vista defensivo, `no_new_privs` não substitui namespaces, seccomp ou o dropping de capabilities. Ele é uma camada de reforço. Bloqueia uma classe específica de escalation subsequente após a obtenção de code execution. Isso o torna particularmente valioso em ambientes nos quais as images contêm helper binaries, artefatos de package-manager ou ferramentas legadas que, de outra forma, seriam perigosas quando combinadas com um comprometimento parcial.

## Operação

A flag do kernel por trás desse comportamento é `PR_SET_NO_NEW_PRIVS`. Depois de definida para um processo, chamadas posteriores a `execve()` não podem aumentar os privilégios. O detalhe importante é que o processo ainda pode executar binaries; ele simplesmente não pode usar esses binaries para atravessar um limite de privilégios que o kernel normalmente respeitaria.

O comportamento do kernel também é **herdado e irreversível**: depois que uma task define `no_new_privs`, o bit é herdado através de `fork()`, `clone()` e `execve()`, e não pode ser desativado posteriormente. Isso é útil em assessments porque um único `NoNewPrivs: 1` no processo do container normalmente significa que os descendentes também devem permanecer nesse modo, a menos que você esteja analisando uma process tree completamente diferente.

Em ambientes orientados ao Kubernetes, `allowPrivilegeEscalation: false` mapeia para esse comportamento no processo do container. Em runtimes no estilo Docker e Podman, o equivalente geralmente é habilitado explicitamente por meio de uma security option. Na camada OCI, o mesmo conceito aparece como `process.noNewPrivileges`.

## Nuances importantes

`no_new_privs` bloqueia o ganho de privilégios **no momento da execução**, não toda e qualquer alteração de privilégios. Em particular:

- transições setuid e setgid deixam de funcionar através de `execve()`
- file capabilities não são adicionadas ao permitted set em `execve()`
- LSMs como AppArmor ou SELinux não relaxam as restrições após `execve()`
- privilégios já mantidos continuam sendo privilégios já mantidos

Esse último ponto é importante operacionalmente. Se o processo já estiver sendo executado como root, já tiver uma capability perigosa ou já tiver acesso a uma runtime API poderosa ou a um host mount gravável, definir `no_new_privs` não neutraliza essas exposições. Isso apenas remove um **próximo passo** comum em uma cadeia de privilege-escalation.

Observe também que a flag não bloqueia alterações de privilégios que não dependem de `execve()`. Por exemplo, uma task que já tenha privilégios suficientes ainda pode chamar `setuid(2)` diretamente ou receber um file descriptor privilegiado através de um Unix socket. É por isso que `no_new_privs` deve ser analisado junto com [seccomp](seccomp.md), capability sets e exposição de namespaces, em vez de ser tratado como uma solução independente.

## Laboratório

Inspecione o estado do processo atual:
```bash
grep NoNewPrivs /proc/self/status
```
Compare isso com um container em que o runtime habilita a flag:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Em uma workload hardened, o resultado deve mostrar `NoNewPrivs: 1`.

Você também pode demonstrar o efeito real usando um setuid binary:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
O objetivo da comparação não é afirmar que `su` seja explorável universalmente. É mostrar que a mesma image pode se comportar de maneiras muito diferentes dependendo de `execve()` ainda estar permitido a atravessar uma boundary de privilege.

## Impacto de Segurança

Se `no_new_privs` estiver ausente, um foothold dentro do container ainda poderá ser elevado por meio de helpers setuid ou binaries com file capabilities. Se estiver presente, essas alterações de privilege pós-exec serão bloqueadas. O efeito é especialmente relevante em base images amplas que incluem muitos utilities que a aplicação nunca precisou.

Também existe uma interação importante com o seccomp. Tarefas unprivileged geralmente precisam que `no_new_privs` esteja definido antes de poderem instalar um filtro seccomp no filter mode. Essa é uma das razões pelas quais containers hardened frequentemente exibem `Seccomp` e `NoNewPrivs` habilitados em conjunto. Da perspectiva de um attacker, ver ambos geralmente significa que o ambiente foi configurado deliberadamente, e não por acidente.

## Misconfigurações

O problema mais comum é simplesmente não habilitar esse controle em ambientes onde ele seria compatível. No Kubernetes, deixar `allowPrivilegeEscalation` habilitado costuma ser o erro operacional padrão. No Docker e no Podman, omitir a security option relevante produz o mesmo efeito. Outro failure mode recorrente é presumir que, pelo fato de um container não ser "privileged", as transições de privilege durante o exec se tornam automaticamente irrelevantes.

Uma armadilha mais sutil do Kubernetes é que `allowPrivilegeEscalation: false` **não** é respeitado da forma esperada quando o container é `privileged` ou quando possui `CAP_SYS_ADMIN`. A API do Kubernetes documenta que `allowPrivilegeEscalation` é efetivamente sempre true nesses casos. Na prática, isso significa que o campo deve ser tratado como um sinal entre outros na postura final, e não como uma garantia de que o runtime terminou com `NoNewPrivs: 1`.

## Abuse

Se `no_new_privs` não estiver definido, a primeira pergunta é se a image contém binaries que ainda podem elevar o privilege:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Resultados interessantes incluem:

- `NoNewPrivs: 0`
- auxiliares setuid, como `su`, `mount`, `passwd` ou ferramentas administrativas específicas da distribuição
- binários com file capabilities que concedem privilégios de rede ou de filesystem

Em uma avaliação real, essas descobertas não comprovam, por si só, uma escalada de privilégios funcional, mas identificam exatamente os binários que vale a pena testar em seguida.

No Kubernetes, verifique também se a intenção do YAML corresponde à realidade do kernel:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
Combinações interessantes incluem:

- `allowPrivilegeEscalation: false` na especificação do Pod, mas `NoNewPrivs: 0` no container
- `cap_sys_admin` presente, o que torna o campo do Kubernetes muito menos confiável
- `Seccomp: 0` e `NoNewPrivs: 0`, o que geralmente indica uma postura de runtime amplamente enfraquecida, em vez de um único erro isolado

### Exemplo completo: Privilege Escalation dentro do container através de setuid

Esse controle geralmente impede **privilege escalation dentro do container**, e não diretamente o escape do host. Se `NoNewPrivs` for `0` e existir um helper setuid, teste-o explicitamente:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Se um binário setuid conhecido estiver presente e funcional, tente executá-lo de uma forma que preserve a transição de privilégios:
```bash
/bin/su -c id 2>/dev/null
```
Isso, por si só, não permite escapar do container, mas pode converter um foothold de baixo privilégio dentro do container em root do container, o que frequentemente se torna um pré-requisito para um posterior container escape através de mounts, runtime sockets ou interfaces voltadas ao kernel.

## Checks

O objetivo destes checks é determinar se a obtenção de privilégios em tempo de execução está bloqueada e se a imagem ainda contém helpers que seriam relevantes caso não esteja.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
O que é interessante aqui:

- `NoNewPrivs: 1` geralmente é o resultado mais seguro.
- `NoNewPrivs: 0` significa que os caminhos de escalation baseados em setuid e file-cap continuam relevantes.
- `NoNewPrivs: 1` junto com `Seccomp: 2` é um sinal comum de uma postura de hardening mais intencional.
- Um manifesto do Kubernetes que declara `allowPrivilegeEscalation: false` é útil, mas o status do kernel é a fonte de verdade.
- Uma imagem minimalista com poucos binários setuid/file-cap, ou nenhum, oferece ao atacante menos opções de post-exploitation mesmo quando `no_new_privs` está ausente.

## Padrões de Runtime

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Não habilitado por padrão | Habilitado explicitamente com `--security-opt no-new-privileges=true`; também existe um padrão global do daemon via `dockerd --no-new-privileges` | omitir a flag, `--privileged` |
| Podman | Não habilitado por padrão | Habilitado explicitamente com `--security-opt no-new-privileges` ou configuração de segurança equivalente | omitir a opção, `--privileged` |
| Kubernetes | Controlado pela política da workload | `allowPrivilegeEscalation: false` solicita o efeito, mas `privileged: true` e `CAP_SYS_ADMIN` fazem com que ele permaneça efetivamente habilitado | `allowPrivilegeEscalation: true`, `privileged: true`, adicionar `CAP_SYS_ADMIN` |
| containerd / CRI-O no Kubernetes | Segue as configurações da workload do Kubernetes / `OCI process.noNewPrivileges` | Geralmente herdado do contexto de segurança do Pod e traduzido para a configuração do runtime OCI | igual à linha do Kubernetes |

Essa proteção geralmente está ausente simplesmente porque ninguém a habilitou, não porque o runtime não ofereça suporte a ela.

## Referências

- [Documentação do kernel Linux: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Configure um Security Context para um Pod ou Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
