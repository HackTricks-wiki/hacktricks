# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` é um recurso de hardening do kernel que impede um processo de ganhar mais privilege através de `execve()`. Em termos práticos, uma vez que a flag é definida, executar um binário setuid, um binário setgid ou um arquivo com Linux file capabilities não concede privilege extra além do que o processo já tinha. Em ambientes containerized, isso é importante porque muitas cadeias de privilege-escalation dependem de encontrar um executável dentro da image que muda privilege quando lançado.

Do ponto de vista defensivo, `no_new_privs` não substitui namespaces, seccomp ou capability dropping. É uma camada de reforço. Ela bloqueia uma classe específica de escalation posterior depois que a execução de código já foi obtida. Isso a torna particularmente valiosa em ambientes onde as images contêm helper binaries, artefatos de package-manager ou ferramentas legadas que, de outra forma, seriam perigosas quando combinadas com um compromise parcial.

## Operation

A flag do kernel por trás desse comportamento é `PR_SET_NO_NEW_PRIVS`. Uma vez definida para um processo, chamadas posteriores de `execve()` não podem aumentar privilege. O detalhe importante é que o processo ainda pode executar binaries; ele simplesmente não pode usar esses binaries para cruzar uma privilege boundary que o kernel, de outra forma, reconheceria.

O comportamento do kernel também é **herdado e irreversível**: uma vez que uma task define `no_new_privs`, o bit é herdado através de `fork()`, `clone()` e `execve()`, e não pode ser desativado depois. Isso é útil em assessments porque um único `NoNewPrivs: 1` no processo do container normalmente significa que os descendentes também devem permanecer nesse modo, a menos que você esteja olhando para uma tree de processos completamente diferente.

Em ambientes orientados a Kubernetes, `allowPrivilegeEscalation: false` mapeia para esse comportamento para o processo do container. Em runtimes no estilo Docker e Podman, o equivalente normalmente é ativado explicitamente por meio de uma security option. Na camada OCI, o mesmo conceito aparece como `process.noNewPrivileges`.

## Important Nuances

`no_new_privs` bloqueia ganho de privilege em **tempo de exec**, não todas as mudanças de privilege. Em particular:

- transições setuid e setgid deixam de funcionar através de `execve()`
- file capabilities não são adicionadas ao conjunto permitido em `execve()`
- LSMs como AppArmor ou SELinux não relaxam restrições após `execve()`
- privilege já obtido continua sendo privilege já obtido

Esse último ponto importa operacionalmente. Se o processo já roda como root, já tem uma capability perigosa, ou já tem acesso a uma runtime API poderosa ou a um host mount gravável, definir `no_new_privs` não neutraliza essas exposições. Ele apenas remove um **próximo passo** comum em uma cadeia de privilege-escalation.

Observe também que a flag não bloqueia mudanças de privilege que não dependem de `execve()`. Por exemplo, uma task que já é privilegiada o suficiente ainda pode chamar `setuid(2)` diretamente ou receber um file descriptor privilegiado via um Unix socket. É por isso que `no_new_privs` deve ser lido junto com [seccomp](seccomp.md), capability sets e exposure de namespace, e não como uma resposta isolada.

## Lab

Inspecione o estado atual do processo:
```bash
grep NoNewPrivs /proc/self/status
```
Compare isso com um container onde o runtime habilita a flag:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Em uma workload hardened, o resultado deve mostrar `NoNewPrivs: 1`.

Você também pode demonstrar o efeito real contra um binário setuid:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
O ponto da comparação não é que `su` seja explorável universalmente. É que a mesma image pode se comportar de forma muito diferente dependendo de `execve()` ainda poder ou não atravessar uma privilege boundary.

## Security Impact

Se `no_new_privs` estiver ausente, um foothold dentro do container ainda pode ser elevado por meio de setuid helpers ou binaries com file capabilities. Se ele estiver presente, essas mudanças de privilégio pós-exec são bloqueadas. O efeito é especialmente relevante em broad base images que trazem muitas utilities que a aplicação nunca precisou desde o início.

Há também uma interação importante com seccomp. Tasks sem privilégios geralmente precisam de `no_new_privs` definido antes de poderem instalar um seccomp filter em filter mode. Essa é uma das razões pelas quais containers hardened frequentemente mostram `Seccomp` e `NoNewPrivs` habilitados juntos. Do ponto de vista do attacker, ver ambos normalmente significa que o ambiente foi configurado deliberadamente, e não por acidente.

## Misconfigurations

O problema mais comum é simplesmente não habilitar o control em ambientes onde ele seria compatível. No Kubernetes, deixar `allowPrivilegeEscalation` habilitado costuma ser o erro operacional padrão. No Docker e no Podman, omitir a security option relevante tem o mesmo efeito. Outro modo de falha recorrente é assumir que, porque um container é "not privileged", transitions de privilege em tempo de execução são automaticamente irrelevantes.

Uma armadilha mais sutil no Kubernetes é que `allowPrivilegeEscalation: false` **não** é respeitado da forma que as pessoas esperam quando o container é `privileged` ou quando ele tem `CAP_SYS_ADMIN`. A API do Kubernetes documenta que `allowPrivilegeEscalation` é efetivamente sempre true nesses casos. Na prática, isso significa que o field deve ser tratado como um sinal na postura final, e não como uma garantia de que o runtime terminou com `NoNewPrivs: 1`.

## Abuse

Se `no_new_privs` não estiver definido, a primeira pergunta é se o image contém binaries que ainda podem elevar privilege:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Resultados interessantes incluem:

- `NoNewPrivs: 0`
- helpers setuid como `su`, `mount`, `passwd`, ou ferramentas administrativas específicas da distribuição
- binaries com file capabilities que concedem privilégios de rede ou de filesystem

Em uma avaliação real, esses achados não provam por si só uma escalation funcional, mas identificam exatamente os binaries que vale testar em seguida.

Em Kubernetes, verifique também se a intenção do YAML corresponde à realidade do kernel:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
Combinações interessantes incluem:

- `allowPrivilegeEscalation: false` no Pod spec, mas `NoNewPrivs: 0` no container
- `cap_sys_admin` presente, o que torna o campo do Kubernetes muito menos confiável
- `Seccomp: 0` e `NoNewPrivs: 0`, o que geralmente indica uma postura de runtime amplamente enfraquecida em vez de um único erro isolado

### Full Example: In-Container Privilege Escalation Through setuid

Este controle geralmente previne **in-container privilege escalation** em vez de host escape diretamente. Se `NoNewPrivs` for `0` e existir um helper setuid, teste-o explicitamente:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Se um binário setuid conhecido estiver presente e funcional, tente iniciá-lo de uma forma que preserve a transição de privilégios:
```bash
/bin/su -c id 2>/dev/null
```
Isso, por si só, não escapa do container, mas pode converter um ponto de apoio de baixo privilégio dentro do container em container-root, o que muitas vezes se torna o pré-requisito para uma posterior escape do host por meio de mounts, runtime sockets ou interfaces voltadas ao kernel.

## Checks

O objetivo desses checks é estabelecer se o ganho de privilégio em tempo de execução está bloqueado e se a imagem ainda contém helpers que importariam caso não estivesse.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
What is interesting here:

- `NoNewPrivs: 1` is usually the safer result.
- `NoNewPrivs: 0` means setuid and file-cap based escalation paths remain relevant.
- `NoNewPrivs: 1` plus `Seccomp: 2` is a common sign of a more intentional hardening posture.
- A Kubernetes manifest that says `allowPrivilegeEscalation: false` is useful, but the kernel status is the ground truth.
- A minimal image with few or no setuid/file-cap binaries gives an attacker fewer post-exploitation options even when `no_new_privs` is missing.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Não habilitado por padrão | Habilitado explicitamente com `--security-opt no-new-privileges=true`; também existe um padrão global do daemon via `dockerd --no-new-privileges` | omitting the flag, `--privileged` |
| Podman | Não habilitado por padrão | Habilitado explicitamente com `--security-opt no-new-privileges` ou configuração de segurança equivalente | omitting the option, `--privileged` |
| Kubernetes | Controlado pela policy da workload | `allowPrivilegeEscalation: false` solicita o efeito, mas `privileged: true` e `CAP_SYS_ADMIN` mantêm isso efetivamente true | `allowPrivilegeEscalation: true`, `privileged: true`, adding `CAP_SYS_ADMIN` |
| containerd / CRI-O under Kubernetes | Segue as configurações da workload do Kubernetes / OCI `process.noNewPrivileges` | Geralmente herdado do security context do Pod e traduzido para a OCI runtime config | same as Kubernetes row |

This protection is often absent simply because nobody turned it on, not because the runtime lacks support for it.

## References

- [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
