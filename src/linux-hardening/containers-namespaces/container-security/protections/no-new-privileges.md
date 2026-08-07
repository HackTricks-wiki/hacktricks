# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` é um recurso de hardening do kernel que impede que um processo obtenha mais privilégios através de `execve()`. Em termos práticos, depois que o flag é definido, executar um binário setuid, um binário setgid ou um arquivo com Linux file capabilities não concede privilégios adicionais além dos que o processo já possuía. Em ambientes containerizados, isso é importante porque muitas cadeias de privilege-escalation dependem da descoberta de um executável dentro da imagem que altere os privilégios quando iniciado.

Do ponto de vista defensivo, `no_new_privs` não substitui namespaces, seccomp ou a remoção de capabilities. Ele é uma camada de reforço. Bloqueia uma classe específica de escalada subsequente depois que a execução de código já foi obtida. Isso o torna particularmente valioso em ambientes nos quais as imagens contêm binários auxiliares, artefatos de gerenciadores de pacotes ou ferramentas legadas que, de outra forma, seriam perigosos quando combinados com um comprometimento parcial.

## Operação

O flag do kernel por trás desse comportamento é `PR_SET_NO_NEW_PRIVS`. Depois que ele é definido para um processo, chamadas posteriores a `execve()` não podem aumentar os privilégios. O detalhe importante é que o processo ainda pode executar binários; ele simplesmente não pode usá-los para atravessar um limite de privilégio que o kernel normalmente respeitaria.<sup>[[1]](#references)</sup>

O comportamento do kernel também é **herdado e irreversível**: depois que uma task define `no_new_privs`, o bit é herdado através de `fork()`, `clone()` e `execve()`, e não pode ser desativado posteriormente.<sup>[[1]](#references)</sup> Isso é útil em assessments porque um único `NoNewPrivs: 1` no processo do container normalmente significa que os descendentes também devem permanecer nesse modo, a menos que você esteja analisando uma árvore de processos completamente diferente.

Em ambientes orientados ao Kubernetes, `allowPrivilegeEscalation: false` mapeia para esse comportamento no processo do container.<sup>[[2]](#references)</sup> Em runtimes no estilo Docker e Podman, o equivalente geralmente é habilitado explicitamente por meio de uma opção de segurança. Na camada OCI, o mesmo conceito aparece como `process.noNewPrivileges`.

## Nuances importantes

`no_new_privs` bloqueia o ganho de privilégios **no momento da execução**, não toda mudança de privilégio.<sup>[[1]](#references)</sup> Em particular:

- as transições setuid e setgid deixam de funcionar através de `execve()`
- file capabilities não são adicionadas ao conjunto permitido durante `execve()`
- LSMs, como AppArmor ou SELinux, não relaxam as restrições depois de `execve()`
- um privilégio que já foi obtido continua sendo um privilégio já obtido

Esse último ponto é importante operacionalmente. Se o processo já estiver sendo executado como root, já tiver uma capability perigosa ou já tiver acesso a uma poderosa API de runtime ou a um host mount gravável, definir `no_new_privs` não neutraliza essas exposições. Ele apenas remove um **próximo passo** comum em uma cadeia de privilege-escalation.

Observe também que o flag não bloqueia mudanças de privilégio que não dependam de `execve()`.<sup>[[1]](#references)</sup> Por exemplo, uma task que já tenha privilégios suficientes ainda pode chamar `setuid(2)` diretamente ou receber um file descriptor privilegiado através de um Unix socket. É por isso que `no_new_privs` deve ser analisado junto com [seccomp](seccomp.md), conjuntos de capabilities e exposição de namespaces, e não como uma solução independente.

## Laboratório

Inspecione o estado do processo atual:
```bash
grep NoNewPrivs /proc/self/status
```
Compare isso com um container em que o runtime habilita a flag:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Em um workload protegido, o resultado deve mostrar `NoNewPrivs: 1`.

Você também pode demonstrar o efeito real em um binário setuid:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
O objetivo da comparação não é afirmar que `su` seja universalmente explorável. É mostrar que a mesma image pode se comportar de maneiras muito diferentes dependendo de `execve()` ainda estar permitido para atravessar uma fronteira de privilégio.

## Impacto na segurança

Se `no_new_privs` estiver ausente, um foothold dentro do container ainda poderá ser elevado por meio de helpers setuid ou de binaries com file capabilities. Se estiver presente, essas alterações de privilégio pós-exec são bloqueadas. O efeito é especialmente relevante em base images amplas que incluem muitos utilitários que a aplicação nunca precisou.

Também existe uma interação importante com o seccomp. Tasks não privilegiadas geralmente precisam que `no_new_privs` esteja definido antes de poderem instalar um filtro seccomp no modo filter.<sup>[[1]](#references)</sup> Esse é um dos motivos pelos quais containers hardened frequentemente exibem `Seccomp` e `NoNewPrivs` habilitados ao mesmo tempo. Do ponto de vista de um atacante, ver ambos normalmente indica que o ambiente foi configurado deliberadamente, e não por acidente.

## Misconfigurações

O problema mais comum é simplesmente não habilitar esse controle em ambientes nos quais ele seria compatível. No Kubernetes, deixar `allowPrivilegeEscalation` habilitado costuma ser o erro operacional padrão. No Docker e no Podman, omitir a security option relevante produz o mesmo efeito. Outro modo recorrente de falha é presumir que, pelo fato de um container não ser "privileged", as transições de privilégio durante o exec são automaticamente irrelevantes.

Uma armadilha mais sutil do Kubernetes é que `allowPrivilegeEscalation: false` **não** é respeitado da maneira esperada quando o container é `privileged` ou possui `CAP_SYS_ADMIN`. A API do Kubernetes documenta que `allowPrivilegeEscalation` é efetivamente sempre true nesses casos.<sup>[[2]](#references)</sup> Na prática, isso significa que o campo deve ser tratado como um sinal entre outros na postura final, e não como uma garantia de que o runtime terminou com `NoNewPrivs: 1`.

## Abuso

Se `no_new_privs` não estiver definido, a primeira pergunta é se a image contém binaries que ainda podem elevar privilégios:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Resultados interessantes incluem:

- `NoNewPrivs: 0`
- helpers setuid, como `su`, `mount`, `passwd` ou ferramentas administrativas específicas da distribuição
- binários com file capabilities que concedem privilégios de rede ou de filesystem

Em uma avaliação real, essas descobertas não comprovam, por si só, uma escalation funcional, mas identificam exatamente os binários que devem ser testados em seguida.

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

### Exemplo completo: In-Container Privilege Escalation através de setuid

Esse controle geralmente impede **in-container privilege escalation**, e não diretamente o host escape. Se `NoNewPrivs` for `0` e existir um helper setuid, teste-o explicitamente:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Se um binário setuid conhecido estiver presente e funcional, tente iniciá-lo de uma forma que preserve a transição de privilégios:
```bash
/bin/su -c id 2>/dev/null
```
Isso, por si só, não escapa do container, mas pode transformar um foothold de baixo privilégio dentro do container em container-root, o que geralmente se torna um pré-requisito para um escape posterior para o host por meio de mounts, runtime sockets ou interfaces voltadas ao kernel.

## Verificações

O objetivo dessas verificações é estabelecer se o ganho de privilégios em tempo de execução está bloqueado e se a image ainda contém helpers relevantes caso não esteja.
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
- Um manifest do Kubernetes que declara `allowPrivilegeEscalation: false` é útil, mas o status do kernel é a fonte de verdade.
- Uma imagem minimalista com poucos ou nenhum binário setuid/file-cap oferece a um atacante menos opções de post-exploitation mesmo quando `no_new_privs` está ausente.

## Padrões de Runtime

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Não habilitado por padrão | Habilitado explicitamente com `--security-opt no-new-privileges=true`; também existe um padrão para todo o daemon via `dockerd --no-new-privileges` | omitir a flag, `--privileged` |
| Podman | Não habilitado por padrão | Habilitado explicitamente com `--security-opt no-new-privileges` ou configuração de segurança equivalente | omitir a opção, `--privileged` |
| Kubernetes | Controlado pela policy do workload | `allowPrivilegeEscalation: false` solicita o efeito, mas `privileged: true` e `CAP_SYS_ADMIN` o mantêm efetivamente habilitado | `allowPrivilegeEscalation: true`, `privileged: true`, adicionar `CAP_SYS_ADMIN` |
| containerd / CRI-O no Kubernetes | Segue as configurações do workload do Kubernetes / `OCI process.noNewPrivileges` | Geralmente herdado do security context do Pod e convertido na configuração do runtime OCI | igual à linha do Kubernetes |

Essa proteção geralmente está ausente simplesmente porque ninguém a habilitou, não porque o runtime não ofereça suporte a ela.

## Referências

- [1] [Documentação do kernel Linux: Flag No New Privileges](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [2] [Kubernetes: Configurar um Security Context para um Pod ou Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

{{#include ../../../../banners/hacktricks-training.md}}
