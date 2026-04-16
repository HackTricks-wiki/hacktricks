# Assessment And Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Uma boa avaliação de container deve responder a duas perguntas em paralelo. Primeiro, o que um atacante pode fazer a partir do workload atual? Segundo, quais escolhas do operador tornaram isso possível? Ferramentas de enumeração ajudam com a primeira pergunta, e orientações de hardening ajudam com a segunda. Manter ambas na mesma página torna a seção mais útil como referência de campo, em vez de apenas um catálogo de técnicas de escape.

Uma atualização prática para ambientes modernos é que muitas writeups antigas de container assumem silenciosamente um **rootful runtime**, **sem isolamento de user namespace**, e muitas vezes **cgroup v1**. Essas suposições não são mais seguras. Antes de gastar tempo em primitivas antigas de escape, primeiro confirme se o workload é rootless ou userns-remapped, se o host está usando cgroup v2 e se Kubernetes ou o runtime agora está aplicando perfis padrão de seccomp e AppArmor. Esses detalhes frequentemente determinam se uma breakout famosa ainda se aplica.

## Enumeration Tools

Várias ferramentas continuam úteis para caracterizar rapidamente um ambiente de container:

- `linpeas` pode identificar muitos indicadores de container, sockets montados, conjuntos de capabilities, sistemas de arquivos perigosos e indícios de breakout.
- `CDK` foca especificamente em ambientes de container e inclui enumeração além de algumas verificações automatizadas de escape.
- `amicontained` é leve e útil para identificar restrições de container, capabilities, exposição de namespaces e classes prováveis de breakout.
- `deepce` é outro enumerador focado em container com verificações orientadas a breakout.
- `grype` é útil quando a avaliação inclui revisão de vulnerabilidades de image-package em vez de apenas análise de escape em runtime.
- `Tracee` é útil quando você precisa de **evidência em runtime** em vez de apenas postura estática, especialmente para execução suspeita de processos, acesso a arquivos e coleta de eventos ciente de container.
- `Inspektor Gadget` é útil em Kubernetes e em investigações de host Linux quando você precisa de visibilidade baseada em eBPF vinculada a pods, containers, namespaces e outros conceitos de nível superior.

O valor dessas ferramentas é velocidade e cobertura, não certeza. Elas ajudam a revelar rapidamente a postura geral, mas os achados interessantes ainda precisam de interpretação manual em relação ao modelo real de runtime, namespace, capability e mount.

## Hardening Priorities

Os princípios mais importantes de hardening são conceitualmente simples, embora a implementação varie por plataforma. Evite containers privilegiados. Evite sockets de runtime montados. Não dê aos containers caminhos do host graváveis, a menos que haja um motivo muito específico. Use user namespaces ou execução rootless quando viável. Remova todas as capabilities e adicione de volta apenas as que o workload realmente precisa. Mantenha seccomp, AppArmor e SELinux ativados em vez de desativá-los para corrigir problemas de compatibilidade de aplicação. Limite recursos para que um container comprometido não consiga facilmente negar serviço ao host.

Higiene de image e build importa tanto quanto postura em runtime. Use imagens mínimas, reconstrua com frequência, faça scan delas, exija provenance quando prático e mantenha secrets fora de layers. Um container executando como non-root com uma image pequena e uma superfície estreita de syscall e capability é muito mais fácil de defender do que uma large convenience image executando com root equivalente ao host e ferramentas de debug pré-instaladas.

Para Kubernetes, as baselines de hardening atuais são mais opinativas do que muitos operadores ainda assumem. Os **Pod Security Standards** embutidos tratam `restricted` como o perfil de "current best practice": `allowPrivilegeEscalation` deve ser `false`, workloads devem ser executados como non-root, seccomp deve ser definido explicitamente como `RuntimeDefault` ou `Localhost`, e conjuntos de capabilities devem ser removidos agressivamente. Durante a avaliação, isso importa porque um cluster que está usando apenas labels `warn` ou `audit` pode parecer hardened no papel enquanto ainda admite pods arriscados na prática.

## Modern Triage Questions

Antes de entrar em páginas específicas de escape, responda estas perguntas rápidas:

1. O workload é **rootful**, **rootless** ou **userns-remapped**?
2. O node está usando **cgroup v1** ou **cgroup v2**?
3. **seccomp** e **AppArmor/SELinux** estão configurados explicitamente ou apenas herdados quando disponíveis?
4. Em Kubernetes, o namespace está realmente **enforcing** `baseline` ou `restricted`, ou apenas avisando/auditando?

Useful checks:
```bash
id
cat /proc/self/uid_map 2>/dev/null
cat /proc/self/gid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/1/attr/current 2>/dev/null
find /var/run/secrets -maxdepth 3 -type f 2>/dev/null | head
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get ns "$NS" -o jsonpath='{.metadata.labels}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.supplementalGroupsPolicy}{"\n"}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.seccompProfile.type}{"\n"}{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.capabilities.drop}{"\n"}' 2>/dev/null
```
O que é interessante aqui:

- Se `/proc/self/uid_map` mostrar root do container mapeado para uma **faixa alta de UID do host**, muitas writeups antigas de host-root ficam menos relevantes, porque root no container já não é equivalente a host-root.
- Se `/sys/fs/cgroup` for `cgroup2fs`, writeups antigas específicas de **cgroup v1** como abuso de `release_agent` não devem mais ser sua primeira aposta.
- Se seccomp e AppArmor forem herdados apenas implicitamente, a portabilidade pode ser mais fraca do que os defensores esperam. Em Kubernetes, definir explicitamente `RuntimeDefault` costuma ser mais forte do que depender silenciosamente dos padrões do nó.
- Se `supplementalGroupsPolicy` estiver definido como `Strict`, o pod deve evitar herdar silenciosamente memberships extras de grupo de `/etc/group` dentro da imagem, o que torna o comportamento de acesso a volumes e arquivos baseado em grupo mais previsível.
- Labels de namespace como `pod-security.kubernetes.io/enforce=restricted` valem a pena ser verificadas diretamente. `warn` e `audit` são úteis, mas não impedem que um pod arriscado seja criado.

## Exemplos de Resource-Exhaustion

Controles de recurso não são glamourosos, mas fazem parte da segurança de containers porque limitam o raio de impacto de uma compromise. Sem limites de memória, CPU ou PID, um shell simples pode ser suficiente para degradar o host ou workloads vizinhos.

Exemplos de testes que impactam o host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Esses exemplos são úteis porque mostram que nem todo resultado perigoso de container é um "escape" limpo. Limites fracos de cgroup ainda podem transformar execução de código em impacto operacional real.

Em ambientes baseados em Kubernetes, também verifique se os controles de recursos existem de fato antes de tratar DoS como algo teórico:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Hardening Tooling

Para ambientes centrados em Docker, `docker-bench-security` continua sendo uma linha de base útil de auditoria no lado do host porque verifica problemas comuns de configuração em relação a orientações de benchmark amplamente reconhecidas:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
A ferramenta não é um substituto para threat modeling, mas ainda é valiosa para encontrar defaults descuidados de daemon, mount, network e runtime que se acumulam ao longo do tempo.

Para Kubernetes e ambientes com forte dependência de runtime, combine verificações estáticas com visibilidade de runtime:

- `Tracee` é útil para detection em runtime ciente de container e forensics rápida quando você precisa confirmar o que um workload comprometido realmente acessou.
- `Inspektor Gadget` é útil quando a assessment precisa de telemetria em nível de kernel mapeada de volta para pods, containers, atividade DNS, execução de arquivos ou comportamento de network.

## Checks

Use estes como comandos rápidos de primeira passagem durante a assessment:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
O que é interessante aqui:

- Um processo root com capacidades amplas e `Seccomp: 0` merece atenção imediata.
- Um processo root que também tem um **mapeamento UID 1:1** é muito mais interessante do que "root" dentro de um user namespace devidamente isolado.
- `cgroup2fs` geralmente significa que muitas cadeias antigas de escape de **cgroup v1** não são seu melhor ponto de partida, enquanto a ausência de `memory.max` ou `pids.max` ainda aponta para controles fracos de blast radius.
- Montagens suspeitas e runtime sockets geralmente oferecem um caminho mais rápido para impacto do que qualquer kernel exploit.
- A combinação de postura fraca do runtime e limites fracos de recursos geralmente indica um ambiente de container permissivo em geral, em vez de um único erro isolado.

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
