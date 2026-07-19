# Avaliação e Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

Uma boa avaliação de container deve responder a duas perguntas em paralelo. Primeiro, o que um atacante pode fazer a partir da workload atual? Segundo, quais escolhas do operador tornaram isso possível? As ferramentas de enumeração ajudam com a primeira pergunta, e as orientações de hardening ajudam com a segunda. Manter ambas na mesma página torna a seção mais útil como referência de campo, em vez de apenas um catálogo de técnicas de escape.

Uma atualização prática para ambientes modernos é que muitos writeups antigos sobre containers assumem silenciosamente um **runtime rootful**, **nenhum isolamento de user namespace** e, frequentemente, **cgroup v1**. Essas suposições não são mais seguras. Antes de perder tempo com primitivas antigas de escape, confirme primeiro se a workload é rootless ou usa userns-remapped, se o host utiliza cgroup v2 e se o Kubernetes ou o runtime está aplicando perfis padrão de seccomp e AppArmor. Esses detalhes frequentemente determinam se um breakout conhecido ainda é aplicável.

## Ferramentas de Enumeração

Várias ferramentas continuam sendo úteis para caracterizar rapidamente um ambiente de containers:

- `linpeas` pode identificar diversos indicadores de containers, sockets montados, conjuntos de capabilities, filesystems perigosos e indícios de breakout.
- `CDK` é focado especificamente em ambientes de containers e inclui enumeração, além de algumas verificações automatizadas de escape.
- `amicontained` é leve e útil para identificar restrições de containers, capabilities, exposição de namespaces e possíveis classes de breakout.
- `deepce` é outro enumerador focado em containers, com verificações orientadas a breakout.
- `grype` é útil quando a avaliação inclui a análise de vulnerabilidades dos pacotes da imagem, em vez de apenas a análise de escapes no runtime.
- `Tracee` é útil quando você precisa de **evidências em runtime**, em vez de apenas da postura estática, especialmente para execução suspeita de processos, acesso a arquivos e coleta de eventos com reconhecimento de containers.
- `Inspektor Gadget` é útil em investigações de Kubernetes e hosts Linux quando você precisa de visibilidade baseada em eBPF relacionada a pods, containers, namespaces e outros conceitos de nível mais alto.

O valor dessas ferramentas está na velocidade e na cobertura, não na certeza. Elas ajudam a revelar rapidamente a postura geral, mas as descobertas relevantes ainda precisam de interpretação manual com base no modelo real de runtime, namespaces, capabilities e mounts.

## Prioridades de Hardening

Os princípios mais importantes de hardening são conceitualmente simples, embora sua implementação varie conforme a plataforma. Evite containers privilegiados. Evite sockets de runtime montados. Não forneça paths do host com permissão de escrita aos containers, a menos que exista uma razão muito específica. Use user namespaces ou execução rootless sempre que possível. Remova todas as capabilities e adicione apenas aquelas de que a workload realmente precisa. Mantenha seccomp, AppArmor e SELinux habilitados, em vez de desativá-los para corrigir problemas de compatibilidade da aplicação. Limite os recursos para que um container comprometido não possa causar trivialmente uma negação de serviço no host.

A higiene das imagens e do processo de build é tão importante quanto a postura do runtime. Use imagens mínimas, faça rebuilds frequentes, analise-as, exija provenance quando for viável e mantenha secrets fora das layers. Um container executado como non-root, com uma imagem pequena e uma superfície restrita de syscalls e capabilities, é muito mais fácil de defender do que uma imagem grande, criada por conveniência, executada como root equivalente ao host e com ferramentas de debugging pré-instaladas.

Para Kubernetes, os baselines atuais de hardening são mais rigorosos do que muitos operadores ainda presumem. Os **Pod Security Standards** integrados consideram `restricted` o perfil de "current best practice": `allowPrivilegeEscalation` deve ser `false`, as workloads devem ser executadas como non-root, o seccomp deve ser definido explicitamente como `RuntimeDefault` ou `Localhost`, e os conjuntos de capabilities devem ser removidos agressivamente. Durante a avaliação, isso é importante porque um cluster que utiliza apenas labels `warn` ou `audit` pode parecer hardened no papel e ainda assim permitir pods arriscados na prática.

## Perguntas de Triage Modernas

Antes de acessar páginas específicas sobre escape, responda a estas perguntas rápidas:

1. A workload é **rootful**, **rootless** ou **userns-remapped**?
2. O node utiliza **cgroup v1** ou **cgroup v2**?
3. **seccomp** e **AppArmor/SELinux** estão configurados explicitamente ou apenas herdados quando disponíveis?
4. No Kubernetes, o namespace está realmente **enforcing** `baseline` ou `restricted`, ou apenas emitindo warnings/auditing?

Verificações úteis:
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

- Se `/proc/self/uid_map` mostrar o root do container mapeado para um **high host UID range**, muitos writeups antigos sobre escrita como host-root se tornam menos relevantes, porque o root no container já não é equivalente ao host-root.
- Se `/sys/fs/cgroup` for `cgroup2fs`, writeups antigos específicos do **cgroup v1**, como o abuso de `release_agent`, já não devem ser sua primeira hipótese.
- Se seccomp e AppArmor forem apenas herdados implicitamente, a portabilidade pode ser mais fraca do que os defensores esperam. No Kubernetes, definir explicitamente `RuntimeDefault` costuma ser mais seguro do que depender silenciosamente dos padrões do node.
- Se `supplementalGroupsPolicy` estiver definido como `Strict`, o pod deve evitar herdar silenciosamente associações adicionais de grupos de `/etc/group` dentro da imagem, tornando mais previsível o comportamento de acesso a volumes e arquivos baseado em grupos.
- Vale verificar diretamente labels de namespace, como `pod-security.kubernetes.io/enforce=restricted`. `warn` e `audit` são úteis, mas não impedem a criação de um pod arriscado.

## Triagem do Baseline de Runtime

Um baseline de runtime é a verificação rápida que informa se um container parece uma workload isolada comum ou um foothold de control plane com impacto no host. Ela deve coletar fatos suficientes para priorizar a próxima página a ser lida: abuso do runtime socket, mounts do host, namespaces, cgroups, capabilities ou revisão de secrets da imagem.

Verificações úteis de dentro de uma workload:
```bash
id
hostname
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/uid_map 2>/dev/null
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
readlink /proc/self/ns/{pid,mnt,net,ipc,cgroup,user} 2>/dev/null
mount
find /run /var/run -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Interpretação:

- `memory.max` / `pids.max` ausentes ou ilimitados indicam controles fracos de blast radius, mesmo sem um escape bem-sucedido.
- Um root shell com `NoNewPrivs: 0`, capabilities amplas e seccomp permissivo é muito mais interessante do que um workload restrito sem privilégios de root.
- Runtime sockets e mounts graváveis do host geralmente têm prioridade sobre kernel exploits, pois já expõem um caminho de controle de gerenciamento ou do filesystem.
- Namespaces compartilhados de PID, rede, IPC ou cgroup nem sempre são escapes completos por si só, mas facilitam encontrar o próximo passo.

## Exemplos de Esgotamento de Recursos

Os controles de recursos não são glamorosos, mas fazem parte da container security porque limitam o blast radius de um comprometimento. Sem limites de memória, CPU ou PID, um shell simples pode ser suficiente para degradar o host ou workloads vizinhos.

Exemplos de testes que impactam o host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Esses exemplos são úteis porque mostram que nem todo resultado perigoso em um container é um "escape" limpo. Limites fracos de cgroup ainda podem transformar a execução de código em um impacto operacional real.

Em ambientes baseados em Kubernetes, verifique também se os controles de recursos existem antes de considerar o DoS apenas teórico:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Ferramentas de Hardening

Para ambientes centrados em Docker, `docker-bench-security` continua sendo uma referência útil para auditorias no lado do host, pois verifica problemas comuns de configuração com base em orientações de benchmark amplamente reconhecidas:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
A ferramenta não substitui o threat modeling, mas ainda é valiosa para encontrar padrões padrão descuidados de daemon, mount, rede e runtime que se acumulam com o tempo.

Para Kubernetes e ambientes com uso intenso de runtime, combine verificações estáticas com visibilidade em runtime:

- `Tracee` é útil para detecção em runtime com consciência de containers e forensics rápidos quando você precisa confirmar o que um workload comprometido realmente acessou.
- `Inspektor Gadget` é útil quando a assessment precisa de telemetria em nível de kernel associada novamente a pods, containers, atividade de DNS, execução de arquivos ou comportamento de rede.

## Verificações

Use estes comandos como uma primeira verificação rápida durante a assessment:
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

- Um processo root com amplas capabilities e `Seccomp: 0` merece atenção imediata.
- Um processo root que também possui um **1:1 UID map** é muito mais interessante do que "root" dentro de um user namespace devidamente isolado.
- `cgroup2fs` geralmente significa que muitas cadeias de escape antigas de **cgroup v1** não são o melhor ponto de partida, enquanto a ausência de `memory.max` ou `pids.max` ainda aponta para controles fracos do raio de impacto.
- Mounts suspeitos e runtime sockets frequentemente oferecem um caminho mais rápido para obter impacto do que qualquer exploit de kernel.
- A combinação de uma postura fraca do runtime e limites de recursos fracos geralmente indica um ambiente de containers permissivo em geral, em vez de um único erro isolado.

## Referências

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
