# Avaliação e Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

Uma boa avaliação de containers deve responder a duas perguntas paralelas. Primeiro, o que um atacante pode fazer a partir da workload atual? Segundo, quais escolhas do operador tornaram isso possível? As ferramentas de enumeração ajudam a responder à primeira pergunta, e as orientações de hardening ajudam com a segunda. Manter ambas nesta página torna a seção mais útil como referência de campo, em vez de apenas um catálogo de técnicas de escape.

Uma atualização prática para ambientes modernos é que muitos textos antigos sobre containers presumem discretamente um **runtime rootful**, **sem isolamento de user namespace** e, muitas vezes, **cgroup v1**. Essas premissas já não são seguras. Antes de dedicar tempo a primitivas de escape antigas, confirme se a workload é rootless ou usa userns-remapped, se o host está usando cgroup v2 e se o Kubernetes ou o runtime está aplicando agora perfis padrão de seccomp e AppArmor. Muitas vezes, esses detalhes determinam se um breakout conhecido ainda é aplicável.

## Ferramentas de enumeração

Várias ferramentas continuam sendo úteis para caracterizar rapidamente um ambiente de container:

- `linpeas` pode identificar muitos indicadores de container, sockets montados, conjuntos de capabilities, filesystems perigosos e indícios de breakout.
- `CDK` é voltado especificamente para ambientes de container e inclui enumeração, além de algumas verificações automatizadas de escape.
- `amicontained` é leve e útil para identificar restrições de container, capabilities, exposição de namespaces e possíveis classes de breakout.
- `deepce` é outra ferramenta de enumeração voltada para containers, com verificações direcionadas a breakouts.
- `grype` é útil quando a avaliação inclui a análise de vulnerabilidades nos pacotes da imagem, em vez de apenas a análise de escape em runtime.
- `Tracee` é útil quando você precisa de **evidências em runtime**, e não apenas da postura estática, especialmente para execução suspeita de processos, acesso a arquivos e coleta de eventos com reconhecimento de containers.
- `Inspektor Gadget` é útil em investigações de Kubernetes e hosts Linux quando você precisa de visibilidade baseada em eBPF e associada a pods, containers, namespaces e outros conceitos de nível superior.

O valor dessas ferramentas está na velocidade e na cobertura, não na certeza. Elas ajudam a revelar rapidamente a postura geral, mas as descobertas relevantes ainda precisam ser interpretadas manualmente considerando o runtime real e o modelo de namespaces, capabilities e mounts.

## Prioridades de hardening

Os princípios mais importantes de hardening são conceitualmente simples, embora sua implementação varie conforme a plataforma. Evite containers privilegiados. Evite sockets de runtime montados. Não conceda aos containers acesso gravável a caminhos do host, a menos que haja um motivo muito específico. Use user namespaces ou execução rootless quando viável. Remova todas as capabilities e adicione apenas as que a workload realmente precisa. Mantenha seccomp, AppArmor e SELinux habilitados, em vez de desativá-los para resolver problemas de compatibilidade de aplicações. Limite os recursos para que um container comprometido não possa causar facilmente uma negação de serviço no host.

A higiene das imagens e dos builds é tão importante quanto a postura em runtime. Use imagens mínimas, faça rebuilds frequentes, examine-as, exija proveniência sempre que possível e mantenha secrets fora das camadas. É muito mais fácil defender um container executado como não root, com uma imagem pequena e uma superfície restrita de syscalls e capabilities, do que uma imagem grande e conveniente, executada como root equivalente ao host e com ferramentas de debugging pré-instaladas.

No Kubernetes, as linhas de base atuais de hardening são mais prescritivas do que muitos operadores ainda supõem. Os **Pod Security Standards** integrados tratam `restricted` como o perfil de "melhor prática atual": `allowPrivilegeEscalation` deve ser `false`, as workloads devem ser executadas como não root, seccomp deve ser definido explicitamente como `RuntimeDefault` ou `Localhost`, e os conjuntos de capabilities devem ser reduzidos agressivamente. Durante uma avaliação, isso importa porque um cluster que usa apenas labels `warn` ou `audit` pode parecer hardened no papel, mas ainda admitir pods arriscados na prática.<sup>[[1]](#references)</sup>

Quando um Pod tem um token de service account montado, avalie suas permissões **por namespace de destino**. Uma regra que lista Pods em um namespace não estabelece permissões em outro; um token montado em outro Pod pode ter direitos diferentes. Use `kubectl auth can-i list pods -n <target-namespace>` e `kubectl auth can-i list secrets -n <target-namespace>` com a identidade que está sendo avaliada. Uma verificação permitida de listagem de Secrets é um indício sério, pois uma resposta de listagem pode incluir o conteúdo dos Secrets, mas não prova que há um token privilegiado. O acesso ao host também exige um direito utilizável de criação de workloads, a admissão do mount `hostPath` proposto e um contexto de segurança do node/pod que permita a operação de arquivo pretendida. Consulte as [verificações de autorização](https://kubernetes.io/docs/reference/access-authn-authz/authorization/) e as [orientações de RBAC sobre escalonamento de privilégios](https://kubernetes.io/docs/concepts/security/rbac-good-practices/) do Kubernetes.

## Perguntas modernas de triagem

Antes de explorar páginas específicas sobre escapes, responda a estas perguntas rápidas:

1. A workload é **rootful**, **rootless** ou **userns-remapped**?
2. O node está usando **cgroup v1** ou **cgroup v2**?
3. **seccomp** e **AppArmor/SELinux** estão configurados explicitamente ou apenas herdados quando disponíveis?
4. No Kubernetes, o namespace está realmente **aplicando** `baseline` ou `restricted`, ou apenas emitindo avisos/auditoria?

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

- Se `/proc/self/uid_map` mostrar o root do container mapeado para um **intervalo alto de UID no host**, muitos writeups antigos sobre host-root ficam menos relevantes, pois o root no container deixa de ser equivalente ao root no host.
- Se `/sys/fs/cgroup` for `cgroup2fs`, writeups antigos específicos de **cgroup v1**, como o abuso de `release_agent`, não devem ser sua primeira hipótese.
- Se seccomp e AppArmor forem herdados apenas implicitamente, a portabilidade pode ser menor do que os defenders esperam. No Kubernetes, definir explicitamente `RuntimeDefault` costuma ser mais seguro do que depender silenciosamente dos padrões do node.
- Se `supplementalGroupsPolicy` estiver definido como `Strict`, o pod deve evitar herdar silenciosamente associações adicionais a grupos de `/etc/group` dentro da image, tornando mais previsível o comportamento de acesso a volumes e arquivos baseado em grupos.
- Vale a pena verificar diretamente labels de namespace, como `pod-security.kubernetes.io/enforce=restricted`. `warn` e `audit` são úteis, mas não impedem a criação de um pod arriscado.

## Triagem da linha de base do runtime

Uma linha de base de runtime é uma verificação rápida que indica se um container parece uma workload isolada comum ou um foothold de control plane com impacto no host. Ela deve coletar fatos suficientes para priorizar a próxima página a consultar: abuso de runtime socket, mounts do host, namespaces, cgroups, capabilities ou análise de secrets da image.

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

- `memory.max` / `pids.max` ausentes ou ilimitados indicam controles fracos do raio de impacto, mesmo sem uma fuga clara.
- Um shell root com `NoNewPrivs: 0`, capabilities amplas e seccomp permissivo é muito mais interessante do que uma carga de trabalho restrita e não root.
- Sockets de runtime e mounts graváveis do host geralmente têm prioridade sobre exploits de kernel, pois já expõem um caminho de controle de gerenciamento ou do sistema de arquivos.
- Namespaces compartilhados de PID, rede, IPC ou cgroup nem sempre são, por si só, fugas completas, mas facilitam encontrar o próximo passo.

## Exemplos de esgotamento de recursos

Controles de recursos não são glamorosos, mas fazem parte da segurança de containers porque limitam o raio de impacto de uma invasão. Sem limites de memória, CPU ou PID, um simples shell pode ser suficiente para degradar o host ou cargas de trabalho vizinhas.

Exemplos de testes com impacto no host:

```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```

Esses exemplos são úteis porque mostram que nem todo resultado perigoso em um container é um «escape» completo. Limites fracos de cgroup ainda podem transformar a execução de código em impacto operacional real.

Em ambientes com Kubernetes, verifique também se existem controles de recursos antes de tratar DoS como algo teórico:

```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```

## Ferramentas de hardening

Em ambientes centrados no Docker, `docker-bench-security` continua sendo uma referência útil para auditorias no host, pois verifica problemas comuns de configuração com base em diretrizes de benchmark amplamente reconhecidas. Os avisos sobre o runtime devem ser analisados separadamente, pois um benchmark de configuração não consegue detectar se o runtime instalado é afetado por uma vulnerabilidade divulgada recentemente. <sup>[[2]](#references)</sup>

```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```

A ferramenta não substitui a modelagem de ameaças, mas ainda é valiosa para encontrar configurações padrão descuidadas de daemon, montagem, rede e runtime que se acumulam com o tempo.

Para ambientes Kubernetes e com uso intenso de runtimes, combine verificações estáticas com visibilidade em runtime:

- `Tracee` é útil para detecção em runtime com reconhecimento de containers e análise forense rápida, quando você precisa confirmar o que uma workload comprometida realmente acessou.
- `Inspektor Gadget` é útil quando a avaliação exige telemetria em nível de kernel associada a pods, containers, atividade DNS, execução de arquivos ou comportamento de rede.

## Verificações

Use estes comandos para uma primeira avaliação rápida:

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
- Um processo root que também tem um **mapa de UID 1:1** é muito mais interessante do que "root" dentro de um user namespace devidamente isolado.
- `cgroup2fs` geralmente significa que muitas das antigas chains de escape de **cgroup v1** não são o melhor ponto de partida, enquanto a ausência de `memory.max` ou `pids.max` ainda indica controles fracos de raio de impacto.
- Mounts suspeitos e sockets de runtime costumam oferecer um caminho mais rápido para causar impacto do que qualquer kernel exploit.
- A combinação de uma postura fraca do runtime e limites fracos de recursos geralmente indica um ambiente de container permissivo como um todo, em vez de um único erro isolado.

## References

- [1] [Padrões de Segurança de Pods do Kubernetes](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [2] [Aviso de Segurança do Docker: Múltiplas Vulnerabilidades no runc, BuildKit e Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
