# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

**seccomp** é o mecanismo que permite ao kernel aplicar um filtro às syscalls que um processo pode invocar. Em ambientes conteinerizados, seccomp normalmente é usado no modo de filtro de forma que o processo não seja simplesmente marcado como "restrito" de maneira vaga, mas sim submetido a uma política concreta de syscalls. Isso importa porque muitos container breakouts exigem alcançar interfaces do kernel muito específicas. Se o processo não consegue invocar com sucesso as syscalls relevantes, uma grande classe de ataques desaparece antes que qualquer nuance de namespaces ou capabilities se torne relevante.

O modelo mental chave é simples: namespaces decidem **o que o processo pode ver**, capabilities decidem **quais ações privilegiadas o processo é, nominalmente, autorizado a tentar**, e seccomp decide **se o kernel vai mesmo aceitar o ponto de entrada do syscall para a ação tentada**. É por isso que seccomp frequentemente previne ataques que, de outra forma, pareceriam possíveis com base apenas nas capabilities.

## Security Impact

Muita superfície perigosa do kernel é acessível apenas por meio de um conjunto relativamente pequeno de syscalls. Exemplos que repetidamente importam no fortalecimento de containers incluem `mount`, `unshare`, `clone` ou `clone3` com flags particulares, `bpf`, `ptrace`, `keyctl`, e `perf_event_open`. Um atacante que consegue alcançar essas syscalls pode ser capaz de criar novos namespaces, manipular subsistemas do kernel, ou interagir com attack surface que um container de aplicação normal não precisa.

É por isso que os perfis seccomp de runtime padrão são tão importantes. Eles não são meramente "defesa extra". Em muitos ambientes eles representam a diferença entre um container que pode exercer uma ampla porção da funcionalidade do kernel e outro que é limitado a uma superfície de syscalls mais próxima do que a aplicação realmente necessita.

## Modes And Filter Construction

Historicamente o seccomp tinha um modo estrito em que apenas um conjunto mínimo de syscalls permanecia disponível, mas o modo relevante para runtimes de container modernos é o modo de filtro seccomp, frequentemente chamado **seccomp-bpf**. Nesse modelo, o kernel avalia um programa de filtro que decide se um syscall deve ser permitido, negado retornando um errno, trapped, logged, ou matar o processo. Runtimes de container usam esse mecanismo porque ele é suficientemente expressivo para bloquear amplas classes de syscalls perigosas enquanto ainda permite o comportamento normal da aplicação.

Dois exemplos de baixo nível são úteis porque tornam o mecanismo concreto em vez de mágico. O modo estrito demonstra o antigo modelo "apenas um conjunto mínimo de syscalls sobrevive":
```c
#include <fcntl.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(void) {
int output = open("output.txt", O_WRONLY);
const char *val = "test";
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
write(output, val, strlen(val) + 1);
open("output.txt", O_RDONLY);
}
```
O `open` final faz com que o processo seja morto porque não faz parte do conjunto mínimo do strict mode.

Um exemplo de filtro libseccomp mostra o modelo de política moderno com mais clareza:
```c
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
SCMP_A0(SCMP_CMP_EQ, 1),
SCMP_A2(SCMP_CMP_LE, 512));
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
SCMP_A0(SCMP_CMP_NE, 1));
seccomp_load(ctx);
seccomp_release(ctx);
printf("pid=%d\n", getpid());
}
```
Esse estilo de política é o que a maioria dos leitores imagina quando pensa em perfis seccomp em tempo de execução.

## Laboratório

Uma maneira simples de confirmar que o seccomp está ativo em um container é:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Você também pode tentar uma operação que os perfis padrão normalmente restringem:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Se o container estiver a correr sob um perfil seccomp padrão, operações do tipo `unshare` são frequentemente bloqueadas. Isto é uma demonstração útil porque mostra que, mesmo que a userspace tool exista dentro da image, o kernel path de que ela precisa pode ainda estar indisponível.

Se o container estiver a correr sob um perfil seccomp padrão, operações do tipo `unshare` são frequentemente bloqueadas mesmo quando a userspace tool existe dentro da image.

Para inspecionar o estado do processo de forma mais geral, execute:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Uso em tempo de execução

Docker suporta perfis seccomp padrão e personalizados e permite que administradores os desativem com `--security-opt seccomp=unconfined`. Podman oferece suporte similar e frequentemente combina seccomp com execução rootless em uma postura padrão bastante sensata. Kubernetes expõe seccomp através da configuração da carga de trabalho, onde `RuntimeDefault` é geralmente o baseline sensato e `Unconfined` deve ser tratado como uma exceção que requer justificativa em vez de um interruptor de conveniência.

Em ambientes baseados em containerd e CRI-O, o caminho exato é mais em camadas, mas o princípio é o mesmo: o engine de nível superior ou orquestrador decide o que deve acontecer, e o runtime acaba instalando a política seccomp resultante para o processo do container. O resultado ainda depende da configuração final do runtime que chega ao kernel.

### Exemplo de Política Personalizada

Docker e motores similares podem carregar um perfil seccomp customizado a partir de JSON. Um exemplo mínimo que nega `chmod` enquanto permite todo o resto fica assim:
```json
{
"defaultAction": "SCMP_ACT_ALLOW",
"syscalls": [
{
"name": "chmod",
"action": "SCMP_ACT_ERRNO"
}
]
}
```
Aplicado com:
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
O comando falha com `Operation not permitted`, demonstrando que a restrição vem da política de syscalls em vez de apenas das permissões normais de arquivo. Em um hardening real, listas de permissão (allowlists) são geralmente mais fortes do que padrões permissivos com uma pequena lista negra.

## Configurações incorretas

O erro mais grosseiro é definir seccomp como **unconfined** porque uma aplicação falhou sob a política padrão. Isso é comum durante solução de problemas e muito perigoso como correção permanente. Uma vez que o filtro desaparece, muitas primitives de escape baseadas em syscalls voltam a ficar acessíveis, especialmente quando capacidades poderosas ou compartilhamento do namespace do host também estão presentes.

Outro problema frequente é o uso de um **perfil permissivo personalizado** que foi copiado de algum blog ou solução interna sem revisão cuidadosa. Equipes às vezes mantêm quase todos os syscalls perigosos simplesmente porque o perfil foi construído em torno de "impedir que a aplicação quebre" em vez de "conceder apenas o que a aplicação realmente precisa". Uma terceira concepção errada é assumir que seccomp é menos importante para containers não-root. Na realidade, muita superfície de ataque do kernel continua relevante mesmo quando o processo não é UID 0.

## Abuso

Se seccomp está ausente ou gravemente enfraquecido, um atacante pode invocar syscalls de criação de namespaces, expandir a superfície de ataque do kernel alcançável através de `bpf` ou `perf_event_open`, abusar de `keyctl`, ou combinar essas rotas de syscall com capacidades perigosas como `CAP_SYS_ADMIN`. Em muitos ataques reais, seccomp não é o único controle ausente, mas sua ausência encurta dramaticamente o caminho do exploit porque remove uma das poucas defesas que podem bloquear um syscall arriscado antes mesmo do restante do modelo de privilégios entrar em jogo.

O teste prático mais útil é tentar as exatas famílias de syscall que os perfis padrão normalmente bloqueiam. Se elas de repente funcionarem, a postura do container mudou muito:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Se `CAP_SYS_ADMIN` ou outra capability forte estiver presente, teste se seccomp é a única barreira ausente antes do abuso baseado em mount:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Em alguns alvos, o objetivo imediato não é um escape completo, mas sim a coleta de informações e a expansão da superfície de ataque do kernel. Esses comandos ajudam a determinar se caminhos de syscall especialmente sensíveis são alcançáveis:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Se o seccomp estiver ausente e o container também for privilegiado de outras formas, é nesse momento que faz sentido pivotar para as breakout techniques mais específicas já documentadas nas páginas legacy container-escape.

### Exemplo completo: seccomp foi a única coisa bloqueando `unshare`

Em muitos targets, o efeito prático de remover o seccomp é que namespace-creation ou mount syscalls passam a funcionar. Se o container também tiver `CAP_SYS_ADMIN`, a seguinte sequência pode se tornar possível:
```bash
grep Seccomp /proc/self/status
capsh --print | grep cap_sys_admin
mkdir -p /tmp/nsroot
unshare -m sh -c '
mount -t tmpfs tmpfs /tmp/nsroot &&
mkdir -p /tmp/nsroot/proc &&
mount -t proc proc /tmp/nsroot/proc &&
mount | grep /tmp/nsroot
'
```
Por si só isto ainda não é um host escape, mas demonstra que seccomp era a barreira que impedia a exploração relacionada ao mount.

### Exemplo completo: seccomp desabilitado + cgroup v1 `release_agent`

Se seccomp estiver desabilitado e o container puder montar hierarquias cgroup v1, a técnica `release_agent` da seção cgroups torna-se alcançável:
```bash
grep Seccomp /proc/self/status
mount | grep cgroup
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
Isto não é um exploit exclusivo de seccomp. O ponto é que, uma vez que seccomp esteja unconfined, syscall-heavy breakout chains que antes eram bloqueadas podem começar a funcionar exatamente como escritas.

## Checks

O objetivo destas verificações é determinar se o seccomp está ativo, se `no_new_privs` o acompanha, e se a configuração em tempo de execução mostra seccomp sendo explicitamente desabilitado.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
O que é interessante aqui:

- Um valor `Seccomp` diferente de zero significa que o filtro está ativo; `0` geralmente significa ausência de proteção seccomp.
- Se as opções de segurança do runtime incluírem `seccomp=unconfined`, a workload perdeu uma de suas defesas mais úteis ao nível de syscall.
- NoNewPrivs não é seccomp em si, mas ver ambos juntos normalmente indica uma postura de hardening mais cuidadosa do que ver nenhum dos dois.

Se um container já tiver mounts suspeitas, capacidades amplas ou namespaces compartilhados do host, e seccomp também estiver unconfined, essa combinação deve ser tratada como um sinal de escalada importante. O container ainda pode não ser trivialmente explorável, mas o número de pontos de entrada no kernel disponíveis para o atacante aumentou abruptamente.

## Padrões de Runtime

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Geralmente ativado por padrão | Usa o perfil seccomp padrão incorporado do Docker, a menos que seja substituído | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Geralmente ativado por padrão | Aplica o perfil seccomp padrão do runtime, a menos que seja substituído | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Não garantido por padrão** | Se `securityContext.seccompProfile` não estiver definido, o padrão é `Unconfined` a menos que o kubelet habilite `--seccomp-default`; `RuntimeDefault` ou `Localhost` devem ser definidos explicitamente | `securityContext.seccompProfile.type: Unconfined`, deixar seccomp sem definição em clusters sem `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Segue as configurações do nó e do Pod do Kubernetes | O perfil do runtime é usado quando o Kubernetes solicita `RuntimeDefault` ou quando o kubelet tem o default de seccomp habilitado | Mesmo que a linha do Kubernetes; a configuração direta do CRI/OCI também pode omitir seccomp inteiramente |

O comportamento do Kubernetes é o que mais frequentemente surpreende os operadores. Em muitos clusters, seccomp ainda está ausente a menos que o Pod o solicite ou o kubelet esteja configurado para usar `RuntimeDefault` por padrão.
{{#include ../../../../banners/hacktricks-training.md}}
