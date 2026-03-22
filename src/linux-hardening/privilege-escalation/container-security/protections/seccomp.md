# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Visão Geral

**seccomp** é o mecanismo que permite ao kernel aplicar um filtro aos syscalls que um processo pode invocar. Em ambientes containerizados, seccomp é normalmente usado no modo de filtro para que o processo não seja simplesmente marcado como "restricted" de forma vaga, mas sim sujeito a uma política concreta de syscalls. Isso importa porque muitos container breakouts exigem acesso a interfaces muito específicas do kernel. Se o processo não puder invocar com sucesso os syscalls relevantes, uma grande classe de ataques desaparece antes que qualquer nuance de namespaces ou capabilities se torne relevante.

O modelo mental chave é simples: namespaces decidem **o que o processo pode ver**, capabilities decidem **quais ações privilegiadas o processo está, nominalmente, autorizado a tentar**, e seccomp decide **se o kernel vai mesmo aceitar o ponto de entrada do syscall para a ação tentada**. Por isso seccomp frequentemente previne ataques que, de outra forma, pareceriam possíveis com base apenas nas capabilities.

## Impacto na Segurança

Muita superfície perigosa do kernel é acessível apenas através de um conjunto relativamente pequeno de syscalls. Exemplos que são repetidamente relevantes no hardening de containers incluem `mount`, `unshare`, `clone` or `clone3` com flags específicos, `bpf`, `ptrace`, `keyctl`, e `perf_event_open`. Um atacante que conseguir acessar esses syscalls pode ser capaz de criar novos namespaces, manipular subsistemas do kernel, ou interagir com superfícies de ataque que um container de aplicação normal não precisa de forma alguma.

É por isso que os perfis seccomp padrão do runtime são tão importantes. Eles não são meramente "extra defense". Em muitos ambientes eles representam a diferença entre um container que pode exercer uma ampla porção da funcionalidade do kernel e outro que está restrito a uma superfície de syscalls mais próxima do que a aplicação realmente precisa.

## Modos e Construção do Filtro

seccomp historicamente tinha um modo strict no qual apenas um conjunto mínimo de syscalls permanecia disponível, mas o modo relevante para runtimes de container modernos é o modo de filtro do seccomp, frequentemente chamado **seccomp-bpf**. Nesse modelo, o kernel avalia um programa de filtro que decide se um syscall deve ser permitido, negado com um errno, trapped, logado, ou que mate o processo. Container runtimes usam esse mecanismo porque ele é expressivo o suficiente para bloquear amplas classes de syscalls perigosos enquanto ainda permite o comportamento normal da aplicação.

Dois exemplos em baixo nível são úteis porque tornam o mecanismo concreto em vez de mágico. O modo strict demonstra o antigo "only a minimal syscall set survives" model:
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
O `open` final faz com que o processo seja encerrado porque não faz parte do conjunto mínimo do strict mode.

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
Este estilo de política é o que a maioria dos leitores deve imaginar quando pensa em perfis seccomp em tempo de execução.

## Laboratório

Uma maneira simples de confirmar que o seccomp está ativo em um contêiner é:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Você também pode tentar uma operação que os perfis padrão normalmente restringem:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Se o container estiver a correr sob um perfil seccomp padrão normal, operações do tipo `unshare` são frequentemente bloqueadas. Isto é uma demonstração útil porque mostra que, mesmo que a ferramenta userspace exista dentro da imagem, o caminho do kernel de que ela precisa pode ainda estar indisponível.
Se o container estiver a correr sob um perfil seccomp padrão normal, operações do tipo `unshare` são frequentemente bloqueadas mesmo quando a ferramenta userspace existe dentro da imagem.

Para inspecionar o status do processo de forma mais geral, execute:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Uso em tempo de execução

Docker suporta tanto perfis seccomp padrão quanto personalizados e permite que administradores os desabilitem com `--security-opt seccomp=unconfined`. Podman tem suporte similar e frequentemente combina seccomp com execução sem root em uma postura padrão muito sensata. Kubernetes expõe seccomp através da configuração de workload, onde `RuntimeDefault` é geralmente a linha de base sensata e `Unconfined` deve ser tratado como uma exceção que requer justificativa em vez de um alternador de conveniência.

Em ambientes baseados em containerd e CRI-O, o caminho exato é mais em camadas, mas o princípio é o mesmo: o mecanismo de nível superior ou orquestrador decide o que deve acontecer, e o runtime eventualmente instala a política seccomp resultante para o processo do container. O resultado ainda depende da configuração final do runtime que chega ao kernel.

### Exemplo de política personalizada

Docker e mecanismos similares podem carregar um perfil seccomp personalizado a partir de JSON. Um exemplo mínimo que nega `chmod` enquanto permite todo o resto fica assim:
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
O comando falha com `Operation not permitted`, demonstrando que a restrição vem da política de syscalls em vez das permissões ordinárias de arquivo sozinhas. Em hardening real, listas de permissão geralmente são mais fortes do que padrões permissivos com uma pequena lista negra.

## Configurações incorretas

O erro mais bruto é definir seccomp como **unconfined** porque uma aplicação falhou sob a política padrão. Isso é comum durante solução de problemas e muito perigoso como correção permanente. Uma vez que o filtro desaparece, muitas breakout primitives baseadas em syscall tornam-se alcançáveis novamente, especialmente quando capabilities poderosas ou compartilhamento do namespace do host também estão presentes.

Outro problema frequente é o uso de um **perfil permissivo personalizado** que foi copiado de algum blog ou solução interna sem revisão cuidadosa. Equipes às vezes mantêm quase todos os syscalls perigosos simplesmente porque o perfil foi construído em torno de "impedir que a aplicação quebre" em vez de "conceder apenas o que a aplicação realmente precisa". Uma terceira concepção errada é supor que seccomp é menos importante para contêineres não-root. Na realidade, muita superfície de ataque do kernel continua relevante mesmo quando o processo não é UID 0.

## Abuso

Se seccomp estiver ausente ou muito enfraquecido, um atacante pode conseguir invocar syscalls de criação de namespace, expandir a superfície de ataque do kernel alcançável através de `bpf` ou `perf_event_open`, abusar de `keyctl`, ou combinar esses caminhos de syscall com capabilities perigosas como `CAP_SYS_ADMIN`. Em muitos ataques reais, seccomp não é o único controle ausente, mas sua ausência encurta dramaticamente o caminho do exploit porque remove uma das poucas defesas que podem impedir uma syscall arriscada antes mesmo do resto do modelo de privilégios entrar em jogo.

O teste prático mais útil é tentar as exatas famílias de syscall que os perfis padrão normalmente bloqueiam. Se elas funcionarem de repente, a postura do contêiner mudou muito:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Se `CAP_SYS_ADMIN` ou outra strong capability estiver presente, teste se seccomp é a única barreira faltando antes do mount-based abuse:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Em alguns alvos, o valor imediato não é um escape completo, mas coleta de informações e expansão da superfície de ataque do kernel. Esses comandos ajudam a determinar se caminhos de syscall especialmente sensíveis são alcançáveis:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Se o seccomp estiver ausente e o container também for privilegiado de outras maneiras, é nesse momento que faz sentido pivotar para as técnicas de breakout mais específicas já documentadas nas páginas legacy container-escape.

### Exemplo completo: seccomp era a única coisa bloqueando `unshare`

Em muitos targets, o efeito prático de remover seccomp é que a criação de namespaces ou syscalls de mount de repente começam a funcionar. Se o container também tiver `CAP_SYS_ADMIN`, a sequência a seguir pode se tornar possível:
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
Por si só, isto ainda não é um host escape, mas demonstra que o seccomp era a barreira que impedia explorações relacionadas a mount.

### Exemplo completo: seccomp desativado + cgroup v1 `release_agent`

Se o seccomp estiver desativado e o container puder montar hierarquias cgroup v1, a técnica `release_agent` da seção cgroups torna-se atingível:
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
Este não é um exploit apenas de seccomp. A ideia é que, uma vez que o seccomp esteja unconfined, syscall-heavy breakout chains que antes eram bloqueadas podem começar a funcionar exatamente como escritas.

## Checks

O objetivo destas verificações é estabelecer se o seccomp está ativo, se `no_new_privs` o acompanha, e se a configuração do runtime mostra o seccomp sendo explicitamente desativado.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
What is interesting here:

- Um valor de `Seccomp` diferente de zero significa que o filtro está ativo; `0` normalmente indica ausência de proteção seccomp.
- Se as opções de segurança do runtime incluem `seccomp=unconfined`, a carga de trabalho perdeu uma das suas defesas mais úteis a nível de syscall.
- `NoNewPrivs` não é seccomp em si, mas ver ambos juntos normalmente indica uma postura de hardening mais cuidadosa do que ver nenhum.

Se um container já tem mounts suspeitos, capacidades amplas, ou namespaces do host compartilhados, e o seccomp também está unconfined, essa combinação deve ser tratada como um forte sinal de escalada. O container pode ainda não ser trivialmente comprometível, mas o número de pontos de entrada do kernel disponíveis ao atacante aumentou acentuadamente.

## Runtime Defaults

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Geralmente ativado por padrão | Usa o perfil seccomp padrão embutido do Docker, a menos que seja substituído | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Geralmente ativado por padrão | Aplica o perfil seccomp padrão do runtime, a menos que seja substituído | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Não garantido por padrão** | Se `securityContext.seccompProfile` não estiver definido, o padrão é `Unconfined` a menos que o kubelet habilite `--seccomp-default`; `RuntimeDefault` ou `Localhost` devem ser configurados explicitamente caso contrário | `securityContext.seccompProfile.type: Unconfined`, deixar o seccomp não definido em clusters sem `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Segue as configurações do nó e dos Pods do Kubernetes | O perfil do runtime é usado quando o Kubernetes solicita `RuntimeDefault` ou quando o kubelet habilita a padronização de seccomp | Mesmo que a linha do Kubernetes; a configuração direta do CRI/OCI também pode omitir seccomp completamente |

O comportamento do Kubernetes é o que mais frequentemente surpreende os operadores. Em muitos clusters, o seccomp ainda está ausente a menos que o Pod o solicite ou o kubelet esteja configurado para usar `RuntimeDefault` por padrão.
{{#include ../../../../banners/hacktricks-training.md}}
