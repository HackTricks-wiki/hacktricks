# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Visão geral

**seccomp** é o mecanismo que permite ao kernel aplicar um filtro aos syscalls que um processo pode invocar. Em ambientes containerizados, seccomp é normalmente usado em filter mode para que o processo não seja simplesmente marcado como "restricted" de forma vaga, mas sim sujeito a uma política concreta de syscall. Isso importa porque muitas container breakouts requerem alcançar interfaces very specific do kernel. Se o processo não consegue invocar com sucesso os syscalls relevantes, uma grande classe de ataques desaparece antes mesmo que qualquer nuance de namespaces ou capabilities torne-se relevante.

O modelo mental chave é simples: namespaces decidem **o que o processo pode ver**, capabilities decidem **quais ações privilegiadas o processo está nominalmente autorizado a tentar**, e seccomp decide **se o kernel vai sequer aceitar o ponto de entrada do syscall para a ação tentada**. É por isso que seccomp frequentemente previne ataques que, de outra forma, pareceriam possíveis com base apenas nas capabilities.

## Impacto na segurança

Muito da superfície perigosa do kernel é acessível apenas através de um conjunto relativamente pequeno de syscalls. Exemplos que aparecem repetidamente em hardening de container incluem `mount`, `unshare`, `clone` ou `clone3` com flags específicos, `bpf`, `ptrace`, `keyctl`, e `perf_event_open`. Um atacante que consegue alcançar esses syscalls pode ser capaz de criar novos namespaces, manipular subsistemas do kernel, ou interagir com superfície de ataque que um container de aplicação normal não precisa de forma alguma.

É por isso que os runtime seccomp profiles padrão são tão importantes. Eles não são meramente uma "defesa extra". Em muitos ambientes eles fazem a diferença entre um container que pode exercitar uma ampla porção da funcionalidade do kernel e outro que é limitado a uma superfície de syscalls mais próxima do que a aplicação realmente precisa.

## Modos e Construção do Filtro

seccomp historicamente tinha um strict mode no qual apenas um conjunto mínimo de syscalls permanecia disponível, mas o modo relevante para runtimes modernos de container é seccomp filter mode, frequentemente chamado **seccomp-bpf**. Nesse modelo, o kernel avalia um programa de filtro que decide se um syscall deve ser permitido, negado com um errno, aprisionado (trapped), logado, ou que mate o processo. Container runtimes usam esse mecanismo porque ele é suficientemente expressivo para bloquear classes amplas de syscalls perigosos enquanto ainda permite o comportamento normal da aplicação.

Dois exemplos de baixo nível são úteis porque tornam o mecanismo concreto em vez de mágico. Strict mode demonstra o velho modelo de "apenas um conjunto mínimo de syscalls sobrevive":
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
O `open` final faz com que o processo seja terminado porque não faz parte do conjunto mínimo do modo estrito.

Um exemplo de filtro libseccomp mostra o modelo de política moderno de forma mais clara:
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
Este estilo de política é o que a maioria dos leitores deve imaginar quando pensa em runtime seccomp profiles.

## Lab

Uma maneira simples de confirmar que seccomp está ativo em um container é:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Você também pode tentar uma operação que os perfis padrão comumente restringem:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Se o container estiver executando sob um perfil seccomp padrão normal, operações do tipo `unshare` costumam ser bloqueadas. Isto é uma demonstração útil porque mostra que mesmo que a userspace tool exista dentro da imagem, o kernel path de que ela precisa ainda pode estar indisponível.
Se o container estiver executando sob um perfil seccomp padrão normal, operações do tipo `unshare` costumam ser bloqueadas mesmo quando a userspace tool existe dentro da imagem.

Para inspecionar o status do processo de forma mais geral, execute:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Uso em tempo de execução

Docker suporta perfis seccomp padrão e personalizados e permite que administradores os desativem com `--security-opt seccomp=unconfined`. O Podman tem suporte semelhante e frequentemente combina seccomp com execução rootless em uma postura padrão bastante sensata. O Kubernetes expõe seccomp através da configuração de workload, onde `RuntimeDefault` geralmente é a linha de base sensata e `Unconfined` deve ser tratado como uma exceção que requer justificativa em vez de um interruptor de conveniência.

Em ambientes baseados em containerd e CRI-O, o caminho exato é mais estratificado, mas o princípio é o mesmo: o engine de nível superior ou orquestrador decide o que deve acontecer, e o runtime eventualmente instala a política seccomp resultante para o processo do container. O resultado ainda depende da configuração final do runtime que chega ao kernel.

### Exemplo de Política Personalizada

Docker e engines semelhantes podem carregar um perfil seccomp personalizado a partir de JSON. Um exemplo mínimo que nega `chmod` enquanto permite todo o resto é o seguinte:
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
I don't see the file content. Por favor, cole o conteúdo de src/linux-hardening/privilege-escalation/container-security/protections/seccomp.md que você quer que eu traduza, e eu farei a tradução para português seguindo suas instruções.
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
O comando falha com `Operation not permitted`, demonstrando que a restrição vem da política de syscall em vez de apenas das permissões normais de arquivo. No hardening real, allowlists são geralmente mais fortes do que defaults permissivos com uma pequena blacklist.

## Misconfigurations

O erro mais grosseiro é definir seccomp para **unconfined** porque uma aplicação falhou sob a política padrão. Isso é comum durante a solução de problemas e muito perigoso como correção permanente. Uma vez que o filtro desaparece, muitos primitivos de breakout baseados em syscall tornam-se alcançáveis novamente, especialmente quando powerful capabilities ou host namespace sharing também estão presentes.

Outro problema frequente é o uso de um **custom permissive profile** que foi copiado de algum blog ou workaround interno sem ser revisado cuidadosamente. Equipes às vezes mantêm quase todos os syscalls perigosos simplesmente porque o perfil foi construído em torno de "impedir que o app quebre" em vez de "conceder apenas o que o app realmente precisa". Uma terceira concepção equivocada é assumir que seccomp é menos importante para containers não-root. Na realidade, muita superfície de ataque do kernel continua relevante mesmo quando o processo não é UID 0.

## Abuse

Se seccomp estiver ausente ou fortemente enfraquecido, um atacante pode ser capaz de invocar syscalls de criação de namespace, expandir a superfície de ataque do kernel alcançável através de `bpf` ou `perf_event_open`, abusar de `keyctl`, ou combinar esses caminhos de syscall com capacidades perigosas como `CAP_SYS_ADMIN`. Em muitos ataques reais, seccomp não é o único controle ausente, mas sua ausência encurta dramaticamente o caminho do exploit porque remove uma das poucas defesas que podem impedir um syscall arriscado antes que o restante do modelo de privilégios entre em jogo.

O teste prático mais útil é tentar exatamente as famílias de syscall que os perfis padrão geralmente bloqueiam. Se elas passarem a funcionar de repente, a postura do container mudou muito:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Se `CAP_SYS_ADMIN` ou outra forte capability estiver presente, teste se seccomp é a única barreira faltante antes de mount-based abuse:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Em alguns alvos, o objetivo imediato não é escapar completamente, mas sim coletar informações e expandir a superfície de ataque do kernel. Esses comandos ajudam a determinar se caminhos de syscall especialmente sensíveis são alcançáveis:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Se o seccomp estiver ausente e o container também for privilegiado de outras maneiras, é aí que faz sentido pivotar para as técnicas de breakout mais específicas já documentadas nas páginas legadas container-escape.

### Exemplo completo: seccomp era a única coisa impedindo `unshare`

Em muitos alvos, o efeito prático de remover o seccomp é que syscalls de criação de namespace ou de mount começam a funcionar de repente. Se o container também tiver `CAP_SYS_ADMIN`, a seguinte sequência pode se tornar possível:
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
Por si só, isto ainda não é um host escape, mas demonstra que seccomp era a barreira que impedia a exploração relacionada a mount.

### Exemplo completo: seccomp desativado + cgroup v1 `release_agent`

Se seccomp estiver desativado e o container puder montar hierarquias cgroup v1, a técnica `release_agent` da seção cgroups torna-se alcançável:
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
Este não é um exploit apenas de seccomp. A questão é que, uma vez que o seccomp esteja sem restrições, cadeias de breakout com muitas syscalls que antes eram bloqueadas podem começar a funcionar exatamente como foram escritas.

## Verificações

O objetivo dessas verificações é estabelecer se o seccomp está ativo, se `no_new_privs` o acompanha, e se a configuração em tempo de execução mostra o seccomp sendo desativado explicitamente.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
O que é interessante aqui:

- Um valor de `Seccomp` diferente de zero significa que o filtro está ativo; `0` geralmente significa nenhuma proteção seccomp.
- Se as opções de segurança do runtime incluírem `seccomp=unconfined`, a workload perdeu uma de suas defesas em nível de syscall mais úteis.
- NoNewPrivs não é o seccomp em si, mas ver ambos juntos geralmente indica uma postura de hardening mais cuidadosa do que ver nenhum dos dois.

Se um container já tem mounts suspeitos, capabilities amplas, ou shared host namespaces, e seccomp também estiver unconfined, essa combinação deve ser tratada como um sinal de escalada grave. O container ainda pode não ser trivialmente comprometido, mas o número de pontos de entrada do kernel disponíveis ao atacante aumentou drasticamente.

## Padrões do Runtime

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Geralmente ativado por padrão | Usa o perfil seccomp padrão embutido do Docker, a menos que seja sobrescrito | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Geralmente ativado por padrão | Aplica o perfil seccomp padrão do runtime, a menos que seja sobrescrito | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Não garantido por padrão** | Se `securityContext.seccompProfile` não estiver definido, o padrão é `Unconfined` a menos que o kubelet habilite `--seccomp-default`; `RuntimeDefault` ou `Localhost` devem ser definidos explicitamente caso contrário | `securityContext.seccompProfile.type: Unconfined`, deixar seccomp não definido em clusters sem `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Segue as configurações de node e Pod do Kubernetes | O perfil do runtime é usado quando o Kubernetes solicita `RuntimeDefault` ou quando o kubelet habilita o default de seccomp | Mesmo que a linha do Kubernetes; configuração direta do CRI/OCI também pode omitir seccomp inteiramente |

O comportamento do Kubernetes é o que mais frequentemente surpreende os operadores. Em muitos clusters, seccomp ainda está ausente a menos que o Pod o solicite ou o kubelet esteja configurado para usar `RuntimeDefault` como padrão.
