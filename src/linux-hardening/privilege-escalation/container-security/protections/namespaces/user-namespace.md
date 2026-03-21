# Namespace de Usuário

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O namespace de usuário altera o significado de IDs de usuário e grupo ao permitir que o kernel mapeie IDs vistos dentro do namespace para IDs diferentes fora dele. Esta é uma das proteções modernas mais importantes para containers porque aborda diretamente o maior problema histórico dos containers clássicos: **o root dentro do container costumava estar desconfortavelmente próximo do root no host**.

Com namespaces de usuário, um processo pode rodar como UID 0 dentro do container e ainda corresponder a uma faixa de UID sem privilégios no host. Isso significa que o processo pode se comportar como root para muitas tarefas dentro do container, ao mesmo tempo em que é muito menos poderoso do ponto de vista do host. Isso não resolve todos os problemas de segurança de containers, mas altera significativamente as consequências de uma compromissão do container.

## Operação

Um namespace de usuário possui arquivos de mapeamento como `/proc/self/uid_map` e `/proc/self/gid_map` que descrevem como IDs do namespace são traduzidos para IDs do pai. Se o root dentro do namespace mapear para um UID sem privilégios no host, então operações que exigiriam root real no host simplesmente não têm o mesmo peso. É por isso que namespaces de usuário são centrais para **rootless containers** e por que são uma das maiores diferenças entre os padrões antigos de containers com root e designs modernos de menor privilégio.

O ponto é sutil mas crucial: o root dentro do container não é eliminado, ele é **traduzido**. O processo ainda experimenta um ambiente semelhante ao root localmente, mas o host não deve tratá‑lo como root completo.

## Laboratório

Um teste manual é:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Isso faz com que o usuário atual apareça como root dentro do namespace, enquanto fora dele ele continua a não ser root do host. É uma das melhores demonstrações simples para entender por que os user namespaces são tão valiosos.

Em containers, você pode comparar o mapeamento visível com:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
A saída exata depende de o engine estar usando user namespace remapping ou de uma configuração rootful mais tradicional.

Você também pode ler o mapeamento do lado do host com:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Uso em tempo de execução

Rootless Podman é um dos exemplos mais claros de namespaces de usuário sendo tratados como um mecanismo de segurança de primeira classe. Rootless Docker também depende deles. O suporte do Docker a userns-remap melhora a segurança em implantações de daemon rootful também, embora historicamente muitas implantações o deixassem desabilitado por razões de compatibilidade. O suporte do Kubernetes a namespaces de usuário melhorou, mas a adoção e os padrões variam por runtime, distro e política do cluster. Sistemas Incus/LXC também dependem fortemente de UID/GID shifting e ideias de idmapping.

A tendência geral é clara: ambientes que usam namespaces de usuário de forma séria geralmente oferecem uma resposta melhor para "o que o root do container realmente significa?" do que ambientes que não o fazem.

## Detalhes Avançados de Mapeamento

Quando um processo não privilegiado escreve em `uid_map` ou `gid_map`, o kernel aplica regras mais restritivas do que aplica para um escritor privilegiado do namespace pai. Apenas mapeamentos limitados são permitidos, e para `gid_map` o escritor geralmente precisa desabilitar `setgroups(2)` primeiro:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Isso importa porque explica por que a configuração de namespace de usuário às vezes falha em experimentos rootless e por que runtimes precisam de lógica auxiliar cuidadosa em torno da delegação de UID/GID.

Outra funcionalidade avançada é o **ID-mapped mount**. Em vez de alterar a propriedade no disco, um ID-mapped mount aplica um mapeamento de namespace de usuário a um mount de forma que a propriedade apareça traduzida nessa visão do mount. Isso é especialmente relevante em setups rootless e runtimes modernos porque permite que caminhos compartilhados do host sejam usados sem operações recursivas de `chown`. Em termos de segurança, a funcionalidade muda como um bind mount aparece como gravável dentro do namespace, embora não reescreva os metadados do sistema de arquivos subjacente.

Finalmente, lembre-se de que quando um processo cria ou entra em um novo namespace de usuário, ele recebe um conjunto completo de capabilities **dentro desse namespace**. Isso não significa que subitamente ganhou poder global no host. Significa que essas capabilities podem ser usadas apenas onde o modelo de namespace e outras proteções as permitirem. Esta é a razão pela qual `unshare -U` pode subitamente tornar montagem ou operações privilegiadas locais ao namespace possíveis sem eliminar diretamente a fronteira root do host.

## Misconfigurations

A principal fraqueza é simplesmente não usar namespaces de usuário em ambientes onde eles seriam viáveis. Se o root do container mapeia muito diretamente para o root do host, mounts graváveis do host e operações privilegiadas do kernel tornam-se muito mais perigosas. Outro problema é forçar o compartilhamento do namespace de usuário do host ou desabilitar o remapeamento por compatibilidade sem reconhecer quanto isso altera a fronteira de confiança.

Namespaces de usuário também precisam ser considerados em conjunto com o resto do modelo. Mesmo quando estão ativos, uma exposição ampla da API do runtime ou uma configuração de runtime muito fraca ainda pode permitir escalada de privilégios por outros caminhos. Mas sem eles, muitas classes antigas de breakout tornam-se muito mais fáceis de explorar.

## Abuse

Se o container for rootful sem separação de namespace de usuário, um bind mount gravável do host torna-se muito mais perigoso porque o processo pode realmente estar escrevendo como root do host. Capabilities perigosas igualmente ganham mais significado. O atacante não precisa mais lutar tanto contra a fronteira de tradução porque essa fronteira praticamente não existe.

A presença ou ausência do namespace de usuário deve ser verificada cedo ao avaliar um caminho de breakout de container. Isso não responde a todas as perguntas, mas mostra imediatamente se "root in container" tem relevância direta para o host.

O padrão de abuso mais prático é confirmar o mapeamento e então testar imediatamente se o conteúdo montado do host é gravável com privilégios relevantes para o host:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Se o arquivo for criado como real host root, a user namespace isolation fica efetivamente ausente para esse caminho. Nesse ponto, abusos clássicos de host-file tornam-se realistas:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Uma confirmação mais segura durante uma avaliação ao vivo é escrever um marcador benigno em vez de modificar arquivos críticos:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Essas verificações importam porque respondem rapidamente à pergunta real: o root neste container mapeia-se suficientemente próximo do host root para que um host mount com permissão de escrita se torne imediatamente um caminho de comprometimento do host?

### Exemplo Completo: Recuperando Namespace-Local Capabilities

Se seccomp permite `unshare` e o ambiente permite um novo user namespace, o processo pode recuperar um conjunto completo de capabilities dentro desse novo namespace:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Isto, por si só, não é um host escape. A razão pela qual isto importa é que user namespaces podem reativar ações privilegiadas locais ao namespace que depois se combinam com pontos de montagem fracos, kernels vulneráveis ou superfícies de runtime mal expostas.

## Checks

Estes comandos destinam-se a responder à pergunta mais importante desta página: a quem o root dentro deste container corresponde no host?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
- Se o processo for UID 0 e os mapas mostrarem um host-root mapping direto ou muito próximo, o container é muito mais perigoso.
- Se root mapeia para um unprivileged host range, isso é uma linha de base muito mais segura e normalmente indica uma real user namespace isolation.
- Os mapping files são mais valiosos do que `id` sozinho, porque `id` mostra apenas a identidade namespace-local.

Se o workload roda como UID 0 e o mapping mostra que isso corresponde de perto ao host root, você deve interpretar o restante dos privilégios do container de forma muito mais estrita.
