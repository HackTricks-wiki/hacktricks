# Namespace de Usuário

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O namespace de usuário altera o significado dos IDs de usuário e grupo ao permitir que o kernel mapeie os IDs vistos dentro do namespace para IDs diferentes fora dele. Essa é uma das proteções modernas mais importantes para containers, pois aborda diretamente o maior problema histórico dos containers clássicos: **root dentro do container costumava estar desconfortavelmente próximo de root no host**.

Com user namespaces, um processo pode ser executado como UID 0 dentro do container e ainda corresponder a um intervalo de UIDs não privilegiados no host. Isso significa que o processo pode se comportar como root em muitas tarefas dentro do container, sendo, ao mesmo tempo, muito menos poderoso do ponto de vista do host. Isso não resolve todos os problemas de segurança de containers, mas altera significativamente as consequências de um comprometimento do container.

## Operação

Um user namespace possui arquivos de mapeamento como `/proc/self/uid_map` e `/proc/self/gid_map`, que descrevem como os IDs do namespace são traduzidos para os IDs do namespace pai. Se root dentro do namespace for mapeado para um UID não privilegiado do host, as operações que exigiriam root real no host simplesmente não terão o mesmo peso. É por isso que user namespaces são fundamentais para **rootless containers** e representam uma das maiores diferenças entre os padrões mais antigos de containers rootful e os designs modernos de least privilege.

O ponto é sutil, mas crucial: root dentro do container não é eliminado, ele é **traduzido**. O processo ainda vivencia localmente um ambiente semelhante ao de root, mas o host não deve tratá-lo como root completo.

## Lab

Um teste manual é:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Isso faz com que o usuário atual apareça como root dentro do namespace, embora ainda não seja root no host fora dele. É uma das melhores demonstrações simples para entender por que os user namespaces são tão valiosos.

Em containers, você pode comparar o mapeamento visível com:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
A saída exata depende de o engine estar usando user namespace remapping ou uma configuração rootful mais tradicional.

Você também pode ler o mapeamento pelo lado do host com:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Uso em Runtime

Rootless Podman é um dos exemplos mais claros de namespaces de usuário sendo tratados como um mecanismo de segurança de primeira classe. Rootless Docker também depende deles. O suporte do Docker a userns-remap também melhora a segurança em implantações com daemon rootful, embora, historicamente, muitas implantações o tenham deixado desabilitado por motivos de compatibilidade. O suporte do Kubernetes a namespaces de usuário melhorou, mas a adoção e os padrões variam conforme o runtime, a distro e a política do cluster. Os sistemas Incus/LXC também dependem bastante de shifting de UID/GID e de conceitos de idmapping.

A tendência geral é clara: ambientes que usam namespaces de usuário de forma séria geralmente oferecem uma resposta melhor à pergunta "o que o root do container realmente significa?" do que ambientes que não os utilizam.

## Detalhes Avançados de Mapeamento

Quando um processo sem privilégios escreve em `uid_map` ou `gid_map`, o kernel aplica regras mais rigorosas do que as aplicadas a um processo escritor privilegiado do namespace pai. Apenas mapeamentos limitados são permitidos e, para `gid_map`, o processo escritor geralmente precisa desabilitar `setgroups(2)` primeiro:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Esse detalhe é importante porque explica por que a configuração de user namespaces às vezes falha em experimentos rootless e por que os runtimes precisam de uma lógica auxiliar cuidadosa em torno da delegação de UID/GID.

Outro recurso avançado é o **ID-mapped mount**. Em vez de alterar a propriedade no disco, um ID-mapped mount aplica um mapeamento de user namespace a um mount, fazendo com que a propriedade apareça traduzida por meio dessa visualização do mount. Isso é especialmente relevante em configurações rootless e em runtimes modernos, pois permite usar caminhos compartilhados do host sem operações recursivas de `chown`. Do ponto de vista de segurança, o recurso altera o quanto um bind mount parece ser gravável de dentro do namespace, embora não reescreva os metadados subjacentes do filesystem.

Por fim, lembre-se de que, quando um processo cria ou entra em um novo user namespace, ele recebe um conjunto completo de capabilities **dentro desse namespace**. Isso não significa que ele tenha subitamente obtido poder global sobre o host. Significa que essas capabilities só podem ser usadas onde o modelo de namespaces e as demais proteções permitirem. Esse é o motivo pelo qual `unshare -U` pode tornar possíveis operações de montagem ou operações privilegiadas locais ao namespace sem fazer diretamente desaparecer o limite do root do host.

## Configurações incorretas

A principal fraqueza é simplesmente não usar user namespaces em ambientes onde isso seria viável. Se o root do container for mapeado de forma muito direta para o root do host, mounts graváveis do host e operações privilegiadas do kernel se tornam muito mais perigosos. Outro problema é forçar o compartilhamento do user namespace do host ou desabilitar o remapping por compatibilidade sem reconhecer o quanto isso altera o limite de confiança.

Os user namespaces também precisam ser considerados em conjunto com o restante do modelo. Mesmo quando estão ativos, uma ampla exposição da API do runtime ou uma configuração muito fraca do runtime ainda pode permitir privilege escalation por outros caminhos. Porém, sem eles, muitas classes antigas de breakout se tornam muito mais fáceis de explorar.

## Abuso

Se o container for rootful sem separação por user namespace, um bind mount gravável do host se torna muito mais perigoso porque o processo pode realmente estar escrevendo como root do host. Da mesma forma, capabilities perigosas se tornam mais relevantes. O atacante não precisa mais lutar tanto contra o limite de tradução, pois esse limite praticamente não existe.

A presença ou ausência de user namespaces deve ser verificada no início da avaliação de um caminho de breakout de container. Isso não responde a todas as perguntas, mas mostra imediatamente se o "root no container" tem relevância direta para o host.

O padrão de abuso mais prático é confirmar o mapeamento e, em seguida, testar imediatamente se o conteúdo montado do host pode ser gravado com privilégios relevantes para o host:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Se o arquivo for criado como root real do host, o isolamento do user namespace estará efetivamente ausente para esse caminho. Nesse ponto, abusos clássicos de arquivos do host tornam-se viáveis:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Uma confirmação mais segura durante uma avaliação em andamento é gravar um marcador inofensivo em vez de modificar arquivos críticos:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Essas verificações são importantes porque respondem rapidamente à pergunta real: o root neste container corresponde de forma suficientemente próxima ao root do host para que um mount do host com permissão de escrita se torne imediatamente um caminho para comprometer o host?

### Exemplo Completo: Recuperando Capabilities Locais do Namespace

Se o seccomp permitir `unshare` e o ambiente permitir um novo user namespace, o processo poderá recuperar um conjunto completo de capabilities dentro desse novo namespace:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Isso, por si só, não é um host escape. O motivo pelo qual isso importa é que user namespaces podem reativar ações privilegiadas locais ao namespace, que posteriormente se combinam com mounts fracos, kernels vulneráveis ou superfícies de runtime mal expostas.

## Verificações

Estes comandos devem responder à pergunta mais importante desta página: para qual identidade root dentro deste container é mapeado no host?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
O que é interessante aqui:

- Se o processo tiver UID 0 e os maps mostrarem um mapeamento direto ou muito próximo do root do host, o container será muito mais perigoso.
- Se o root for mapeado para um intervalo não privilegiado do host, essa será uma baseline muito mais segura e geralmente indicará um isolamento real por user namespace.
- Os arquivos de mapeamento são mais valiosos do que `id` isoladamente, porque `id` mostra apenas a identidade local do namespace.

Se o workload for executado como UID 0 e o mapeamento mostrar que isso corresponde aproximadamente ao root do host, você deverá interpretar os demais privilégios do container de forma muito mais rigorosa.
{{#include ../../../../../banners/hacktricks-training.md}}
