# Namespace de Usuário

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O namespace de usuário altera o significado dos IDs de usuário e grupo ao permitir que o kernel mapeie IDs vistos dentro do namespace para IDs diferentes fora dele. Esta é uma das proteções de container modernas mais importantes porque aborda diretamente o maior problema histórico dos containers clássicos: **o root dentro do container costumava estar desconfortavelmente próximo do root no host**.

Com namespaces de usuário, um processo pode ser executado como UID 0 dentro do container e ainda corresponder a um intervalo de UID sem privilégios no host. Isso significa que o processo pode agir como root para muitas tarefas dentro do container, enquanto é muito menos poderoso do ponto de vista do host. Isso não resolve todos os problemas de segurança de containers, mas altera significativamente as consequências de uma compromissão do container.

## Operação

Um namespace de usuário possui arquivos de mapeamento como `/proc/self/uid_map` e `/proc/self/gid_map` que descrevem como os IDs do namespace são traduzidos para IDs do pai. Se o root dentro do namespace for mapeado para um UID sem privilégios no host, então operações que exigiriam o verdadeiro root do host simplesmente não têm o mesmo peso. É por isso que namespaces de usuário são centrais para **containers sem root** e por que eles são uma das maiores diferenças entre as configurações padrão antigas que usavam root em containers e designs modernos de menor privilégio.

O ponto é sutil mas crucial: o root dentro do container não é eliminado, ele é **traduzido**. O processo ainda experimenta um ambiente semelhante ao root localmente, mas o host não deve tratá-lo como root completo.

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
A saída exata depende de o engine estar usando remapeamento do namespace de usuário ou uma configuração rootful mais tradicional.

Você também pode ler o mapeamento do lado do host com:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Uso em Tempo de Execução

Rootless Podman é um dos exemplos mais claros de namespaces de usuário sendo tratados como um mecanismo de segurança de primeira classe. Rootless Docker também depende deles. O suporte userns-remap do Docker melhora a segurança em implantações com daemon rootful também, embora historicamente muitas implantações o deixassem desabilitado por razões de compatibilidade. O suporte do Kubernetes a user namespaces melhorou, mas a adoção e os padrões variam conforme o runtime, a distro e a política do cluster. Sistemas Incus/LXC também dependem fortemente das ideias de deslocamento UID/GID e idmapping.

A tendência geral é clara: ambientes que usam user namespaces de forma séria geralmente oferecem uma resposta melhor para "o que o root do container realmente significa?" do que ambientes que não os utilizam.

## Detalhes Avançados de Mapeamento

Quando um processo não privilegiado grava em `uid_map` ou `gid_map`, o kernel aplica regras mais rígidas do que para um escritor privilegiado no namespace pai. Apenas mapeamentos limitados são permitidos, e para `gid_map` o escritor normalmente precisa desabilitar `setgroups(2)` primeiro:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Esse detalhe importa porque explica por que a configuração de user-namespace às vezes falha em experimentos rootless e por que runtimes precisam de lógica auxiliar cuidadosa em torno da delegação de UID/GID.

Another advanced feature is the **ID-mapped mount**. Em vez de alterar a propriedade no disco, um ID-mapped mount aplica um mapeamento de user-namespace a um mount de forma que a propriedade aparece traduzida através dessa visão do mount. Isso é especialmente relevante em setups rootless e runtimes modernos porque permite que caminhos compartilhados do host sejam usados sem operações recursivas de `chown`. Em termos de segurança, a funcionalidade muda como um bind mount aparece como gravável de dentro do namespace, mesmo que não reescreva os metadados do sistema de arquivos subjacente.

Por fim, lembre-se que quando um processo cria ou entra em um novo user namespace, ele recebe um conjunto completo de capabilities **dentro desse namespace**. Isso não significa que ele de repente ganhou poder global no host. Significa que essas capabilities podem ser usadas apenas onde o modelo de namespace e outras proteções as permitirem. É por isso que `unshare -U` pode subitamente tornar possíveis operações privilegiadas de montagem ou locais ao namespace sem, diretamente, fazer o limite root do host desaparecer.

## Misconfigurations

A principal fraqueza é simplesmente não usar user namespaces em ambientes onde eles seriam viáveis. Se o root do container mapeia muito diretamente para o root do host, host mounts graváveis e operações privilegiadas do kernel se tornam muito mais perigosas. Outro problema é forçar o compartilhamento do user namespace do host ou desabilitar o remapping por compatibilidade sem reconhecer quanto isso altera a fronteira de confiança.

User namespaces também precisam ser considerados em conjunto com o restante do modelo. Mesmo quando estão ativos, uma ampla exposição da runtime API ou uma configuração de runtime muito fraca ainda pode permitir escalada de privilégios por outros caminhos. Mas sem eles, muitas classes antigas de breakout tornam-se muito mais fáceis de explorar.

## Abuse

Se o container é rootful sem separação de user namespace, um bind mount host gravável torna-se muito mais perigoso porque o processo pode realmente estar escrevendo como root do host. Capabilities perigosas, igualmente, tornam-se mais significativas. O atacante não precisa mais lutar tanto contra a fronteira de tradução porque essa fronteira praticamente não existe.

A presença ou ausência de user namespace deve ser verificada cedo ao avaliar um caminho de container breakout. Isso não responde a todas as perguntas, mas mostra imediatamente se "root in container" tem relevância direta para o host.

O padrão de abuso mais prático é confirmar o mapeamento e então testar imediatamente se o conteúdo montado do host é gravável com privilégios relevantes ao host:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Se o arquivo for criado como root real do host, o isolamento do user namespace é efetivamente ausente para esse caminho. A partir desse ponto, abusos clássicos de arquivos do host tornam-se realistas:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Uma confirmação mais segura durante uma avaliação ao vivo é escrever um marcador benigno em vez de modificar arquivos críticos:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Essas verificações importam porque respondem rapidamente à pergunta real: does root in this container map closely enough to host root that a writable host mount immediately becomes a host compromise path?

### Exemplo Completo: Recuperando Namespace-Local Capabilities

Se seccomp permite `unshare` e o ambiente permite um novo user namespace, o processo pode recuperar um conjunto completo de capabilities dentro desse novo namespace:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Isso, por si só, não é um host escape. A razão pela qual isto importa é que user namespaces podem reativar ações privilegiadas namespace-local que depois se combinam com weak mounts, vulnerable kernels ou runtime surfaces mal expostas.

## Verificações

Esses comandos têm como objetivo responder à pergunta mais importante desta página: a que corresponde 'root' dentro deste container no host?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
O que é interessante aqui:

- Se o processo for UID 0 e os maps mostrarem um host-root mapping direto ou muito próximo, o container é muito mais perigoso.
- Se root mapear para uma faixa de host sem privilégios, isso é uma linha de base muito mais segura e geralmente indica verdadeira user namespace isolation.
- Os mapping files são mais valiosos do que `id` sozinho, porque `id` só mostra a namespace-local identity.

Se o workload rodar como UID 0 e o mapeamento mostrar que isso corresponde de perto ao host root, você deve interpretar o restante dos privilégios do container de forma muito mais rígida.
{{#include ../../../../../banners/hacktricks-training.md}}
