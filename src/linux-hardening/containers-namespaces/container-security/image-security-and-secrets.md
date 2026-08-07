# Segurança, Assinatura E Secrets De Imagens

{{#include ../../../banners/hacktricks-training.md}}

## Registries De Imagens E Confiança

A segurança de containers começa antes de o workload ser iniciado. A imagem determina quais binários, interpretadores, bibliotecas, scripts de inicialização e configurações incorporadas chegam à produção. Se a imagem tiver um backdoor, estiver desatualizada ou for criada com secrets embutidos, o hardening do runtime realizado posteriormente já estará operando sobre um artefato comprometido.

É por isso que a procedência da imagem, a verificação de vulnerabilidades, a verificação de assinaturas e o tratamento de secrets fazem parte da mesma conversa que namespaces e seccomp. Eles protegem uma fase diferente do ciclo de vida, mas as falhas nessa etapa frequentemente definem a attack surface que o runtime posteriormente terá de conter.

## Registries De Imagens E Confiança

As imagens podem vir de registries públicos, como o Docker Hub, ou de registries privados operados por uma organização. A questão de segurança não é simplesmente onde a imagem está armazenada, mas se a equipe consegue estabelecer sua procedência e integridade. Fazer pull de imagens sem assinatura ou com rastreamento inadequado a partir de fontes públicas aumenta o risco de conteúdo malicioso ou adulterado entrar na produção. Mesmo os registries hospedados internamente precisam de propriedade, revisão e uma política de confiança claramente definidos.

O Docker Content Trust historicamente usava conceitos do Notary e do TUF para exigir imagens assinadas. O ecossistema exato evoluiu, mas a lição permanente continua útil: a identidade e a integridade da imagem devem ser verificáveis, em vez de presumidas.

Exemplo histórico de fluxo de trabalho do Docker Content Trust:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
O objetivo do exemplo não é afirmar que toda equipe ainda deve usar as mesmas ferramentas, mas sim que signing e key management são tarefas operacionais, não teoria abstrata.

## Scanning de Vulnerabilidades

O scanning de images ajuda a responder a duas perguntas diferentes. Primeiro, a image contém packages ou libraries vulneráveis conhecidos? Segundo, a image inclui software desnecessário que amplia a superfície de ataque? Uma image repleta de debugging tools, shells, interpreters e packages obsoletos é mais fácil de explorar e mais difícil de analisar.

Exemplos de scanners usados com frequência incluem:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Os resultados dessas ferramentas devem ser interpretados com cuidado. Uma vulnerabilidade em um package não utilizado não apresenta o mesmo risco que um caminho de RCE exposto, mas ambos ainda são relevantes para decisões de hardening.

## Secrets em Tempo de Build

Um dos erros mais antigos em pipelines de build de containers é incorporar secrets diretamente na imagem ou passá-los por meio de variáveis de ambiente que posteriormente ficam visíveis através de `docker inspect`, logs de build ou camadas recuperadas. Os secrets de build devem ser montados de forma efêmera durante o build, em vez de serem copiados para o filesystem da imagem.

O BuildKit aprimorou esse modelo ao permitir o gerenciamento dedicado de secrets em tempo de build. Em vez de gravar um secret em uma camada, a etapa de build pode consumi-lo temporariamente:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Isso é importante porque as camadas da imagem são artefatos duráveis. Quando um secret entra em uma camada commitada, excluir posteriormente o arquivo em outra camada não remove verdadeiramente a divulgação original do histórico da imagem.

## Secrets em Runtime

Os secrets necessários para um workload em execução também devem evitar padrões ad hoc, como variáveis de ambiente simples, sempre que possível. Volumes, integrações dedicadas de secret-management, Docker secrets e Kubernetes Secrets são mecanismos comuns. Nenhum deles elimina todos os riscos, especialmente se o atacante já tiver code execution no workload, mas eles ainda são preferíveis a armazenar credenciais permanentemente na imagem ou expô-las casualmente por meio de ferramentas de inspeção.

Uma declaração simples de secret no estilo Docker Compose é semelhante a:
```yaml
version: "3.7"
services:
my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret
secrets:
my_secret:
file: ./my_secret_file.txt
```
No Kubernetes, objetos Secret, volumes projetados, tokens de service account e identidades de workload cloud criam um modelo mais amplo e poderoso, mas também criam mais oportunidades de exposição acidental por meio de mounts do host, RBAC abrangente ou um design fraco de Pod.

## Abuse

Ao revisar um alvo, o objetivo é descobrir se secrets foram incorporados à imagem, leaked nas layers ou montados em locais previsíveis do runtime:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Esses comandos ajudam a distinguir entre três problemas diferentes: leaks de configuração da aplicação, leaks na camada da image e arquivos de secrets injetados em runtime. Se um secret aparecer em `/run/secrets`, em um volume projetado ou em um caminho de token de identidade da cloud, o próximo passo é entender se ele concede acesso apenas à workload atual ou a um control plane muito maior.

### Exemplo Completo: Secret Incorporado No Filesystem Da Image

Se uma pipeline de build copiou arquivos `.env` ou credenciais para a image final, o post-exploitation se torna simples:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
O impacto depende da aplicação, mas signing keys incorporadas, JWT secrets ou credenciais de cloud podem facilmente transformar o comprometimento do container em comprometimento da API, movimento lateral ou falsificação de tokens confiáveis da aplicação.

### Exemplo Completo: Verificação de Leak de Secrets em Build-Time

Se a preocupação é que o histórico da image tenha capturado uma layer contendo um secret:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Esse tipo de revisão é útil porque um segredo pode ter sido excluído da visualização final do sistema de arquivos, mas ainda permanecer em uma camada anterior ou nos metadados da build.

## Verificações

Estas verificações têm o objetivo de determinar se a imagem e o pipeline de tratamento de segredos provavelmente aumentaram a superfície de ataque antes do runtime.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
O que é interessante aqui:

- Um histórico de build suspeito pode revelar credenciais copiadas, material SSH ou etapas de build inseguras.
- Secrets em caminhos de volumes projetados podem levar ao acesso ao cluster ou à cloud, não apenas ao acesso à aplicação local.
- Um grande número de arquivos de configuração com credenciais em texto simples geralmente indica que a image ou o modelo de deployment está carregando mais material de confiança do que o necessário.

## Padrões de Runtime

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker / BuildKit | Suporta mounts seguros de secrets durante o build, mas não automaticamente | Secrets podem ser montados de forma efêmera durante o `build`; assinatura e scanning de images exigem escolhas explícitas de workflow | copiar secrets para a image, passar secrets por `ARG` ou `ENV`, desabilitar verificações de provenance |
| Podman / Buildah | Suporta builds nativos de OCI e workflows com suporte a secrets | Workflows de build robustos estão disponíveis, mas os operadores ainda precisam escolhê-los intencionalmente | incorporar secrets em Containerfiles, contexts de build amplos, bind mounts permissivos durante os builds |
| Kubernetes | Objetos Secret nativos e volumes projetados | A entrega de secrets em runtime é um recurso de primeira classe, mas a exposição depende de RBAC, design do pod e mounts do host | mounts de Secret excessivamente amplos, uso indevido de tokens de service account, acesso a volumes gerenciados pelo kubelet via `hostPath` |
| Registries | A integridade é opcional, a menos que seja imposta | Registries públicos e privados dependem igualmente de políticas, signing e decisões de admission | fazer pull livremente de images sem assinatura, admission control fraco, gerenciamento inadequado de chaves |

{{#include ../../../banners/hacktricks-training.md}}
