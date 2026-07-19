# Segurança, Assinatura e Secrets de Imagens

{{#include ../../../banners/hacktricks-training.md}}

## Registries de Imagens e Trust

A segurança de containers começa antes de o workload ser iniciado. A imagem determina quais binários, interpretadores, libraries, scripts de inicialização e configurações incorporadas chegam à produção. Se a imagem tiver um backdoor, estiver desatualizada ou tiver sido criada com secrets incorporados nela, o hardening do runtime realizado posteriormente já estará operando sobre um artifact comprometido.

É por isso que a proveniência das imagens, a varredura de vulnerabilidades, a verificação de assinaturas e o tratamento de secrets devem fazer parte da mesma discussão que namespaces e seccomp. Eles protegem uma fase diferente do ciclo de vida, mas as falhas aqui frequentemente definem a attack surface que o runtime terá de conter posteriormente.

As imagens podem vir de registries públicos, como o Docker Hub, ou de registries privados operados por uma organização. A questão de segurança não é simplesmente onde a imagem está armazenada, mas se a equipe consegue estabelecer sua proveniência e integridade. Fazer pull de imagens não assinadas ou mal rastreadas de fontes públicas aumenta o risco de conteúdo malicioso ou adulterado entrar em produção. Mesmo os registries hospedados internamente precisam de ownership, revisão e uma trust policy claros.

O Docker Content Trust historicamente usava os conceitos de Notary e TUF para exigir imagens assinadas. O ecossistema exato evoluiu, mas a lição duradoura continua útil: a identidade e a integridade das imagens devem ser verificáveis, e não presumidas.

Exemplo de workflow histórico do Docker Content Trust:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
O objetivo do exemplo não é que todas as equipes ainda precisem usar as mesmas ferramentas, mas sim mostrar que assinatura e gerenciamento de chaves são tarefas operacionais, não teoria abstrata.

## Varredura de Vulnerabilidades

A varredura de imagens ajuda a responder a duas perguntas diferentes. Primeiro, a imagem contém pacotes ou bibliotecas vulneráveis conhecidos? Segundo, a imagem inclui software desnecessário que amplia a superfície de ataque? Uma imagem cheia de ferramentas de debugging, shells, interpretadores e pacotes desatualizados é mais fácil de explorar e mais difícil de analisar.

Exemplos de scanners usados com frequência incluem:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Os resultados dessas ferramentas devem ser interpretados com cuidado. Uma vulnerabilidade em um package não utilizado não apresenta o mesmo risco que um caminho de RCE exposto, mas ambos ainda são relevantes para decisões de hardening.

## Secrets em Tempo de Build

Um dos erros mais antigos em pipelines de build de containers é inserir secrets diretamente na imagem ou passá-los por meio de variáveis de ambiente que posteriormente ficam visíveis através de `docker inspect`, logs de build ou camadas recuperadas. Os secrets em tempo de build devem ser montados de forma efêmera durante o build, em vez de serem copiados para o filesystem da imagem.

O BuildKit aprimorou esse modelo ao permitir o gerenciamento dedicado de secrets em tempo de build. Em vez de gravar um secret em uma camada, a etapa de build pode consumi-lo de forma transitória:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Isso é importante porque as camadas da imagem são artefatos duráveis. Quando um secret entra em uma camada com commit, excluir posteriormente o arquivo em outra camada não remove de fato a divulgação original do histórico da imagem.

## Secrets em Runtime

Os secrets necessários para um workload em execução também devem evitar padrões improvisados, como variáveis de ambiente simples, sempre que possível. Volumes, integrações dedicadas de gerenciamento de secrets, Docker secrets e Kubernetes Secrets são mecanismos comuns. Nenhum deles elimina todos os riscos, especialmente se o attacker já tiver code execution no workload, mas eles ainda são preferíveis a armazenar credenciais permanentemente na imagem ou expô-las casualmente por meio de ferramentas de inspeção.

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
No Kubernetes, objetos Secret, volumes projetados, tokens de service account e identidades de workload da cloud criam um modelo mais amplo e poderoso, mas também geram mais oportunidades de exposição acidental por meio de host mounts, RBAC permissivo ou um design fraco de Pod.

## Abuso

Ao revisar um alvo, o objetivo é descobrir se os secrets foram incorporados à imagem, sofreram leak para as layers ou foram montados em localizações previsíveis de runtime:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Esses comandos ajudam a distinguir entre três problemas diferentes: leaks de configuração da aplicação, leaks na camada da imagem e arquivos de secrets injetados em runtime. Se um secret aparecer em `/run/secrets`, em um volume projetado ou em um caminho de token de identidade cloud, o próximo passo é entender se ele concede acesso apenas ao workload atual ou a um control plane muito maior.

### Exemplo completo: Secret incorporado no filesystem da imagem

Se um pipeline de build copiou arquivos `.env` ou credenciais para a imagem final, o post-exploitation se torna simples:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
O impacto depende da aplicação, mas chaves de assinatura incorporadas, secrets JWT ou credenciais de cloud podem facilmente transformar o comprometimento do container em comprometimento da API, movimento lateral ou falsificação de tokens confiáveis da aplicação.

### Exemplo Completo: Verificação de Leak de Secrets em Build-Time

Se a preocupação é que o histórico da imagem tenha capturado uma layer contendo um secret:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Esse tipo de revisão é útil porque um segredo pode ter sido excluído da visualização final do sistema de arquivos, mas ainda permanecer em uma camada anterior ou nos metadados de build.

## Verificações

Estas verificações têm como objetivo determinar se a imagem e o pipeline de gerenciamento de segredos provavelmente aumentaram a superfície de ataque antes do runtime.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
O que é interessante aqui:

- Um histórico de build suspeito pode revelar credenciais copiadas, material de SSH ou etapas de build inseguras.
- Secrets em caminhos de volumes projetados podem levar a acesso ao cluster ou à cloud, não apenas ao acesso à aplicação local.
- Um grande número de arquivos de configuração com credenciais em plaintext geralmente indica que a imagem ou o modelo de deployment está carregando mais material de confiança do que o necessário.

## Padrões de Runtime

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker / BuildKit | Suporta mounts seguros de secrets durante o build, mas não automaticamente | Secrets podem ser montados de forma efêmera durante o `build`; assinatura e scanning de imagens exigem escolhas explícitas de workflow | copiar secrets para a imagem, passar secrets por `ARG` ou `ENV`, desabilitar verificações de provenance |
| Podman / Buildah | Suporta builds nativos de OCI e workflows com suporte a secrets | Workflows de build seguros estão disponíveis, mas os operadores ainda precisam escolhê-los intencionalmente | incorporar secrets em Containerfiles, usar contextos de build amplos, bind mounts permissivos durante os builds |
| Kubernetes | Objetos Secret nativos e volumes projetados | A entrega de secrets em Runtime é um recurso de primeira classe, mas a exposição depende de RBAC, design do pod e mounts do host | mounts de Secret excessivamente amplos, uso indevido de tokens de service account, acesso a volumes gerenciados pelo kubelet via `hostPath` |
| Registries | A integridade é opcional, a menos que seja imposta | Registries públicos e privados dependem igualmente de políticas, assinatura e decisões de admission | fazer pull livremente de imagens sem assinatura, admission control fraco, gerenciamento inadequado de chaves |
{{#include ../../../banners/hacktricks-training.md}}
