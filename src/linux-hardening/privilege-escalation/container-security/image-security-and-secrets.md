# Segurança de Imagens, Assinatura e Segredos

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

A segurança de containers começa antes da carga de trabalho ser iniciada. A imagem determina quais binários, interpretadores, bibliotecas, scripts de inicialização e configurações embutidas chegam à produção. Se a imagem estiver backdoored, desatualizada ou construída com segredos incorporados, o hardening em tempo de execução que vem depois já estará operando sobre um artefato comprometido.

É por isso que a proveniência da imagem, a varredura de vulnerabilidades, a verificação de assinaturas e o manuseio de segredos pertencem à mesma conversa que namespaces e seccomp. Eles protegem uma fase diferente do ciclo de vida, mas falhas aqui frequentemente definem a superfície de ataque que o runtime terá que conter mais tarde.

## Registros de Imagens e Confiança

As imagens podem vir de registries públicos como o Docker Hub ou de registries privados operados por uma organização. A questão de segurança não é simplesmente onde a imagem fica, mas se a equipe consegue estabelecer proveniência e integridade. Baixar imagens sem assinatura ou mal rastreadas de fontes públicas aumenta o risco de conteúdo malicioso ou adulterado entrar em produção. Mesmo registries hospedados internamente precisam de propriedade clara, revisão e política de confiança.

Docker Content Trust historicamente usou Notary e conceitos do TUF para exigir imagens assinadas. O ecossistema exato evoluiu, mas a lição duradoura continua válida: identidade e integridade da imagem devem ser verificáveis em vez de assumidas.

Exemplo de fluxo de trabalho histórico do Docker Content Trust:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
O objetivo do exemplo não é que toda equipe deva continuar usando as mesmas ferramentas, mas que assinatura e gerenciamento de chaves são tarefas operacionais, não teoria abstrata.

## Varredura de Vulnerabilidades

A varredura de imagens ajuda a responder duas perguntas diferentes. Primeiro, a imagem contém pacotes ou bibliotecas com vulnerabilidades conhecidas? Segundo, a imagem carrega software desnecessário que amplia a superfície de ataque? Uma imagem cheia de ferramentas de depuração, shells, interpretadores e pacotes obsoletos é tanto mais fácil de explorar quanto mais difícil de analisar.

Exemplos de scanners comumente usados incluem:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Os resultados dessas ferramentas devem ser interpretados com cuidado. Uma vulnerabilidade em um pacote não utilizado não tem o mesmo risco que um caminho de RCE exposto, mas ambos continuam relevantes para decisões de hardening.

## Segredos em tempo de build

Um dos erros mais antigos em pipelines de build de container é embutir segredos diretamente na imagem ou transmiti-los por variáveis de ambiente que depois ficam visíveis via `docker inspect`, logs de build ou camadas recuperadas. Segredos em tempo de build devem ser montados de forma efêmera durante o build em vez de copiados para o sistema de arquivos da imagem.

BuildKit melhorou esse modelo ao permitir tratamento dedicado de segredos em tempo de build. Em vez de gravar um segredo em uma camada, a etapa de build pode consumi-lo de forma transitória:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
This matters because image layers are durable artifacts. Once a secret enters a committed layer, later deleting the file in another layer does not truly remove the original disclosure from the image history.

## Runtime Secrets

Secrets necessários para uma carga de trabalho em execução também devem evitar padrões ad hoc, como variáveis de ambiente simples, sempre que possível. Volumes, integrações dedicadas de secret-management, Docker secrets e Kubernetes Secrets são mecanismos comuns. Nenhum deles elimina todo o risco, especialmente se o atacante já tiver execução de código na carga de trabalho, mas ainda assim são preferíveis a armazenar credenciais permanentemente na imagem ou expô-las casualmente por ferramentas de inspeção.

Uma declaração simples de secret no estilo Docker Compose fica assim:
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
No Kubernetes, Secret objects, projected volumes, service-account tokens e cloud workload identities criam um modelo mais amplo e mais poderoso, mas também criam mais oportunidades para exposição acidental através de host mounts, RBAC amplo ou design fraco de Pod.

## Abuso

Ao revisar um alvo, o objetivo é descobrir se segredos foram incorporados na imagem, leaked into layers, ou montados em locais previsíveis de runtime:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Esses comandos ajudam a distinguir entre três problemas diferentes: leaks de configuração da aplicação, leaks na camada de imagem e arquivos secretos injetados em tempo de execução. Se um segredo aparece em `/run/secrets`, em um projected volume, ou em um cloud identity token path, o próximo passo é entender se ele concede acesso apenas à carga de trabalho atual ou a um plano de controle muito maior.

### Exemplo Completo: Segredo Embutido no Sistema de Arquivos da Imagem

Se um pipeline de build copiou arquivos `.env` ou credenciais para a imagem final, post-exploitation torna-se simples:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
O impacto depende da aplicação, mas chaves de assinatura embutidas, JWT secrets ou cloud credentials podem facilmente transformar o comprometimento do container em comprometimento da API, lateral movement ou falsificação de tokens de aplicação confiáveis.

### Exemplo completo: Build-Time Secret Leakage Check

Se a preocupação é que o histórico da imagem capturou uma secret-bearing layer:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
## Verificações

Esse tipo de revisão é útil porque um segredo pode ter sido removido da vista final do sistema de arquivos enquanto ainda permanece em uma camada anterior ou nos metadados de build.

Essas verificações destinam-se a estabelecer se a imagem e o pipeline de manipulação de segredos provavelmente aumentaram a superfície de ataque antes do tempo de execução.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
O que é interessante aqui:

- Um histórico de build suspeito pode revelar credenciais copiadas, material SSH ou etapas de build inseguras.
- Secrets em caminhos de volumes projetados podem permitir acesso ao cluster ou à nuvem, não apenas à aplicação local.
- Um grande número de arquivos de configuração com credenciais em texto simples geralmente indica que a imagem ou o modelo de implantação está carregando mais material de confiança do que o necessário.

## Padrões de Runtime

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimentos manuais comuns |
| --- | --- | --- | --- |
| Docker / BuildKit | Suporta montagem segura de secrets em tempo de build, mas não automaticamente | Secrets podem ser montados de forma efêmera durante o `build`; assinatura e verificação de imagens exigem escolhas explícitas no fluxo de trabalho | copiar secrets para dentro da imagem, passar secrets via `ARG` ou `ENV`, desativar verificações de proveniência |
| Podman / Buildah | Suporta builds nativos OCI e fluxos de trabalho conscientes de secrets | Fluxos de build robustos estão disponíveis, mas os operadores ainda devem escolhê-los intencionalmente | incorporar secrets em Containerfiles, contextos de build amplos, bind mounts permissivos durante builds |
| Kubernetes | Objetos Secret nativos e volumes projetados | A entrega de secrets em tempo de execução é de primeira classe, mas a exposição depende de RBAC, design do pod e montagens do host | montagens de Secret excessivamente amplas, uso indevido de tokens de service-account, acesso `hostPath` a volumes gerenciados pelo kubelet |
| Registries | Integridade é opcional a menos que seja aplicada | Registros públicos e privados dependem de políticas, assinatura e decisões de admissão | pull de imagens não assinadas livremente, controle de admissão fraco, gerenciamento de chaves inadequado |
