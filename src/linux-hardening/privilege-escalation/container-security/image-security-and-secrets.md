# Segurança de Imagens, Assinatura e Segredos

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

A segurança de containers começa antes da carga de trabalho ser iniciada. A imagem determina quais binários, interpretadores, bibliotecas, scripts de inicialização e configurações incorporadas chegam à produção. Se a imagem estiver backdoorada, desatualizada ou construída com segredos embutidos, o hardening em tempo de execução que se segue já estará operando sobre um artefato comprometido.

É por isso que proveniência de imagem, scanner de vulnerabilidades, verificação de assinatura e tratamento de segredos pertencem à mesma conversa que namespaces e seccomp. Eles protegem uma fase diferente do ciclo de vida, mas falhas aqui frequentemente definem a superfície de ataque que o runtime mais tarde terá de conter.

## Registros de Imagens e Confiança

Imagens podem vir de registries públicos como Docker Hub ou de registries privados operados por uma organização. A questão de segurança não é simplesmente onde a imagem reside, mas se a equipe consegue estabelecer proveniência e integridade. Fazer pull de imagens não assinadas ou mal rastreadas de fontes públicas aumenta o risco de conteúdo malicioso ou adulterado entrar na produção. Mesmo registries hospedados internamente precisam de propriedade clara, revisão e política de confiança.

Docker Content Trust historicamente usou os conceitos do Notary e TUF para exigir imagens assinadas. O ecossistema exato evoluiu, mas a lição duradoura permanece útil: a identidade e integridade da imagem devem ser verificáveis em vez de assumidas.

Exemplo de fluxo de trabalho histórico do Docker Content Trust:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
O objetivo do exemplo não é que todas as equipes devam continuar usando as mesmas ferramentas, mas sim que assinatura e gerenciamento de chaves são tarefas operacionais, não teoria abstrata.

## Varredura de Vulnerabilidades

A varredura de imagens ajuda a responder duas perguntas diferentes. Primeiro, a imagem contém pacotes ou bibliotecas conhecidas por serem vulneráveis? Segundo, a imagem carrega software desnecessário que amplia a superfície de ataque? Uma imagem cheia de ferramentas de depuração, shells, interpretadores e pacotes obsoletos é tanto mais fácil de explorar quanto mais difícil de analisar.

Exemplos de scanners comumente usados incluem:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Os resultados dessas ferramentas devem ser interpretados com cuidado. Uma vulnerabilidade em um pacote não utilizado não apresenta o mesmo risco que um caminho RCE exposto, mas ambos continuam relevantes para decisões de hardening.

## Segredos em tempo de build

Um dos erros mais antigos em pipelines de build de containers é embutir segredos diretamente na imagem ou passá-los por variáveis de ambiente que depois ficam visíveis através de `docker inspect`, logs de build ou camadas recuperadas. Segredos em tempo de build devem ser montados de forma efêmera durante o build em vez de copiados para o sistema de arquivos da imagem.

BuildKit melhorou esse modelo permitindo um manuseio dedicado de segredos em tempo de build. Em vez de escrever um segredo em uma camada, a etapa de build pode consumi-lo de forma transitória:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Isso importa porque as camadas da imagem são artefatos duráveis. Uma vez que um segredo entra em uma camada gravada, deletar o arquivo em outra camada depois não remove verdadeiramente a divulgação original do histórico da imagem.

## Segredos em tempo de execução

Segredos necessários por uma carga de trabalho em execução também devem evitar padrões ad hoc, como variáveis de ambiente em texto simples, sempre que possível. Volumes, integrações dedicadas de gerenciamento de segredos, Docker secrets, e Kubernetes Secrets são mecanismos comuns. Nenhum deles elimina todo o risco, especialmente se o atacante já tiver execução de código na carga de trabalho, mas ainda assim são preferíveis a armazenar credenciais permanentemente na imagem ou expô-las casualmente por meio de ferramentas de inspeção.

Uma simples declaração de secret no estilo Docker Compose fica assim:
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
No Kubernetes, Secret objects, projected volumes, service-account tokens e cloud workload identities criam um modelo mais amplo e poderoso, mas também criam mais oportunidades de exposição acidental por meio de host mounts, RBAC amplo ou design fraco de Pod.

## Abuso

Ao revisar um alvo, o objetivo é descobrir se os secrets foram embutidos na imagem, leaked para camadas, ou montados em locais previsíveis de tempo de execução:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Estes comandos ajudam a distinguir entre três problemas diferentes: configuração da aplicação leaks, camada de imagem leaks e arquivos secretos injetados em tempo de execução. Se um secret aparecer em `/run/secrets`, em um projected volume, ou em um cloud identity token path, o próximo passo é entender se ele concede acesso apenas ao workload atual ou a um control plane muito maior.

### Exemplo completo: Segredo incorporado no sistema de arquivos da imagem

Se a pipeline de build copiou arquivos `.env` ou credenciais para a imagem final, post-exploitation torna-se simples:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
O impacto depende da aplicação, mas embedded signing keys, JWT secrets, ou cloud credentials podem facilmente transformar o comprometimento de um container em comprometimento da API, lateral movement, ou falsificação de tokens de aplicações confiáveis.

### Exemplo completo: Build-Time Secret Leakage Check

Se a preocupação for que o image history tenha capturado uma camada contendo secrets:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Esse tipo de revisão é útil porque um segredo pode ter sido removido da visualização final do sistema de arquivos enquanto ainda permanece em uma camada anterior ou nos metadados de build.

## Verificações

Essas verificações visam determinar se a imagem e o pipeline de manuseio de segredos provavelmente aumentaram a superfície de ataque antes do tempo de execução.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
O que é interessante aqui:

- Um histórico de build suspeito pode revelar credenciais copiadas, material SSH ou etapas de build inseguras.
- Secrets em projected volume paths podem levar a acesso ao cluster ou à cloud, não apenas ao acesso local da aplicação.
- Grande número de arquivos de configuração com credenciais em texto simples geralmente indica que a imagem ou o modelo de deployment está carregando mais material de confiança do que o necessário.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker / BuildKit | Supports secure build-time secret mounts, but not automatically | Secrets can be mounted ephemerally during `build`; image signing and scanning require explicit workflow choices | copying secrets into the image, passing secrets by `ARG` or `ENV`, disabling provenance checks |
| Podman / Buildah | Supports OCI-native builds and secret-aware workflows | Strong build workflows are available, but operators must still choose them intentionally | embedding secrets in Containerfiles, broad build contexts, permissive bind mounts during builds |
| Kubernetes | Native Secret objects and projected volumes | Runtime secret delivery is first-class, but exposure depends on RBAC, pod design, and host mounts | overbroad Secret mounts, service-account token misuse, `hostPath` access to kubelet-managed volumes |
| Registries | Integrity is optional unless enforced | Public and private registries both depend on policy, signing, and admission decisions | pulling unsigned images freely, weak admission control, poor key management |
{{#include ../../../banners/hacktricks-training.md}}
