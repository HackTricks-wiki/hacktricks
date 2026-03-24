# Segurança de Imagens, Assinatura e Segredos

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

A segurança de containers começa antes da carga de trabalho ser iniciada. A imagem determina quais binários, interpretadores, bibliotecas, scripts de inicialização e configurações incorporadas chegam à produção. Se a imagem estiver comprometida por backdoor, desatualizada ou construída com segredos embutidos, o hardening em tempo de execução que se segue já estará operando em um artefato comprometido.

É por isso que a proveniência da imagem, a varredura de vulnerabilidades, a verificação de assinatura e o manuseio de segredos pertencem à mesma conversa que namespaces e seccomp. Eles protegem uma fase diferente do ciclo de vida, mas falhas aqui frequentemente definem a superfície de ataque que o runtime depois terá de conter.

## Registros de Imagens e Confiança

As imagens podem vir de registries públicos como Docker Hub ou de registries privados operados por uma organização. A questão de segurança não é apenas onde a imagem vive, mas se a equipe consegue estabelecer proveniência e integridade. Baixar imagens não assinadas ou mal rastreadas de fontes públicas aumenta o risco de conteúdo malicioso ou alterado entrar em produção. Mesmo registries hospedados internamente precisam de propriedade clara, revisão e política de confiança.

Docker Content Trust historicamente usou conceitos do Notary e do TUF para exigir imagens assinadas. O ecossistema exato evoluiu, mas a lição duradoura permanece útil: a identidade e a integridade da imagem devem ser verificáveis em vez de assumidas.

Exemplo de fluxo de trabalho histórico do Docker Content Trust:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
O ponto do exemplo não é que todas as equipes devam usar as mesmas ferramentas, mas que signing and key management são tarefas operacionais, não teoria abstrata.

## Escaneamento de Vulnerabilidades

O escaneamento de imagens ajuda a responder duas perguntas distintas. Primeiro, a imagem contém pacotes ou bibliotecas conhecidas vulneráveis? Segundo, a imagem carrega software desnecessário que amplia a attack surface? Uma imagem cheia de debugging tools, shells, interpreters e pacotes obsoletos é tanto mais fácil de explorar quanto mais difícil de avaliar.

Exemplos de scanners comumente usados incluem:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Os resultados dessas ferramentas devem ser interpretados com cautela. Uma vulnerabilidade em um pacote não utilizado não equivale, em termos de risco, a um caminho de RCE exposto, mas ambos continuam relevantes para decisões de hardening.

## Segredos em tempo de build

Um dos erros mais antigos em pipelines de build de contêineres é incorporar segredos diretamente na imagem ou passá-los por variáveis de ambiente que depois ficam visíveis via `docker inspect`, logs de build ou camadas recuperadas. Segredos em tempo de build devem ser montados de forma efêmera durante a construção em vez de serem copiados para o sistema de arquivos da imagem.

BuildKit melhorou esse modelo ao permitir um tratamento dedicado para segredos em tempo de build. Em vez de gravar um segredo em uma camada, a etapa de build pode consumi-lo de forma transitória:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Isto importa porque as camadas da imagem são artefatos duráveis. Uma vez que um segredo entra em uma camada confirmada, apagar o arquivo depois em outra camada não remove de fato a divulgação original do histórico da imagem.

## Segredos em tempo de execução

Segredos necessários por uma carga de trabalho em execução também devem evitar padrões ad hoc, como variáveis de ambiente simples, sempre que possível. Volumes, integrações dedicadas de gerenciamento de segredos, Docker secrets e Kubernetes Secrets são mecanismos comuns. Nenhum deles elimina todos os riscos, especialmente se o atacante já tiver execução de código na carga de trabalho, mas ainda assim são preferíveis a armazenar credenciais permanentemente na imagem ou expô-las de forma casual por meio de ferramentas de inspeção.

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
No Kubernetes, Secret objects, projected volumes, service-account tokens, and cloud workload identities criam um modelo mais amplo e poderoso, mas também criam mais oportunidades de exposição acidental através de host mounts, RBAC amplo ou design fraco de Pod.

## Abuso

Ao revisar um alvo, o objetivo é descobrir se secrets foram incorporados na imagem, leaked into layers, ou montados em locais previsíveis de tempo de execução:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Esses comandos ajudam a distinguir entre três problemas diferentes: application configuration leaks, image-layer leaks, and runtime-injected secret files. Se um secret aparecer sob `/run/secrets`, um projected volume, ou um cloud identity token path, o próximo passo é entender se ele concede acesso apenas ao workload atual ou a um much larger control plane.

### Full Example: Embedded Secret In Image Filesystem

Se um build pipeline copiou arquivos `.env` ou credenciais para a imagem final, post-exploitation torna-se simples:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
O impacto depende da aplicação, mas chaves de assinatura embutidas, segredos JWT ou credenciais de cloud podem facilmente transformar o comprometimento de um container em comprometimento de API, lateral movement ou falsificação de tokens de aplicação confiáveis.

### Exemplo completo: Verificação de Build-Time Secret Leakage

Se a preocupação for que o histórico da imagem capturou uma camada contendo segredos:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Este tipo de revisão é útil porque um segredo pode ter sido excluído da vista final do sistema de arquivos enquanto ainda permanece numa camada anterior ou nos metadados de build.

## Verificações

Estas verificações destinam-se a determinar se a imagem e a pipeline de tratamento de segredos provavelmente aumentaram a superfície de ataque antes do tempo de execução.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
- Um histórico de build suspeito pode revelar credenciais copiadas, material SSH ou etapas de build inseguras.
- Secrets em caminhos de volumes projetados podem levar a acesso ao cluster ou à nuvem, não apenas ao aplicativo local.
- Um grande número de arquivos de configuração com credenciais em texto simples geralmente indica que a imagem ou o modelo de implantação está carregando mais material de confiança do que o necessário.

## Padrões em tempo de execução

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker / BuildKit | Suporta montagem segura de secrets em build-time, mas não automaticamente | Secrets podem ser montados de forma efêmera durante `build`; assinatura e verificação de imagens requerem escolhas explícitas de workflow | copiar secrets para dentro da imagem, passar secrets por `ARG` ou `ENV`, desabilitar verificações de proveniência |
| Podman / Buildah | Suporta builds OCI-nativos e workflows conscientes de secrets | Workflows de build robustos estão disponíveis, mas operadores ainda precisam escolhê-los intencionalmente | incorporar secrets em Containerfiles, contextos de build amplos, bind mounts permissivos durante builds |
| Kubernetes | Objetos Secret nativos e projected volumes | A entrega de secrets em runtime é de primeira classe, mas a exposição depende de RBAC, design do pod e montagens no host | montagens de Secret excessivamente amplas, uso indevido de service-account tokens, acesso `hostPath` a volumes gerenciados pelo kubelet |
| Registries | Integridade é opcional a menos que seja aplicada | Registros públicos e privados dependem de políticas, assinatura e decisões de admissão | fazer pull de imagens não assinadas livremente, controle de admissão fraco, gerenciamento de chaves deficiente |
{{#include ../../../banners/hacktricks-training.md}}
