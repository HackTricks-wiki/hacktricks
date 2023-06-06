# Armando Distroless

Um contêiner distroless é um tipo de contêiner que contém apenas as dependências necessárias para executar um aplicativo específico, sem nenhum software ou ferramenta adicional que não seja necessário. Esses contêineres são projetados para serem o mais leves e seguros possível e visam minimizar a superfície de ataque removendo quaisquer componentes desnecessários.

Os contêineres distroless são frequentemente usados em ambientes de produção onde a segurança e a confiabilidade são primordiais.

Alguns exemplos de contêineres distroless são:

* Fornecido pelo Google: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* Fornecido pela Chainguard: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Armando Distroless

O objetivo de armar um contêiner distroless é ser capaz de executar binários e payloads arbitrários, mesmo com as limitações impostas pelo distroless (falta de binários comuns no sistema) e também proteções comumente encontradas em contêineres, como somente leitura ou sem execução em `/dev/shm`.

### Através da memória

Chegando em algum momento de 2023...

### Via binários existentes

#### openssl

Neste post, é explicado que o binário `openssl` é frequentemente encontrado nesses contêineres, potencialmente porque é necessário pelo software que será executado dentro do contêiner.

Abusando do binário `openssl`, é possível executar coisas arbitrárias.
