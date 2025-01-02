# Weaponizing Distroless

{{#include ../../../banners/hacktricks-training.md}}

## O que é Distroless

Um contêiner distroless é um tipo de contêiner que **contém apenas as dependências necessárias para executar um aplicativo específico**, sem qualquer software ou ferramentas adicionais que não sejam necessárias. Esses contêineres são projetados para serem o mais **leves** e **seguros** possível, e têm como objetivo **minimizar a superfície de ataque** removendo quaisquer componentes desnecessários.

Contêineres distroless são frequentemente usados em **ambientes de produção onde segurança e confiabilidade são fundamentais**.

Alguns **exemplos** de **contêineres distroless** são:

- Fornecidos pelo **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
- Fornecidos pelo **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Weaponizing Distroless

O objetivo de armar um contêiner distroless é ser capaz de **executar binários e payloads arbitrários, mesmo com as limitações** impostas pelo **distroless** (falta de binários comuns no sistema) e também proteções comumente encontradas em contêineres, como **somente leitura** ou **sem execução** em `/dev/shm`.

### Através da memória

Vindo em algum momento de 2023...

### Via binários existentes

#### openssl

\***\*[**Neste post,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) é explicado que o binário **`openssl`** é frequentemente encontrado nesses contêineres, potencialmente porque é **necessário\*\* pelo software que vai ser executado dentro do contêiner.

{{#include ../../../banners/hacktricks-training.md}}
