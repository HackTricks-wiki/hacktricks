# Weaponizing Distroless

{{#include ../../../banners/hacktricks-training.md}}

## What is Distroless

A distroless container is a type of container that **특정 애플리케이션을 실행하는 데 필요한 종속성만 포함**하며, 필요하지 않은 추가 소프트웨어나 도구는 포함하지 않습니다. 이러한 컨테이너는 **가볍고** **안전**하도록 설계되었으며, 불필요한 구성 요소를 제거하여 **공격 표면을 최소화**하는 것을 목표로 합니다.

Distroless 컨테이너는 **보안과 신뢰성이 가장 중요한** **생산 환경**에서 자주 사용됩니다.

Some **examples** of **distroless containers** are:

- Provided by **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
- Provided by **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Weaponizing Distroless

The goal of weaponize a distroless container is to be able to **임의의 바이너리와 페이로드를 실행할 수 있는 것**이며, **distroless**에 의해 암시된 **제한**(시스템에 일반적인 바이너리 부족)과 **읽기 전용** 또는 **실행 금지**와 같은 컨테이너에서 일반적으로 발견되는 보호 장치에도 불구하고 가능합니다.

### Through memory

Coming at some point of 2023...

### Via Existing binaries

#### openssl

\***\*[**In this post,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) it is explained that the binary **`openssl`** is frequently found in these containers, potentially because it's **필요\*\* by the software that is going to be running inside the container.

{{#include ../../../banners/hacktricks-training.md}}
