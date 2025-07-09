# Weaponizing Distroless
{{#include /banners/hacktricks-training.md}}


{{#include ../../../banners/hacktricks-training.md}}

## What is Distroless

A distroless container is a type of container that **contains only the necessary dependencies to run a specific application**, without any additional software or tools that are not required. These containers are designed to be as **lightweight** and **secure** as possible, and they aim to **minimize the attack surface** by removing any unnecessary components.

Distroless containers are often used in **production environments where security and reliability are paramount**.

Some **examples** of **distroless containers** are:

- Provided by **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
- Provided by **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Weaponizing Distroless

The goal of weaponize a distroless container is to be able to **execute arbitrary binaries and payloads even with the limitations** implied by **distroless** (lack of common binaries in the system) and also protections commonly found in containers such as **read-only** or **no-execute** in `/dev/shm`.

### Through memory

Coming at some point of 2023...

### Via Existing binaries

#### openssl

\***\*[**In this post,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) it is explained that the binary **`openssl`** is frequently found in these containers, potentially because it's **needed** by the software that is going to be running inside the container.

{{#include ../../../banners/hacktricks-training.md}}
