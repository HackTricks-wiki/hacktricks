# Weaponizing Distroless

{{#include ../../../banners/hacktricks-training.md}}

## What is Distroless

Un contenedor distroless es un tipo de contenedor que **contiene solo las dependencias necesarias para ejecutar una aplicación específica**, sin ningún software o herramienta adicional que no sea requerida. Estos contenedores están diseñados para ser lo más **ligeros** y **seguros** posible, y su objetivo es **minimizar la superficie de ataque** al eliminar cualquier componente innecesario.

Los contenedores distroless se utilizan a menudo en **entornos de producción donde la seguridad y la fiabilidad son primordiales**.

Algunos **ejemplos** de **contenedores distroless** son:

- Proporcionados por **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
- Proporcionados por **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Weaponizing Distroless

El objetivo de armar un contenedor distroless es poder **ejecutar binarios y cargas útiles arbitrarias incluso con las limitaciones** implicadas por **distroless** (falta de binarios comunes en el sistema) y también protecciones comúnmente encontradas en contenedores como **solo lectura** o **sin ejecución** en `/dev/shm`.

### Through memory

Llegando en algún momento de 2023...

### Via Existing binaries

#### openssl

\***\*[**En esta publicación,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) se explica que el binario **`openssl`** se encuentra frecuentemente en estos contenedores, potencialmente porque es **necesario\*\* por el software que se va a ejecutar dentro del contenedor.

{{#include ../../../banners/hacktricks-training.md}}
