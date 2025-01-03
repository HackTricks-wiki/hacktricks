# Weaponizing Distroless

{{#include ../../../banners/hacktricks-training.md}}

## What is Distroless

Un container distroless è un tipo di container che **contiene solo le dipendenze necessarie per eseguire un'applicazione specifica**, senza alcun software o strumento aggiuntivo che non sia richiesto. Questi container sono progettati per essere il più **leggeri** e **sicuri** possibile e mirano a **minimizzare la superficie di attacco** rimuovendo componenti non necessari.

I container distroless sono spesso utilizzati in **ambienti di produzione dove la sicurezza e l'affidabilità sono fondamentali**.

Alcuni **esempi** di **container distroless** sono:

- Forniti da **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
- Forniti da **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Weaponizing Distroless

L'obiettivo di armare un container distroless è essere in grado di **eseguire binari e payload arbitrari anche con le limitazioni** imposte da **distroless** (mancanza di binari comuni nel sistema) e anche protezioni comunemente trovate nei container come **sola lettura** o **nessuna esecuzione** in `/dev/shm`.

### Through memory

In arrivo in un certo momento del 2023...

### Via Existing binaries

#### openssl

\***\*[**In questo post,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) si spiega che il binario **`openssl`** è frequentemente trovato in questi container, potenzialmente perché è **necessario\*\* dal software che verrà eseguito all'interno del container.

{{#include ../../../banners/hacktricks-training.md}}
