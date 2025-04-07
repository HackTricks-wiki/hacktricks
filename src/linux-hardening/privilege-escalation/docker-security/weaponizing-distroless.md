# Wapen van Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Wat is Distroless

'n Distroless-container is 'n tipe container wat **slegs die nodige afhanklikhede bevat om 'n spesifieke toepassing te laat loop**, sonder enige addisionele sagteware of gereedskap wat nie benodig word nie. Hierdie containers is ontwerp om so **liggewig** en **veilig** as moontlik te wees, en hulle poog om die **aanvaloppervlak te minimaliseer** deur enige onnodige komponente te verwyder.

Distroless-containers word dikwels in **produksie-omgewings waar veiligheid en betroubaarheid van die grootste belang is** gebruik.

Sommige **voorbeelde** van **distroless-containers** is:

- Verskaf deur **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
- Verskaf deur **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Wapen van Distroless

Die doel van die wapen van 'n distroless-container is om in staat te wees om **arbitraire binaire en payloads uit te voer selfs met die beperkings** wat deur **distroless** geïmpliseer word (gebrek aan algemene binaire in die stelsel) en ook beskermings wat algemeen in containers voorkom soos **lees-slegs** of **geen-uitvoering** in `/dev/shm`.

### Deur geheue

Kom op 'n sekere punt in 2023...

### Via Bestaande binaire

#### openssl

\***\*[**In hierdie pos,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) word verduidelik dat die binaire **`openssl`** gereeld in hierdie containers voorkom, moontlik omdat dit **benodig** word deur die sagteware wat binne die container gaan loop.

{{#include ../../../banners/hacktricks-training.md}}
