# Weaponizing Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Šta je Distroless

Distroless kontejner je vrsta kontejnera koja **sadrži samo neophodne zavisnosti za pokretanje specifične aplikacije**, bez dodatnog softvera ili alata koji nisu potrebni. Ovi kontejneri su dizajnirani da budu što **lakši** i **bezbedniji**, i imaju za cilj da **minimizuju površinu napada** uklanjanjem svih nepotrebnih komponenti.

Distroless kontejneri se često koriste u **produžnim okruženjima gde su bezbednost i pouzdanost od suštinskog značaja**.

Neki **primeri** **distroless kontejnera** su:

- Obezbeđeni od strane **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
- Obezbeđeni od strane **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Weaponizing Distroless

Cilj oružavanja distroless kontejnera je da se omogući **izvršavanje proizvoljnih binarnih datoteka i payload-a čak i sa ograničenjima** koja podrazumeva **distroless** (nedostatak uobičajenih binarnih datoteka u sistemu) i takođe zaštitama koje se obično nalaze u kontejnerima kao što su **samo-za-čitanje** ili **bez-izvršavanja** u `/dev/shm`.

### Kroz memoriju

Dolazi u nekom trenutku 2023...

### Putem postojećih binarnih datoteka

#### openssl

\***\*[**U ovom postu,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) objašnjeno je da se binarna datoteka **`openssl`** često nalazi u ovim kontejnerima, potencijalno zato što je **potrebna** softveru koji će se pokretati unutar kontejnera.

{{#include ../../../banners/hacktricks-training.md}}
