# Weaponizing Distroless

{{#include ../../../banners/hacktricks-training.md}}

## What is Distroless

Konteina isiyo na mfumo ni aina ya konteina ambayo **ina vitu vya msingi tu vinavyohitajika kuendesha programu maalum**, bila programu au zana za ziada ambazo hazihitajiki. Konteina hizi zimeundwa kuwa **nyepesi** na **salama** kadri inavyowezekana, na zina lengo la **kupunguza uso wa shambulio** kwa kuondoa vipengele visivyohitajika.

Konteina zisizo na mfumo mara nyingi hutumiwa katika **mazingira ya uzalishaji ambapo usalama na uaminifu ni muhimu**.

Baadhi ya **mfano** wa **konteina zisizo na mfumo** ni:

- Iliyotolewa na **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
- Iliyotolewa na **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Weaponizing Distroless

Lengo la kuunda silaha kutoka kwa konteina isiyo na mfumo ni kuwa na uwezo wa **kutekeleza binaries na payloads za kiholela hata na vikwazo** vinavyotokana na **distroless** (ukosefu wa binaries za kawaida katika mfumo) na pia ulinzi unaopatikana mara nyingi katika konteina kama **kusoma tu** au **hakuna utekelezaji** katika `/dev/shm`.

### Through memory

Kujitokeza katika wakati fulani wa 2023...

### Via Existing binaries

#### openssl

\***\*[**Katika chapisho hili,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) inaelezwa kuwa binary **`openssl`** mara nyingi hupatikana katika konteina hizi, labda kwa sababu inahitajika na programu ambayo itakuwa ikikimbia ndani ya konteina.

{{#include ../../../banners/hacktricks-training.md}}
