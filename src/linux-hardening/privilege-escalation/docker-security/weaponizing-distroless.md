# Weaponizing Distroless

{{#include ../../../banners/hacktricks-training.md}}

## What is Distroless

Konteina isiyo na mfumo wa uendeshaji ni aina ya kontena ambayo **ina viambatisho muhimu tu kuendesha programu maalum**, bila programu au zana za ziada ambazo hazihitajiki. Kontena hizi zimeundwa kuwa **nyepesi** na **salama** kadri iwezekanavyo, na zina lengo la **kupunguza uso wa shambulio** kwa kuondoa vipengele visivyohitajika.

Konteina zisizo na mfumo wa uendeshaji mara nyingi hutumiwa katika **mazingira ya uzalishaji ambapo usalama na uaminifu ni muhimu**.

Baadhi ya **mfano** wa **konteina zisizo na mfumo wa uendeshaji** ni:

- Iliyotolewa na **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
- Iliyotolewa na **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Weaponizing Distroless

Lengo la kuunda silaha kutoka kwa kontena isiyo na mfumo wa uendeshaji ni kuwa na uwezo wa **kutekeleza binaries na payloads za kiholela hata na vikwazo** vinavyotokana na **distroless** (ukosefu wa binaries za kawaida katika mfumo) na pia ulinzi unaopatikana mara nyingi katika kontena kama **kusoma tu** au **hakuna utekelezaji** katika `/dev/shm`.

### Through memory

Kujitokeza katika wakati fulani wa 2023...

### Via Existing binaries

#### openssl

\***\*[**Katika chapisho hili,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) inafafanuliwa kuwa binary **`openssl`** mara nyingi hupatikana katika kontena hizi, labda kwa sababu inahitajika\*\* na programu ambayo itakuwa ikikimbia ndani ya kontena.

{{#include ../../../banners/hacktricks-training.md}}
