# Weaponizing Distroless

{{#include ../../../banners/hacktricks-training.md}}

## What is Distroless

Distroless bir konteyner, **belirli bir uygulamayı çalıştırmak için yalnızca gerekli bağımlılıkları içeren** bir konteyner türüdür; gereksiz yazılım veya araçlar içermez. Bu konteynerler, **hafif** ve **güvenli** olmaları için tasarlanmıştır ve gereksiz bileşenleri kaldırarak **saldırı yüzeyini minimize etmeyi** hedefler.

Distroless konteynerler genellikle **güvenlik ve güvenilirliğin ön planda olduğu üretim ortamlarında** kullanılır.

**Distroless konteynerlere** bazı **örnekler** şunlardır:

- **Google** tarafından sağlanan: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
- **Chainguard** tarafından sağlanan: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Weaponizing Distroless

Distroless bir konteyneri silahlandırmanın amacı, **sistem üzerindeki yaygın ikili dosyaların eksikliği** ve ayrıca konteynerlerde sıkça bulunan **salt okunur** veya **çalıştırılamaz** gibi korumalarla birlikte **rastgele ikili dosyaları ve yükleri çalıştırabilmektir**.

### Through memory

2023'ün bir noktasında geliyor...

### Via Existing binaries

#### openssl

\***\*[**Bu yazıda,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) **`openssl`** ikili dosyasının bu konteynerlerde sıkça bulunduğu, muhtemelen konteyner içinde çalışacak yazılım tarafından **gerekli olduğu** açıklanmaktadır.

{{#include ../../../banners/hacktricks-training.md}}
