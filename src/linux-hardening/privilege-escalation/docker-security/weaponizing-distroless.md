# Weaponizing Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Distroless Nedir

Distroless bir konteyner, **belirli bir uygulamayı çalıştırmak için gerekli olan bağımlılıkları** içeren bir konteyner türüdür; gereksiz yazılım veya araçlar içermez. Bu konteynerler, **hafif** ve **güvenli** olmaları için tasarlanmıştır ve gereksiz bileşenleri kaldırarak **saldırı yüzeyini minimize etmeyi** hedefler.

Distroless konteynerler genellikle **güvenlik ve güvenilirliğin ön planda olduğu üretim ortamlarında** kullanılır.

**Distroless konteynerlere** bazı **örnekler** şunlardır:

- **Google** tarafından sağlanan: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
- **Chainguard** tarafından sağlanan: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Distroless'ı Silahlandırma

Distroless bir konteyneri silahlandırmanın amacı, **distroless'in getirdiği sınırlamalara** (sistemde yaygın ikili dosyaların eksikliği) rağmen **rastgele ikili dosyaları ve yükleri çalıştırabilmektir**; ayrıca konteynerlerde yaygın olarak bulunan **salt okunur** veya **çalıştırılamaz** gibi korumaları da aşmaktır.

### Bellek Üzerinden

2023'ün bir noktasında gelecek...

### Mevcut ikili dosyalar aracılığıyla

#### openssl

\***\*[**Bu yazıda,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) **`openssl`** ikilisinin bu konteynerlerde sıkça bulunduğu, muhtemelen konteyner içinde çalışacak yazılım tarafından **gerekli** olduğu açıklanmaktadır.

{{#include ../../../banners/hacktricks-training.md}}
