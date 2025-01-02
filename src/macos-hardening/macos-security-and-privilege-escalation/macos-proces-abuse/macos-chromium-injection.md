# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

Google Chrome, Microsoft Edge, Brave ve diğerleri gibi Chromium tabanlı tarayıcılar. Bu tarayıcılar, ortak bir temel paylaştıkları için Chromium açık kaynak projesine dayanarak inşa edilmiştir ve bu nedenle benzer işlevselliklere ve geliştirici seçeneklerine sahiptir.

#### `--load-extension` Bayrağı

`--load-extension` bayrağı, bir Chromium tabanlı tarayıcıyı komut satırından veya bir betikten başlatırken kullanılır. Bu bayrak, tarayıcıyı başlatırken **bir veya daha fazla uzantıyı otomatik olarak yüklemeye** olanak tanır.

#### `--use-fake-ui-for-media-stream` Bayrağı

`--use-fake-ui-for-media-stream` bayrağı, Chromium tabanlı tarayıcıları başlatmak için kullanılabilecek bir diğer komut satırı seçeneğidir. Bu bayrak, **kamera ve mikrofon üzerinden medya akışlarına erişim izni isteyen normal kullanıcı istemlerini atlamak için tasarlanmıştır**. Bu bayrak kullanıldığında, tarayıcı otomatik olarak kameraya veya mikrofon erişimi talep eden herhangi bir web sitesine veya uygulamaya izin verir.

### Araçlar

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop)
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO)

### Örnek
```bash
# Intercept traffic
voodoo intercept -b chrome
```
Daha fazla örnek bulmak için araç bağlantılarına bakın

## Referanslar

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)

{{#include ../../../banners/hacktricks-training.md}}
