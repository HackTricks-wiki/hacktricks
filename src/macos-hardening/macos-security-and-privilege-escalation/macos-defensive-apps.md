# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Her bir sürecin yaptığı her bağlantıyı izleyecektir. Moduna bağlı olarak (sessiz izin verilen bağlantılar, sessiz reddedilen bağlantılar ve uyarı) her yeni bağlantı kurulduğunda **size bir uyarı gösterecektir**. Ayrıca tüm bu bilgileri görmek için çok güzel bir GUI'ye sahiptir.
- [**LuLu**](https://objective-see.org/products/lulu.html): Objective-See güvenlik duvarı. Şüpheli bağlantılar için sizi uyaran temel bir güvenlik duvarıdır (bir GUI'si vardır ama Little Snitch'inki kadar şık değildir).

## Persistence detection

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): **Kötü amaçlı yazılımların kalıcı olabileceği** çeşitli yerlerde arama yapan Objective-See uygulamasıdır (tek seferlik bir araçtır, izleme servisi değildir).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Kalıcılık oluşturan süreçleri izleyerek KnockKnock gibi çalışır.

## Keyloggers detection

- [**ReiKey**](https://objective-see.org/products/reikey.html): Klavye "olay tapeleri" kuran **keylogger'ları** bulmak için Objective-See uygulamasıdır.

{{#include ../../banners/hacktricks-training.md}}
