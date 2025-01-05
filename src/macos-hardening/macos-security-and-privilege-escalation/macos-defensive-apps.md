# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Він буде моніторити кожне з'єднання, яке здійснює кожен процес. Залежно від режиму (тихе дозволення з'єднань, тихе відмовлення з'єднання та сповіщення) він **показуватиме вам сповіщення** щоразу, коли встановлюється нове з'єднання. Він також має дуже зручний GUI для перегляду всієї цієї інформації.
- [**LuLu**](https://objective-see.org/products/lulu.html): Брандмауер Objective-See. Це базовий брандмауер, який сповіщатиме вас про підозрілі з'єднання (він має GUI, але не такий вишуканий, як у Little Snitch).

## Persistence detection

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Застосунок Objective-See, який шукатиме в кількох місцях, де **шкідливе ПЗ може зберігатися** (це одноразовий інструмент, а не сервіс моніторингу).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Як KnockKnock, моніторячи процеси, які генерують збереження.

## Keyloggers detection

- [**ReiKey**](https://objective-see.org/products/reikey.html): Застосунок Objective-See для виявлення **кейлогерів**, які встановлюють "event taps" клавіатури.

{{#include ../../banners/hacktricks-training.md}}
