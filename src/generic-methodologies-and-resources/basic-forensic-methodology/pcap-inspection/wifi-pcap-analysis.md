# Аналіз Wifi Pcap

{{#include ../../../banners/hacktricks-training.md}}

## Перевірка BSSID

Коли ви отримуєте capture, основний трафік якого передається через Wifi, у WireShark можна почати досліджувати всі SSID capture за допомогою _Wireless --> WLAN Traffic_:

![Аналіз Wifi Pcap - Перевірка BSSID: Коли ви отримуєте capture, основний трафік якого передається через Wifi, у WireShark можна почати досліджувати всі SSID capture за допомогою Wireless --...](<../../../images/image (106).png>)

![Аналіз Wifi Pcap - Перевірка BSSID: Коли ви отримуєте capture, основний трафік якого передається через Wifi, у WireShark можна почати досліджувати всі SSID capture за допомогою Wireless --...](<../../../images/image (492).png>)

### Brute Force

Один зі стовпців цього екрана вказує, чи було **виявлено будь-яку authentication усередині pcap**. Якщо це так, можна спробувати виконати Brute force за допомогою `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Наприклад, це дозволить отримати WPA passphrase, що захищає PSK (pre shared-key), який буде потрібен для подальшого розшифрування трафіку.

## Дані в Beacons / Side Channel

Якщо ви підозрюєте, що **дані витікають усередині beacons Wi-Fi мережі**, ви можете перевірити beacons мережі за допомогою фільтра на кшталт: `wlan contains <NAMEofNETWORK>` або `wlan.ssid == "NAMEofNETWORK"`, а потім пошукати підозрілі рядки серед відфільтрованих пакетів.

## Пошук невідомих MAC-адрес у Wi-Fi мережі

Наступне посилання допоможе знайти **машини, що надсилають дані всередині Wi-Fi мережі**:

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Якщо ви вже знаєте **MAC-адреси, їх можна видалити з результатів**, додавши такі перевірки: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Після виявлення **невідомих MAC-адрес**, які обмінюються даними всередині мережі, ви можете використовувати **фільтри** на кшталт `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)`, щоб відфільтрувати їхній трафік. Зверніть увагу, що фільтри ftp/http/ssh/telnet корисні, якщо ви розшифрували трафік.

## Розшифрування трафіку

Edit --> Preferences --> Protocols --> IEEE 802.11--> Edit

![Пошук невідомих MAC-адрес у Wi-Fi мережі — Розшифрування трафіку: після виявлення невідомих MAC-адрес, які обмінюються даними всередині мережі, ви можете використовувати такі фільтри:...](<../../../images/image (499).png>)

{{#include ../../../banners/hacktricks-training.md}}
