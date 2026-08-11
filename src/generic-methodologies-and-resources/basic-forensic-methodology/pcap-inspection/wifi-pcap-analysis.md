# Аналіз Wifi Pcap

{{#include ../../../banners/hacktricks-training.md}}

## Перевірка BSSID

Коли capture Wi-Fi відкрито у Wireshark, виберіть _Wireless → WLAN Traffic_, щоб узагальнити бездротові мережі, виявлені у capture; кожен рядок відповідає одній бездротовій мережі.<sup>[[1]](#references)</sup>

![Аналіз Wifi Pcap - Перевірка BSSID: Коли ви отримуєте capture, основний трафік якого є Wifi, використовуючи WireShark, ви можете почати досліджувати всі SSID у capture через Wireless --...](<../../../images/image (106).png>)

![Аналіз Wifi Pcap - Перевірка BSSID: Коли ви отримуєте capture, основний трафік якого є Wifi, використовуючи WireShark, ви можете почати досліджувати всі SSID у capture через Wireless --...](<../../../images/image (492).png>)

### Brute Force

Для capture WPA/WPA2-PSK `aircrack-ng` потребує придатного чотиристороннього EAPOL handshake і перевіряє candidate passphrases за допомогою dictionary. Використовуйте `-w`, щоб вказати wordlist, і `-b`, щоб вказати BSSID точки доступу:<sup>[[2]](#references)</sup>
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Якщо кандидат збігається, Aircrack-ng відновлює попередньо спільний ключ; відповідний пароль і SSID можна налаштувати в параметрах розшифрування 802.11 у Wireshark, якщо захоплення та режим безпеки це підтримують.<sup>[[2]](#references)[[5]](#references)</sup>

## Дані в Beacon / Side Channel

Якщо ви підозрюєте, що **дані витікають у beacon-side-channel traffic**, почніть із display filter, наприклад `wlan contains "NAMEofNETWORK"` або `wlan.ssid == "NAMEofNETWORK"`, а потім перевірте відповідні кадри на наявність підозрілих рядків. Перша форма виконує широкий пошук байтів; друга відповідає полю SSID.<sup>[[3]](#references)[[4]](#references)</sup>

## Пошук невідомих MAC-адрес у Wi-Fi Network

Wireshark надає `wlan.ta` як адресу передавача, а `wlan.addr` — як апаратну/MAC-адресу; display filters можуть поєднувати ці поля за допомогою логічних операторів:<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Якщо ви вже знаєте **MAC-адреси, видаліть їх із результатів** за допомогою додаткових перевірок, наприклад `&& !(wlan.addr == 5c:51:88:31:a0:3b)`.

Після виявлення **невідомих MAC-адрес**, які обмінюються даними всередині мережі, використовуйте фільтр на кшталт `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)`, щоб звузити перелік її traffic. Фільтри FTP, HTTP, SSH і Telnet корисні лише тоді, коли Wireshark може розібрати відповідне розшифроване payload.<sup>[[3]](#references)[[5]](#references)</sup>

## Розшифрування Traffic

Щоб додати ключ розшифрування 802.11 у Wireshark, відкрийте _Edit → Preferences → Protocols → IEEE 802.11_ і натисніть _Edit_ поруч із _Decryption Keys_.<sup>[[5]](#references)</sup>

![Пошук невідомих MAC-адрес у Wi-Fi Network - Розшифрування Traffic: після виявлення невідомих MAC-адрес, які обмінюються даними всередині мережі, можна використовувати такі фільтри:...](<../../../images/image (499).png>)

Для WPA/WPA2 Wireshark зазвичай потребує EAPOL four-way handshake і відповідного пароля/SSID; надання transient key може усунути потребу в handshake. Для розшифрування WPA3 для кожного з'єднання потрібен PMK з'єднання.<sup>[[5]](#references)</sup>

## References

- [1] [Посібник користувача Wireshark: WLAN Traffic](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Посібник користувача Wireshark: Створення виразів Display Filter](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Довідник Display Filter Wireshark: IEEE 802.11 wireless LAN](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Посібник користувача Wireshark: Ключі розшифрування IEEE 802.11 WLAN](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
