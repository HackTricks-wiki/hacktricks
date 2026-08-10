# Аналіз Wifi Pcap

## Перевірка BSSID

Відкривши Wi-Fi capture у Wireshark, виберіть _Wireless → WLAN Traffic_, щоб узагальнити бездротові мережі, виявлені в capture; кожен рядок відповідає одній бездротовій мережі.<sup>[[1]](#references)</sup>

![Аналіз Wifi Pcap - Перевірка BSSID: Коли ви отримуєте capture, основний трафік якого є Wifi, використовуючи WireShark, ви можете почати досліджувати всі SSID у capture за допомогою Wireless --...](<../../../images/image (106).png>)

![Аналіз Wifi Pcap - Перевірка BSSID: Коли ви отримуєте capture, основний трафік якого є Wifi, використовуючи WireShark, ви можете почати досліджувати всі SSID у capture за допомогою Wireless --...](<../../../images/image (492).png>)

### Brute Force

Для capture WPA/WPA2-PSK `aircrack-ng` потребує придатного чотиристороннього EAPOL handshake і перевіряє паролі-кандидати за допомогою словника. Використовуйте `-w`, щоб указати wordlist, і `-b`, щоб вибрати BSSID точки доступу:<sup>[[2]](#references)</sup>
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Якщо кандидат збігається, Aircrack-ng відновлює попередньо узгоджений ключ; відповідний пароль і SSID потім можна налаштувати в параметрах розшифрування 802.11 у Wireshark, якщо захоплення та режим безпеки це підтримують.<sup>[[2]](#references)[[5]](#references)</sup>

## Дані в маяках / Side Channel

Якщо ви підозрюєте, що **дані витікають у beacon-side-channel traffic**, почніть із display filter, наприклад `wlan contains "NAMEofNETWORK"` або `wlan.ssid == "NAMEofNETWORK"`, а потім перевірте відповідні кадри на наявність підозрілих рядків. Перша форма виконує широкий пошук байтів; друга відповідає полю SSID.<sup>[[3]](#references)[[4]](#references)</sup>

## Пошук невідомих MAC-адрес у Wi-Fi мережі

Wireshark надає `wlan.ta` як адресу передавача, а `wlan.addr` — як апаратну/MAC-адресу; display filters можуть поєднувати ці поля за допомогою логічних операторів:<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Якщо ви вже знаєте **MAC-адреси, вилучіть їх із результатів**, додавши такі перевірки, як `&& !(wlan.addr == 5c:51:88:31:a0:3b)`.

Після виявлення **невідомих MAC-адрес**, які обмінюються даними всередині мережі, використовуйте filter на кшталт `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)`, щоб звузити перелік її traffic. Фільтри FTP, HTTP, SSH і Telnet корисні лише тоді, коли Wireshark може виконати dissect відповідного розшифрованого payload.<sup>[[3]](#references)[[5]](#references)</sup>

## Розшифрування traffic

Щоб додати ключ розшифрування 802.11 у Wireshark, відкрийте _Edit → Preferences → Protocols → IEEE 802.11_ і натисніть _Edit_ поруч із _Decryption Keys_.<sup>[[5]](#references)</sup>

![Пошук невідомих MAC-адрес у Wi-Fi мережі — розшифрування traffic: після виявлення невідомих MAC-адрес, які обмінюються даними всередині мережі, можна використовувати такі filters:...](<../../../images/image (499).png>)

Для WPA/WPA2 Wireshark зазвичай потребує чотиристороннього EAPOL handshake і відповідних пароля/SSID; надання transient key може усунути потребу в handshake. Для розшифрування WPA3 окремого з'єднання потрібен PMK цього з'єднання.<sup>[[5]](#references)</sup>

## References

- [1] [Посібник користувача Wireshark: WLAN traffic](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Посібник користувача Wireshark: побудова виразів display filter](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Довідник display filter Wireshark: бездротова LAN IEEE 802.11](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Посібник користувача Wireshark: ключі розшифрування IEEE 802.11 WLAN](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
