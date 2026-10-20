# Аналіз Wi-Fi Pcap

{{#include ../../../banners/hacktricks-training.md}}

## Перевірка BSSID

Відкривши захоплення Wi-Fi-трафіку у Wireshark, виберіть _Wireless → WLAN Traffic_, щоб переглянути зведення про бездротові мережі, виявлені в захопленні; кожен рядок відповідає одній бездротовій мережі.<sup>[[1]](#references)</sup>

![Аналіз Wi-Fi Pcap — перевірка BSSID: отримавши захоплення, основний трафік якого становить Wi-Fi, у WireShark можна почати досліджувати всі SSID у захопленні за допомогою Wireless --...](<../../../images/image (106).png>)

![Аналіз Wi-Fi Pcap — перевірка BSSID: отримавши захоплення, основний трафік якого становить Wi-Fi, у WireShark можна почати досліджувати всі SSID у захопленні за допомогою Wireless --...](<../../../images/image (492).png>)

### Brute Force

Для захоплень WPA/WPA2-PSK `aircrack-ng` потрібне придатне для використання чотиристороннє рукостискання EAPOL; утиліта перевіряє можливі парольні фрази зі словника. Використовуйте `-w`, щоб указати файл зі словником, а `-b` — щоб вибрати BSSID точки доступу:<sup>[[2]](#references)</sup>

```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```

Якщо кандидат збігається, Aircrack-ng відновлює попередньо узгоджений ключ; відповідний пароль і SSID можна налаштувати в параметрах розшифрування 802.11 у Wireshark, якщо це підтримують захоплення трафіку та режим безпеки.<sup>[[2]](#references)[[5]](#references)</sup>

## Дані в Beacon-пакетах / побічний канал

Якщо ви підозрюєте, що **дані витікають у трафіку побічного каналу Beacon-пакетів**, почніть із фільтра відображення, наприклад `wlan contains "NAMEofNETWORK"` або `wlan.ssid == "NAMEofNETWORK"`, а потім перевірте відповідні кадри на наявність підозрілих рядків. Перший варіант виконує широкий пошук байтів; другий відповідає полю SSID.<sup>[[3]](#references)[[4]](#references)</sup>

## Пошук невідомих MAC-адрес у мережі Wi-Fi

Wireshark використовує `wlan.ta` як адресу передавача, а `wlan.addr` — як апаратну/MAC-адресу; фільтри відображення можуть поєднувати ці поля логічними операторами:<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Якщо ви вже знаєте **MAC-адреси, вилучіть їх із результатів**, додавши перевірки на кшталт `&& !(wlan.addr == 5c:51:88:31:a0:3b)`.

Виявивши **невідомі MAC-адреси**, що обмінюються даними всередині мережі, звузьте пошук їхнього трафіку за допомогою фільтра на кшталт `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)`. Фільтри FTP, HTTP, SSH і Telnet корисні лише тоді, коли Wireshark може розібрати відповідне розшифроване корисне навантаження.<sup>[[3]](#references)[[5]](#references)</sup>

## Розшифрування трафіку

Щоб додати ключ розшифрування 802.11 у Wireshark, відкрийте _Edit → Preferences → Protocols → IEEE 802.11_ і натисніть _Edit_ поруч із _Decryption Keys_.<sup>[[5]](#references)</sup>

![Пошук невідомих MAC-адрес у мережі Wi-Fi — розшифрування трафіку: виявивши невідомі MAC-адреси, що обмінюються даними всередині мережі, можна скористатися такими фільтрами:...](<../../../images/image (499).png>)

Для WPA/WPA2 Wireshark зазвичай потрібні чотиристороннє рукостискання EAPOL і відповідний пароль/SSID; надання тимчасового ключа дає змогу обійти вимогу щодо рукостискання. Для розшифрування WPA3 окремого з’єднання потрібен його PMK.<sup>[[5]](#references)</sup>

Щоб розшифрувати TLS на прикладному рівні після відновлення трафіку Wi-Fi, див. [поради щодо Wireshark](wireshark-tricks.md#decrypting-tls).

## References

- [1] [Посібник користувача Wireshark: трафік WLAN](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Посібник користувача Wireshark: створення виразів фільтрів відображення](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Довідник фільтрів відображення Wireshark: бездротова локальна мережа IEEE 802.11](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Посібник користувача Wireshark: ключі розшифрування WLAN IEEE 802.11](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
