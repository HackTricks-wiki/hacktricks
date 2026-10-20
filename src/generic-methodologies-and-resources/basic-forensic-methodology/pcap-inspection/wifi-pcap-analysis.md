# Uchambuzi wa Wifi Pcap

{{#include ../../../banners/hacktricks-training.md}}

## Kagua BSSIDs

Ukiwa na capture ya Wi-Fi iliyofunguliwa katika Wireshark, chagua _Wireless → WLAN Traffic_ ili kufupisha mitandao isiyotumia waya iliyoonekana kwenye capture; kila safu inawakilisha mtandao mmoja usiotumia waya.<sup>[[1]](#references)</sup>

![Uchambuzi wa Wifi Pcap - Kagua BSSIDs: Unapopokea capture ambayo trafiki yake kuu ni Wifi, ukitumia WireShark unaweza kuanza kuchunguza SSIDs zote za capture kupitia Wireless --...](<../../../images/image (106).png>)

![Uchambuzi wa Wifi Pcap - Kagua BSSIDs: Unapopokea capture ambayo trafiki yake kuu ni Wifi, ukitumia WireShark unaweza kuanza kuchunguza SSIDs zote za capture kupitia Wireless --...](<../../../images/image (492).png>)

### Brute Force

Kwa capture za WPA/WPA2-PSK, `aircrack-ng` inahitaji handshake halali ya EAPOL ya hatua nne na hujaribu passphrase zinazowezekana kwa kutumia kamusi. Tumia `-w` kutoa wordlist na `-b` kulenga BSSID ya access point:<sup>[[2]](#references)</sup>

```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```

Ikiwa candidate inalingana, Aircrack-ng hurejesha pre-shared key; password na SSID zinazolingana zinaweza kisha kusanidiwa katika mipangilio ya usimbuaji wa 802.11 ya Wireshark, ikiwa capture na security mode vinaiunga mkono.<sup>[[2]](#references)[[5]](#references)</sup>

## Data katika Beacons / Side Channel

Ikiwa unashuku kuwa **data inavuja kupitia beacon-side-channel traffic**, anza na display filter kama `wlan contains "NAMEofNETWORK"` au `wlan.ssid == "NAMEofNETWORK"`, kisha kagua frames zinazolingana ili kutafuta strings zinazotiliwa shaka. Fomu ya kwanza hutafuta bytes kwa upana; ya pili hulinganisha sehemu ya SSID.<sup>[[3]](#references)[[4]](#references)</sup>

## Tafuta Anwani za MAC Zisizojulikana katika Mtandao wa Wi-Fi

Wireshark huonyesha `wlan.ta` kama anwani ya mtumaji na `wlan.addr` kama anwani ya hardware/MAC; display filters zinaweza kuchanganya sehemu hizi kwa kutumia logical operators:<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Ikiwa tayari unajua **anwani za MAC, ziondoe kwenye matokeo** kwa kuongeza masharti kama `&& !(wlan.addr == 5c:51:88:31:a0:3b)`.

Baada ya kugundua anwani za **MAC zisizojulikana** zinazowasiliana ndani ya mtandao, tumia filter kama `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)` ili kupunguza traffic yake. Filters za FTP, HTTP, SSH na Telnet zinafaa tu wakati Wireshark inaweza kuchanganua payload iliyosimbuliwa inayolingana.<sup>[[3]](#references)[[5]](#references)</sup>

## Simbua Traffic

Ili kuongeza ufunguo wa usimbuaji wa 802.11 katika Wireshark, fungua _Edit → Preferences → Protocols → IEEE 802.11_ na ubofye _Edit_ karibu na _Decryption Keys_.<sup>[[5]](#references)</sup>

![Tafuta Anwani za MAC Zisizojulikana katika Mtandao wa Wifi - Simbua Traffic: Baada ya kugundua anwani za MAC zisizojulikana zinazowasiliana ndani ya mtandao, unaweza kutumia filters kama ifuatayo:...](<../../../images/image (499).png>)

Kwa WPA/WPA2, Wireshark huhitaji kwa kawaida EAPOL four-way handshake na password/SSID zinazolingana; kutoa transient key kunaweza kuondoa hitaji la handshake. Usimbuaji wa WPA3 kwa kila connection unahitaji PMK ya connection hiyo.<sup>[[5]](#references)</sup>

Kwa usimbuaji wa TLS wa application layer baada ya kurejesha traffic ya Wi-Fi, angalia [mbinu za Wireshark](wireshark-tricks.md#decrypting-tls).

## References

- [1] [Mwongozo wa Mtumiaji wa Wireshark: Traffic ya WLAN](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Mwongozo wa Mtumiaji wa Wireshark: Kuunda Miunganiko ya Display Filter](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Marejeleo ya Wireshark Display Filter: IEEE 802.11 wireless LAN](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Mwongozo wa Mtumiaji wa Wireshark: Ufunguo wa Usimbuaji wa IEEE 802.11 WLAN](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
