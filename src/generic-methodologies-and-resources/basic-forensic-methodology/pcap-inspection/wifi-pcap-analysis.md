# Ανάλυση Wifi Pcap

{{#include ../../../banners/hacktricks-training.md}}

## Έλεγχος BSSID

Με ανοιχτό ένα Wi-Fi capture στο Wireshark, επιλέξτε _Wireless → WLAN Traffic_ για να δείτε συνοπτικά τα ασύρματα δίκτυα που εντοπίστηκαν στο capture· κάθε γραμμή αντιστοιχεί σε ένα ασύρματο δίκτυο.<sup>[[1]](#references)</sup>

![Ανάλυση Wifi Pcap - Έλεγχος BSSID: Όταν λαμβάνετε ένα capture του οποίου η κύρια κίνηση είναι Wifi και χρησιμοποιείτε το WireShark, μπορείτε να ξεκινήσετε να εξετάζετε όλα τα SSID του capture από το Wireless --...](<../../../images/image (106).png>)

![Ανάλυση Wifi Pcap - Έλεγχος BSSID: Όταν λαμβάνετε ένα capture του οποίου η κύρια κίνηση είναι Wifi και χρησιμοποιείτε το WireShark, μπορείτε να ξεκινήσετε να εξετάζετε όλα τα SSID του capture από το Wireless --...](<../../../images/image (492).png>)

### Brute Force

Για capture WPA/WPA2-PSK, το `aircrack-ng` χρειάζεται ένα έγκυρο four-way EAPOL handshake και δοκιμάζει υποψήφιες φράσεις πρόσβασης από ένα λεξικό. Χρησιμοποιήστε το `-w` για να ορίσετε τη λίστα λέξεων και το `-b` για να στοχεύσετε το BSSID του access point:<sup>[[2]](#references)</sup>

```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```

Αν γίνει αντιστοιχία, το Aircrack-ng ανακτά το pre-shared key· έπειτα, ο αντίστοιχος κωδικός πρόσβασης και το SSID μπορούν να διαμορφωθούν στις ρυθμίσεις αποκρυπτογράφησης 802.11 του Wireshark, εφόσον το capture και η λειτουργία ασφάλειας το υποστηρίζουν.<sup>[[2]](#references)[[5]](#references)</sup>

## Δεδομένα σε Beacons / Side Channel

Αν υποψιάζεστε ότι **διαρρέουν δεδομένα μέσω beacon-side-channel traffic**, ξεκινήστε με ένα display filter όπως `wlan contains "NAMEofNETWORK"` ή `wlan.ssid == "NAMEofNETWORK"` και, στη συνέχεια, ελέγξτε τα αντίστοιχα frames για ύποπτες συμβολοσειρές. Η πρώτη μορφή εκτελεί ευρεία αναζήτηση bytes· η δεύτερη αντιστοιχίζει το πεδίο SSID.<sup>[[3]](#references)[[4]](#references)</sup>

## Εύρεση Άγνωστων MAC Addresses σε Δίκτυο Wi-Fi

Το Wireshark εκθέτει το `wlan.ta` ως τη διεύθυνση transmitter και το `wlan.addr` ως hardware/MAC address· τα display filters μπορούν να συνδυάσουν αυτά τα πεδία με λογικούς τελεστές:<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Αν γνωρίζετε ήδη **MAC addresses, αφαιρέστε τις από το output** προσθέτοντας ελέγχους όπως `&& !(wlan.addr == 5c:51:88:31:a0:3b)`.

Αφού εντοπίσετε **άγνωστες MAC** addresses που επικοινωνούν μέσα στο δίκτυο, χρησιμοποιήστε ένα filter όπως `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)` για να περιορίσετε την κίνηση. Τα filters FTP, HTTP, SSH και Telnet είναι χρήσιμα μόνο όταν το Wireshark μπορεί να αναλύσει το αντίστοιχο αποκρυπτογραφημένο payload.<sup>[[3]](#references)[[5]](#references)</sup>

## Αποκρυπτογράφηση Traffic

Για να προσθέσετε ένα κλειδί αποκρυπτογράφησης 802.11 στο Wireshark, ανοίξτε _Edit → Preferences → Protocols → IEEE 802.11_ και πατήστε _Edit_ δίπλα στο _Decryption Keys_.<sup>[[5]](#references)</sup>

![Εύρεση Άγνωστων MAC Addresses σε Δίκτυο Wi-Fi - Αποκρυπτογράφηση Traffic: Αφού εντοπίσετε άγνωστες MAC addresses που επικοινωνούν μέσα στο δίκτυο, μπορείτε να χρησιμοποιήσετε filters όπως το παρακάτω:...](<../../../images/image (499).png>)

Για WPA/WPA2, το Wireshark συνήθως χρειάζεται το EAPOL four-way handshake και τον αντίστοιχο κωδικό πρόσβασης/SSID· η παροχή του transient key μπορεί να παρακάμψει την απαίτηση για handshake. Η αποκρυπτογράφηση WPA3 ανά σύνδεση απαιτεί το PMK της σύνδεσης.<sup>[[5]](#references)</sup>

Για αποκρυπτογράφηση TLS στο application layer μετά την ανάκτηση της κίνησης Wi-Fi, δείτε τα [κόλπα του Wireshark](wireshark-tricks.md#decrypting-tls).

## References

- [1] [Οδηγός χρήσης του Wireshark: Κίνηση WLAN](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Οδηγός χρήσης του Wireshark: Δημιουργία εκφράσεων Display Filter](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Αναφορά Display Filter του Wireshark: Ασύρματο LAN IEEE 802.11](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Οδηγός χρήσης του Wireshark: Κλειδιά αποκρυπτογράφησης IEEE 802.11 WLAN](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
