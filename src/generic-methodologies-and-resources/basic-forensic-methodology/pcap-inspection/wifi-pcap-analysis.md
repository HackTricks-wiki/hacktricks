# Ανάλυση Wifi Pcap

## Έλεγχος BSSIDs

Με μια Wi-Fi capture ανοιχτή στο Wireshark, επιλέξτε _Wireless → WLAN Traffic_ για να συνοψίσετε τα wireless networks που παρατηρήθηκαν στην capture· κάθε γραμμή αντιπροσωπεύει ένα wireless network.<sup>[[1]](#references)</sup>

![Ανάλυση Wifi Pcap - Έλεγχος BSSIDs: Όταν λαμβάνετε μια capture της οποίας η κύρια κίνηση είναι Wifi με χρήση του WireShark, μπορείτε να ξεκινήσετε την έρευνα όλων των SSIDs της capture μέσω του Wireless --...](<../../../images/image (106).png>)

![Ανάλυση Wifi Pcap - Έλεγχος BSSIDs: Όταν λαμβάνετε μια capture της οποίας η κύρια κίνηση είναι Wifi με χρήση του WireShark, μπορείτε να ξεκινήσετε την έρευνα όλων των SSIDs της capture μέσω του Wireless --...](<../../../images/image (492).png>)

### Brute Force

Για WPA/WPA2-PSK captures, το `aircrack-ng` απαιτεί ένα usable four-way EAPOL handshake και ελέγχει candidate passphrases με ένα dictionary. Χρησιμοποιήστε το `-w` για να καθορίσετε το wordlist και το `-b` για να στοχεύσετε το BSSID του access point:<sup>[[2]](#references)</sup>
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Εάν βρεθεί υποψήφιο που ταιριάζει, το Aircrack-ng ανακτά το pre-shared key· στη συνέχεια, το password και το SSID που ταιριάζουν μπορούν να ρυθμιστούν στις ρυθμίσεις αποκρυπτογράφησης 802.11 του Wireshark, όταν το capture και το security mode το υποστηρίζουν.<sup>[[2]](#references)[[5]](#references)</sup>

## Δεδομένα σε Beacons / Side Channel

Εάν υποψιάζεστε ότι **δεδομένα διαρρέουν σε beacon-side-channel traffic**, ξεκινήστε με ένα display filter όπως `wlan contains "NAMEofNETWORK"` ή `wlan.ssid == "NAMEofNETWORK"`, και στη συνέχεια ελέγξτε τα matching frames για ύποπτες συμβολοσειρές. Η πρώτη μορφή εκτελεί ευρεία αναζήτηση bytes· η δεύτερη αντιστοιχεί στο πεδίο SSID.<sup>[[3]](#references)[[4]](#references)</sup>

## Εύρεση άγνωστων MAC διευθύνσεων σε Wi-Fi Network

Το Wireshark εμφανίζει το `wlan.ta` ως transmitter address και το `wlan.addr` ως hardware/MAC address· τα display filters μπορούν να συνδυάσουν αυτά τα πεδία με logical operators:<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Εάν γνωρίζετε ήδη **MAC addresses, αφαιρέστε τις από το output** προσθέτοντας checks όπως `&& !(wlan.addr == 5c:51:88:31:a0:3b)`.

Μόλις εντοπίσετε **άγνωστες MAC** addresses που επικοινωνούν μέσα στο network, χρησιμοποιήστε ένα filter όπως `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)` για να περιορίσετε το traffic της. Τα FTP, HTTP, SSH και Telnet filters είναι χρήσιμα μόνο όταν το Wireshark μπορεί να κάνει dissect το αντίστοιχο decrypted payload.<sup>[[3]](#references)[[5]](#references)</sup>

## Αποκρυπτογράφηση Traffic

Για να προσθέσετε ένα 802.11 decryption key στο Wireshark, ανοίξτε _Edit → Preferences → Protocols → IEEE 802.11_ και κάντε κλικ στο _Edit_ δίπλα στο _Decryption Keys_.<sup>[[5]](#references)</sup>

![Εύρεση άγνωστων MAC διευθύνσεων σε Wi-Fi Network - Αποκρυπτογράφηση Traffic: Μόλις εντοπίσετε άγνωστες MAC διευθύνσεις που επικοινωνούν μέσα στο network, μπορείτε να χρησιμοποιήσετε filters όπως το ακόλουθο:...](<../../../images/image (499).png>)

Για WPA/WPA2, το Wireshark συνήθως χρειάζεται το EAPOL four-way handshake και το matching password/SSID· η παροχή του transient key μπορεί να παρακάμψει την απαίτηση για handshake. Η per-connection αποκρυπτογράφηση WPA3 απαιτεί το PMK της σύνδεσης.<sup>[[5]](#references)</sup>

## References

- [1] [Οδηγός χρήσης του Wireshark: WLAN Traffic](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Οδηγός χρήσης του Wireshark: Building Display Filter Expressions](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Wireshark Display Filter Reference: IEEE 802.11 wireless LAN](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Οδηγός χρήσης του Wireshark: IEEE 802.11 WLAN Decryption Keys](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
