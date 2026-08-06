# Ανάλυση Wifi Pcap

{{#include ../../../banners/hacktricks-training.md}}

## Έλεγχος BSSIDs

Όταν λαμβάνετε ένα capture του οποίου η κύρια κίνηση είναι Wifi μέσω του WireShark, μπορείτε να ξεκινήσετε την έρευνα όλων των SSIDs του capture με το _Wireless --> WLAN Traffic_:

![Ανάλυση Wifi Pcap - Έλεγχος BSSIDs: Όταν λαμβάνετε ένα capture του οποίου η κύρια κίνηση είναι Wifi μέσω του WireShark, μπορείτε να ξεκινήσετε την έρευνα όλων των SSIDs του capture με το Wireless --...](<../../../images/image (106).png>)

![Ανάλυση Wifi Pcap - Έλεγχος BSSIDs: Όταν λαμβάνετε ένα capture του οποίου η κύρια κίνηση είναι Wifi μέσω του WireShark, μπορείτε να ξεκινήσετε την έρευνα όλων των SSIDs του capture με το Wireless --...](<../../../images/image (492).png>)

### Brute Force

Μία από τις στήλες αυτής της οθόνης υποδεικνύει αν **βρέθηκε οποιοσδήποτε έλεγχος ταυτότητας μέσα στο pcap**. Αν ισχύει αυτό, μπορείτε να προσπαθήσετε να τον κάνετε Brute force χρησιμοποιώντας το `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Για παράδειγμα, θα ανακτήσει το WPA passphrase που προστατεύει ένα PSK (pre shared-key), το οποίο θα απαιτείται για την αποκρυπτογράφηση της κίνησης αργότερα.

## Δεδομένα σε Beacons / Side Channel

Αν υποψιάζεστε ότι **δεδομένα διαρρέουν μέσα στα beacons ενός Wifi network**, μπορείτε να ελέγξετε τα beacons του network χρησιμοποιώντας ένα filter όπως το ακόλουθο: `wlan contains <NAMEofNETWORK>`, ή `wlan.ssid == "NAMEofNETWORK"` και να αναζητήσετε ύποπτες συμβολοσειρές μέσα στα filtered packets.

## Εύρεση Άγνωστων MAC Addresses σε Ένα Wifi Network

Ο ακόλουθος σύνδεσμος θα είναι χρήσιμος για την εύρεση των **μηχανημάτων που στέλνουν δεδομένα μέσα σε ένα Wifi Network**:

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Αν γνωρίζετε ήδη **MAC addresses, μπορείτε να τις αφαιρέσετε από το output**, προσθέτοντας checks όπως το ακόλουθο: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Αφού εντοπίσετε **άγνωστες MAC addresses** που επικοινωνούν μέσα στο network, μπορείτε να χρησιμοποιήσετε **filters** όπως το ακόλουθο: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)` για να φιλτράρετε την κίνησή τους. Σημειώστε ότι τα ftp/http/ssh/telnet filters είναι χρήσιμα αν έχετε αποκρυπτογραφήσει την κίνηση.

## Αποκρυπτογράφηση Κίνησης

Edit --> Preferences --> Protocols --> IEEE 802.11--> Edit

![Εύρεση Άγνωστων MAC Addresses σε Ένα Wifi Network - Αποκρυπτογράφηση Κίνησης: Αφού εντοπίσετε άγνωστες MAC addresses που επικοινωνούν μέσα στο network, μπορείτε να χρησιμοποιήσετε filters όπως το ακόλουθο:...](<../../../images/image (499).png>)

{{#include ../../../banners/hacktricks-training.md}}
