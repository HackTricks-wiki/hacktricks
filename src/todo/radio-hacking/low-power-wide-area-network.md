# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## Εισαγωγή

**Low-Power Wide Area Network** (LPWAN) είναι μια ομάδα ασύρματων, χαμηλής κατανάλωσης, τεχνολογιών ευρείας περιοχής σχεδιασμένων για **μακρινές επικοινωνίες** με χαμηλό ρυθμό μετάδοσης.
Μπορούν να φτάσουν περισσότερα από **έξι μίλια** και οι **μπαταρίες** τους μπορούν να διαρκέσουν έως **20 χρόνια**.

Long Range (**LoRa**) είναι αυτή τη στιγμή η πιο αναπτυγμένη φυσική στρώση LPWAN και η ανοιχτή προδιαγραφή MAC-layer της είναι **LoRaWAN**.

---

## LPWAN, LoRa, και LoRaWAN

* LoRa – Chirp Spread Spectrum (CSS) φυσική στρώση που αναπτύχθηκε από την Semtech (ιδιωτική αλλά τεκμηριωμένη).
* LoRaWAN – Ανοιχτή στρώση MAC/Δικτύου που διατηρείται από την LoRa-Alliance. Οι εκδόσεις 1.0.x και 1.1 είναι κοινές στο πεδίο.
* Τυπική αρχιτεκτονική: *end-device → gateway (packet-forwarder) → network-server → application-server*.

> Το **μοντέλο ασφάλειας** βασίζεται σε δύο κλειδιά ρίζας AES-128 (AppKey/NwkKey) που παράγουν κλειδιά συνεδρίας κατά τη διάρκεια της διαδικασίας *join* (OTAA) ή είναι σκληρά κωδικοποιημένα (ABP). Εάν οποιοδήποτε κλειδί διαρρεύσει, ο επιτιθέμενος αποκτά πλήρη δυνατότητα ανάγνωσης/εγγραφής πάνω στην αντίστοιχη κίνηση.

---

## Περίληψη επιφάνειας επίθεσης

| Στρώση | Αδυναμία | Πρακτική επίδραση |
|-------|----------|------------------|
| PHY | Αντιδραστική / επιλεκτική παρεμβολή | 100 % απώλεια πακέτων αποδεδειγμένη με ένα μόνο SDR και <1 W έξοδο |
| MAC | Join-Accept & επανάληψη πλαισίου δεδομένων (επανάχρηση nonce, ABP counter rollover) | Spoofing συσκευών, εισαγωγή μηνυμάτων, DoS |
| Network-Server | Ανασφαλής packet-forwarder, αδύναμοι φίλτροι MQTT/UDP, παρωχημένο firmware πύλης | RCE σε πύλες → pivot σε OT/IT δίκτυο |
| Εφαρμογή | Σκληρά κωδικοποιημένα ή προβλέψιμα AppKeys | Brute-force/αποκρυπτογράφηση κίνησης, μίμηση αισθητήρων |

---

## Πρόσφατες ευπάθειες (2023-2025)

* **CVE-2024-29862** – *ChirpStack gateway-bridge & mqtt-forwarder* δέχτηκε TCP πακέτα που παρακάμπτουν τους κανόνες stateful firewall σε πύλες Kerlink, επιτρέποντας την έκθεση της απομακρυσμένης διαχείρισης. Διορθώθηκε στην 4.0.11 / 4.2.1 αντίστοιχα.
* **Dragino LG01/LG308 σειρά** – Πολλαπλές CVEs 2022-2024 (π.χ. 2022-45227 directory traversal, 2022-45228 CSRF) παρατηρούνται ακόμα χωρίς διόρθωση το 2025; ενεργοποιούν μη αυθεντικοποιημένη απόρριψη firmware ή επαναφορά ρυθμίσεων σε χιλιάδες δημόσιες πύλες.
* Semtech *packet-forwarder UDP* overflow (μη δημοσιευθείσα προειδοποίηση, διορθώθηκε 2023-10): κατασκευασμένο uplink μεγαλύτερο από 255 B προκάλεσε stack-smash ‑> RCE σε πύλες αναφοράς SX130x (βρέθηκε από το Black Hat EU 2023 “LoRa Exploitation Reloaded”).

---

## Πρακτικές τεχνικές επίθεσης

### 1. Sniff & Decrypt traffic
```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
--freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```
### 2. OTAA join-replay (Επαναχρησιμοποίηση DevNonce)

1. Συλλέξτε ένα νόμιμο **JoinRequest**.
2. Άμεσα επαναμεταδώστε το (ή αυξήστε το RSSI) πριν το αρχικό συσκευή μεταδώσει ξανά.
3. Ο διακομιστής δικτύου εκχωρεί μια νέα DevAddr & κλειδιά συνεδρίας ενώ η στοχευμένη συσκευή συνεχίζει με την παλιά συνεδρία → ο επιτιθέμενος κατέχει κενή συνεδρία και μπορεί να εισάγει πλαστά uplinks.

### 3. Adaptive Data-Rate (ADR) υποβάθμιση

Αναγκάστε το SF12/125 kHz να αυξήσει τον χρόνο αέρα → εξαντλήστε τον κύκλο καθήκοντος της πύλης (άρνηση υπηρεσίας) ενώ διατηρείτε τον αντίκτυπο της μπαταρίας χαμηλό στον επιτιθέμενο (απλώς στείλτε εντολές MAC επιπέδου δικτύου).

### 4. Αντιδραστική παρεμβολή

*HackRF One* που εκτελεί ροή GNU Radio ενεργοποιεί ένα ευρύ φάσμα chirp όποτε ανιχνεύεται προάγγελος – μπλοκάρει όλους τους παράγοντες διάδοσης με ≤200 mW TX; πλήρης διακοπή μετρήθηκε σε απόσταση 2 χλμ.

---

## Offensive tooling (2025)

| Tool | Purpose | Notes |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Δημιουργία/ανάλυση/επίθεση σε πλαίσια LoRaWAN, αναλυτές με βάση τη βάση δεδομένων, brute-forcer | Εικόνα Docker, υποστηρίζει είσοδο Semtech UDP |
| **LoRaPWN** | Εργαλείο Python της Trend Micro για brute OTAA, δημιουργία downlinks, αποκρυπτογράφηση payloads | Demo που κυκλοφόρησε το 2023, SDR-agnostic |
| **LoRAttack** | Multi-channel sniffer + replay με USRP; εξάγει PCAP/LoRaTap | Καλή ενσωμάτωση με Wireshark |
| **gr-lora / gr-lorawan** | GNU Radio OOT blocks για TX/RX βάσης | Θεμέλιο για προσαρμοσμένες επιθέσεις |

---

## Defensive recommendations (checklist pentester)

1. Προτιμήστε **OTAA** συσκευές με πραγματικά τυχαίο DevNonce; παρακολουθήστε διπλότυπα.
2. Επιβάλετε **LoRaWAN 1.1**: 32-bit μετρητές πλαισίων, διακριτά FNwkSIntKey / SNwkSIntKey.
3. Αποθηκεύστε τον μετρητή πλαισίου σε μη πτητική μνήμη (**ABP**) ή μεταναστεύστε σε OTAA.
4. Αναπτύξτε **secure-element** (ATECC608A/SX1262-TRX-SE) για να προστατεύσετε τις ρίζες κλειδιά από την εξαγωγή firmware.
5. Απενεργοποιήστε τις απομακρυσμένες θύρες UDP packet-forwarder (1700/1701) ή περιορίστε με WireGuard/VPN.
6. Διατηρήστε τις πύλες ενημερωμένες; Οι Kerlink/Dragino παρέχουν εικόνες με διορθώσεις του 2024.
7. Εφαρμόστε **ανίχνευση ανωμαλιών κυκλοφορίας** (π.χ., αναλυτής LAF) – σημειώστε επαναφορές μετρητών, διπλές συμμετοχές, ξαφνικές αλλαγές ADR.

## References

* LoRaWAN Auditing Framework (LAF) – https://github.com/IOActive/laf
* Trend Micro LoRaPWN overview – https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a
{{#include ../../banners/hacktricks-training.md}}
