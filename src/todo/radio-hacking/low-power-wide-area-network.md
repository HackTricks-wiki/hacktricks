# Δίκτυο Ευρείας Περιοχής Χαμηλής Ισχύος

{{#include ../../banners/hacktricks-training.md}}

## Εισαγωγή

Το **Low-Power Wide Area Network** (LPWAN) είναι μια ομάδα ασύρματων τεχνολογιών δικτύων ευρείας περιοχής και χαμηλής ισχύος, σχεδιασμένων για **επικοινωνίες μεγάλης εμβέλειας** με χαμηλό ρυθμό μετάδοσης bit.
Μπορούν να φτάσουν σε απόσταση μεγαλύτερη των **έξι μιλίων** και οι **μπαταρίες** τους μπορούν να διαρκέσουν έως και **20 χρόνια**.

Το Long Range (**LoRa**) είναι σήμερα το πιο διαδεδομένο physical layer του LPWAN και η ανοιχτή προδιαγραφή του MAC layer είναι το **LoRaWAN**.

---

## LPWAN, LoRa και LoRaWAN

* LoRa – Physical layer Chirp Spread Spectrum (CSS), που αναπτύχθηκε από τη Semtech (ιδιόκτητο αλλά τεκμηριωμένο).
* LoRaWAN – Ανοιχτό MAC/Network layer που διατηρείται από τη LoRa-Alliance. Οι εκδόσεις 1.0.x και 1.1 είναι συνηθισμένες στην πράξη.
* Τυπική αρχιτεκτονική: *end-device → gateway (packet-forwarder) → network-server → application-server*.

> Το **μοντέλο ασφάλειας** βασίζεται σε δύο root keys AES-128 (AppKey/NwkKey), τα οποία παράγουν session keys κατά τη διαδικασία *join* (OTAA) ή είναι hard-coded (ABP). Αν διαρρεύσει οποιοδήποτε key, ο attacker αποκτά πλήρη δυνατότητα read/write στην αντίστοιχη κίνηση.

---

## Σύνοψη attack surface

| Layer | Αδυναμία | Πρακτικός αντίκτυπος |
|-------|----------|------------------|
| PHY | Reactive / selective jamming | Επιβεβαιώθηκε απώλεια πακέτων 100 % με ένα μόνο SDR και ισχύ εξόδου <1 W |
| MAC | Επανάληψη Join-Accept και data-frame (επαναχρησιμοποίηση nonce, rollover του ABP counter) | Spoofing συσκευών, εισαγωγή μηνυμάτων, DoS |
| Network-Server | Μη ασφαλές packet-forwarder, αδύναμα MQTT/UDP filters, παλιό firmware gateway | RCE σε gateways → pivot στο δίκτυο OT/IT |
| Application | Hard-coded ή προβλέψιμα AppKeys | Brute-force/decrypt traffic, impersonation αισθητήρων |

---

## Πρόσφατες ευπάθειες (2023-2025)

* **CVE-2024-29862** – Το *ChirpStack gateway-bridge & mqtt-forwarder* αποδεχόταν TCP packets που παρέκαμπταν τους stateful firewall rules σε Kerlink gateways, επιτρέποντας την απομακρυσμένη έκθεση του management interface. Διορθώθηκε στις εκδόσεις 4.0.11 / 4.2.1 αντίστοιχα .
* **Dragino LG01/LG308 series** – Πολλαπλά CVEs του 2022-2024 (π.χ. 2022-45227 directory traversal, 2022-45228 CSRF) εξακολουθούσαν να παρατηρούνται ως unpatched το 2025· επέτρεπαν unauthenticated firmware dump ή config overwrite σε χιλιάδες δημόσια gateways .
* Υπερχείλιση του *packet-forwarder UDP* της Semtech (unreleased advisory, patched 2023-10): ένα crafted uplink μεγαλύτερο από 255 B προκαλούσε stack-smash ‑> RCE σε reference gateways με SX130x (εντοπίστηκε στο Black Hat EU 2023 “LoRa Exploitation Reloaded”).

---

## Practical attack techniques

### 1. Sniff & Decrypt traffic
```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
--freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```
### 2. OTAA join-replay (επαναχρησιμοποίηση DevNonce)

1. Καταγράψτε ένα νόμιμο **JoinRequest**.
2. Αναμεταδώστε το αμέσως (ή αυξήστε το RSSI) πριν η αρχική συσκευή μεταδώσει ξανά.
3. Ο network server εκχωρεί ένα νέο DevAddr και session keys, ενώ η συσκευή-στόχος συνεχίζει με το παλιό session → ο attacker αποκτά τον κενό session και μπορεί να εισάγει πλαστά uplinks.

### 3. Υποβάθμιση Adaptive Data-Rate (ADR)

Επιβάλετε SF12/125 kHz για να αυξήσετε τον χρόνο εκπομπής → εξαντλήστε το duty-cycle του gateway (denial-of-service), διατηρώντας παράλληλα χαμηλή την επίδραση στην μπαταρία του attacker (απλώς στέλνοντας MAC commands σε επίπεδο δικτύου).

### 4. Reactive jamming

Το *HackRF One*, που εκτελεί GNU Radio flowgraph, ενεργοποιεί ένα chirp ευρείας ζώνης μόλις ανιχνευτεί preamble – αποκλείει όλους τους spreading factors με ≤200 mW TX· πλήρης διακοπή λειτουργίας μετρήθηκε σε εμβέλεια 2 km .

---

## Offensive tooling (2025)

| Tool | Σκοπός | Σημειώσεις |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Δημιουργία/ανάλυση/επίθεση σε LoRaWAN frames, analyzers με υποστήριξη DB, brute-forcer | Docker image, υποστηρίζει Semtech UDP input |
| **LoRaPWN** | Python utility της Trend Micro για brute OTAA, δημιουργία downlinks, αποκρυπτογράφηση payloads | Demo κυκλοφόρησε το 2023, ανεξάρτητο από SDR |
| **LoRAttack** | Multi-channel sniffer και replay με USRP· εξάγει PCAP/LoRaTap | Καλή ενσωμάτωση με Wireshark |
| **gr-lora / gr-lorawan** | GNU Radio OOT blocks για baseband TX/RX | Βάση για custom attacks |

---

## Αμυντικές συστάσεις (pentester checklist)

1. Προτιμήστε συσκευές **OTAA** με πραγματικά τυχαίο DevNonce· παρακολουθείτε τα duplicates.
2. Επιβάλετε το **LoRaWAN 1.1**: frame counters 32 bit, ξεχωριστά FNwkSIntKey / SNwkSIntKey.
3. Αποθηκεύετε το frame-counter σε non-volatile memory (**ABP**) ή μεταβείτε σε OTAA.
4. Αναπτύξτε **secure-element** (ATECC608A/SX1262-TRX-SE) για την προστασία των root keys από firmware extraction.
5. Απενεργοποιήστε τις απομακρυσμένες θύρες UDP του packet-forwarder (1700/1701) ή περιορίστε τις με WireGuard/VPN.
6. Διατηρείτε τα gateways ενημερωμένα· οι Kerlink/Dragino παρέχουν images με patches του 2024.
7. Υλοποιήστε **traffic anomaly detection** (π.χ. LAF analyzer) – επισημάνετε resets counters, duplicate joins και ξαφνικές αλλαγές ADR.<sup>[[1]](#references)</sup>



## Αναφορές

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Επισκόπηση του Trend Micro LoRaPWN](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)

{{#include ../../banners/hacktricks-training.md}}
