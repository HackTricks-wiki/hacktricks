# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## Εισαγωγή

Το **Low-Power Wide Area Network** (LPWAN) είναι μια ομάδα ασύρματων τεχνολογιών δικτύων ευρείας περιοχής και χαμηλής κατανάλωσης, σχεδιασμένων για **επικοινωνίες μεγάλης εμβέλειας** με χαμηλό ρυθμό μετάδοσης bit.
Ανάλογα με τις παραμέτρους του radio, την κεραία, τη ρυθμιστική περιοχή, το ανάγλυφο και τον duty cycle, οι εγκαταστάσεις LPWAN μπορούν να ανταλλάξουν τη throughput για κάλυψη πολλών χιλιομέτρων και διάρκεια ζωής μπαταρίας πολλών ετών. Αντιμετωπίζετε τα στοιχεία εμβέλειας και μπαταρίας των vendors ως στόχους σχεδιασμού και όχι ως εγγυήσεις.<sup>[[3]](#references)</sup>

Το Long Range (**LoRa**) είναι επί του παρόντος το πιο διαδεδομένο LPWAN physical layer και η open προδιαγραφή του MAC-layer είναι το **LoRaWAN**.

---

## LPWAN, LoRa και LoRaWAN

* LoRa – Chirp Spread Spectrum (CSS) physical layer που αναπτύχθηκε από τη Semtech (proprietary αλλά τεκμηριωμένο).
* LoRaWAN – Open MAC/Network layer που συντηρείται από το LoRa-Alliance. Οι εκδόσεις 1.0.x και 1.1 είναι κοινές στην πράξη.
* Τυπική αρχιτεκτονική: *end-device → gateway (packet-forwarder) → network-server → application-server*.<sup>[[3]](#references)</sup>

> Στο LoRaWAN 1.1, το **μοντέλο ασφάλειας** χρησιμοποιεί ξεχωριστά AES-128 application και network root keys για την παραγωγή role-specific session keys κατά το OTAA. Οι παλαιότερες εγκαταστάσεις 1.0.x συνήθως χρησιμοποιούν ένα AppKey για την παραγωγή των network και application session keys, ενώ το ABP προρυθμίζει απευθείας τα session keys. Η δυνατότητα που αποκτάται από ένα leaked key εξαρτάται επομένως από την έκδοση του LoRaWAN και από το ποιο key εκτέθηκε.<sup>[[3]](#references)</sup>

---

## Σύνοψη attack surface

| Layer | Αδυναμία | Πρακτικός αντίκτυπος |
|-------|----------|------------------|
| PHY | Reactive / selective jamming | Τοπική απώλεια πακέτων· η αποτελεσματικότητα εξαρτάται από το link budget, τον χρονισμό, το bandwidth και τους ρυθμιστικούς περιορισμούς |
| MAC | Replay join και data-frame όταν επαναχρησιμοποιείται η κατάσταση nonce/counter | Αποσυγχρονισμός συσκευών, spoofing ή injection αν ο server/device παραβιάζει τις replay protections |
| Network-Server | Μη ασφαλές packet-forwarder, αδύναμα MQTT/UDP filters, παρωχημένο firmware gateway | RCE σε gateways → pivot στο OT/IT network |
| Application | Hard-coded ή προβλέψιμα AppKeys | Brute-force/decrypt traffic, impersonate sensors |

---

## Αντιπροσωπευτικές implementation vulnerabilities

* **CVE-2024-29862** – Οι εκδόσεις του ChirpStack Gateway Bridge πριν από την 4.0.11 και του MQTT Forwarder πριν από την 4.2.1 μπορούσαν να συνδεθούν σε MQTT broker που ελεγχόταν από attacker, επειδή το TLS server-certificate validation ήταν απενεργοποιημένο. Αυτό θα μπορούσε να εκθέσει credentials και gateway traffic· πραγματοποιήστε upgrade στις fixed releases.<sup>[[4]](#references)</sup>
* **Dragino LG01 firmware 4.3.4** – Το CVE-2022-45227 περιγράφει ένα unauthenticated directory listing του `/lib/` που περιείχε downloadable backup file· το CVE-2022-45228 είναι ένα CSRF χαμηλής σοβαρότητας στη σελίδα logout. Αυτές οι καταγραφές δεν τεκμηριώνουν τον ισχυριζόμενο αντίκτυπο στο LG308, την overwrite configuration, το μέγεθος του πληθυσμού ή την κατάσταση των patches το 2025.<sup>[[6]](#references)[[7]](#references)</sup>
* Μια παλαιότερη έκδοση αυτής της σελίδας περιέγραφε ένα υποτιθέμενο πρόβλημα του Semtech UDP packet-forwarder ως **crafted uplink μεγαλύτερο από 255 bytes που προκαλεί stack smash και RCE σε SX130x reference gateways**, το οποίο αποδιδόταν σε μια παρουσίαση του “LoRa Exploitation Reloaded” στο Black Hat Europe 2023 και σε ένα private patch του Οκτωβρίου 2023. Αυτές οι ακριβείς λεπτομέρειες διατηρούνται εδώ ως ερευνητικό lead, αλλά δεν κατέστη δυνατό να επιβεβαιωθεί κάποιο αντίστοιχο public advisory, presentation ή patch. Μην αντιμετωπίζετε το ζήτημα ως γνωστή vulnerability χωρίς να αποκτήσετε το επηρεαζόμενο product/version και μια επαληθεύσιμη primary source.

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
Αυτές οι εντολές διατηρούν την αρχική ροή εργασίας ως **ενδεικτική σύνταξη**· η διάταξη των repository και τα flags διαφέρουν μεταξύ projects/releases. Η παθητική καταγραφή δεν αποκαλύπτει ένα ισχυρό AppKey. Το offline guessing είναι χρήσιμο μόνο όταν το root key είναι αρκετά αδύναμο ώστε να βρεθεί και μια καταγεγραμμένη join exchange παρέχει μια τιμή που μπορεί να επικυρώσει υποψήφιες τιμές.<sup>[[2]](#references)[[3]](#references)</sup>

### 2. Έλεγχος προστασίας από OTAA replay και κατάστασης nonce

1. Σε ένα εξουσιοδοτημένο δίκτυο δοκιμών, καταγράψτε ένα νόμιμο **JoinRequest**.
2. Κάντε replay του ίδιου request και επιβεβαιώστε ότι ο network server απορρίπτει το επαναχρησιμοποιημένο `DevNonce`.
3. Κάντε reboot ή reset στη συσκευή δοκιμών και επαναλάβετε τον έλεγχο για να εντοπίσετε απώλεια κατάστασης nonce. Ένας compliant server πρέπει να παρακολουθεί τα χρησιμοποιημένα nonces· το replay ενός JoinRequest από μόνο του δεν αποκαλύπτει τα newly derived session keys ούτε παρέχει στον replayer τον έλεγχο μιας session.<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. Υποβάθμιση Adaptive Data-Rate (ADR)

Ένας attacker που μπορεί να κάνει authenticate network-layer MAC commands — για παράδειγμα, μετά από compromise του applicable network session key ή του network server — μπορεί να προσπαθήσει να επιβάλει inefficient data-rate parameters και να αυξήσει το airtime. Ένας nearby unauthenticated transmitter δεν μπορεί να εκδώσει νόμιμα ADR commands απλώς γνωρίζοντας μια device address.<sup>[[3]](#references)</sup>

### 4. Reactive jamming

Ένα reactive jammer μπορεί να μεταδώσει αφού εντοπίσει ένα LoRa preamble και να διαταράξει επιλεκτικά frames. Η προηγούμενη σελίδα ισχυριζόταν ότι μια εγκατάσταση HackRF/GNU Radio προκαλούσε πλήρη διακοπή λειτουργίας σε **2 km με όχι περισσότερα από 200 mW**, αλλά δεν παρασχέθηκε supporting measurement source· διατηρήστε αυτά τα νούμερα μόνο ως reproduction target και όχι ως αναμενόμενο αποτέλεσμα. Η απαιτούμενη transmit power, ο χρονισμός, το bandwidth, τα επηρεαζόμενα spreading factors και η εμβέλεια εξαρτώνται από το περιβάλλον. Κάντε δοκιμές μόνο μέσα σε εξουσιοδοτημένη, RF-contained εγκατάσταση και συμμορφωθείτε με τους τοπικούς κανόνες φάσματος.

---

## Offensive tooling (2025)

| Tool | Purpose | Notes |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Δημιουργία/ανάλυση/επίθεση σε LoRaWAN frames, DB-backed analyzers, brute-forcer | Docker image· υποστηρίζει Semtech UDP input<sup>[[1]](#references)</sup> |
| **LoRaPWN** | Python utility της Trend Micro για brute OTAA, δημιουργία downlinks και αποκρυπτογράφηση payloads | Public research utility· επαληθεύστε το υποστηριζόμενο hardware και τις protocol versions<sup>[[2]](#references)</sup> |
| **LoRAttack** | Research framework για multi-channel LoRaWAN capture, session analysis, key derivation και replay testing | Περιγράφεται σε master's thesis του 2024· αποκτήστε και επαληθεύστε την ακριβή υλοποίηση πριν βασιστείτε στα example flags<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | GNU Radio out-of-tree blocks για LoRa baseband reception ή transceiver research | Τα projects διαφέρουν ως προς τη συμβατότητα με GNU Radio και το feature set<sup>[[9]](#references)</sup> |

---

## Defensive recommendations (pentester checklist)

1. Προτιμήστε **OTAA** και επαληθεύστε ότι οι συσκευές και οι servers διατηρούν το απαιτούμενο nonce state· παρακολουθείτε τα rejected duplicate joins.
2. Προτιμήστε το **LoRaWAN 1.1** όπου υποστηρίζεται, ώστε οι network functions να χρησιμοποιούν distinct session keys και ενημερωμένο nonce handling.<sup>[[3]](#references)</sup>
3. Αποθηκεύστε το frame-counter σε non-volatile memory (**ABP**) ή μεταβείτε σε OTAA.
4. Αναπτύξτε κατάλληλο **secure element** (για παράδειγμα, το ATECC608A σε υποστηριζόμενο design) για να μειώσετε την έκθεση των root keys στη συνηθισμένη αποθήκευση firmware.
5. Μην εκθέτετε configured packet-forwarder UDP listeners (συνήθως 1700) σε untrusted networks· κάντε authenticate/encrypt το gateway backhaul ή περιορίστε το με VPN.
6. Διατηρείτε τα gateways σε vendor-supported firmware και επιβεβαιώνετε το ακριβές model/version έναντι των applicable advisories.
7. Υλοποιήστε **traffic anomaly detection** (π.χ. LAF analyzer) – επισημαίνετε counter resets, duplicate joins και ξαφνικές αλλαγές ADR.<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Επισκόπηση του Trend Micro LoRaPWN](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - Προδιαγραφή LoRaWAN L2 1.1](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - Περιφερειακές παράμετροι LoRaWAN 1.1 και συγχρονισμός join](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [Κατάλογος διπλωματικών εργασιών CTU - Ανάλυση ασφάλειας πρωτοκόλλων LPWAN με αξιοποίηση τεχνολογίας SDR](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [EPFL `gr-lora_sdr` GNU Radio transceiver](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
