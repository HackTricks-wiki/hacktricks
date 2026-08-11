# Επιθέσεις Side-Channel Analysis

{{#include ../../banners/hacktricks-training.md}}

Οι επιθέσεις side-channel ανακτούν μυστικά παρατηρώντας φυσική ή μικρο-αρχιτεκτονική «διαρροή» που *συσχετίζεται* με την εσωτερική κατάσταση, αλλά *δεν* αποτελεί μέρος της λογικής διεπαφής της συσκευής. Τα παραδείγματα κυμαίνονται από τη μέτρηση του στιγμιαίου ρεύματος που καταναλώνει μια smart-card έως την εκμετάλλευση επιδράσεων power-management των CPU μέσω δικτύου.

---

## Κύρια Κανάλια Διαρροής

| Κανάλι | Τυπικός Στόχος | Όργανα Μέτρησης |
|---------|---------------|-----------------|
| Κατανάλωση ισχύος | Smart cards, IoT MCUs, FPGAs | Παλμογράφος μαζί με shunt resistor ή differential probe· το CW503 είναι τροφοδοτικό για probes/LNAs και όχι probe το ίδιο<sup>[[11]](#references)</sup> |
| Ηλεκτρομαγνητικό πεδίο (EM) | CPUs, RFID, AES accelerators | H-field/near-field probe μαζί με low-noise amplifier και παλμογράφο ή SDR receiver, όπως ένα RTL-SDR<sup>[[13]](#references)</sup> |
| Χρόνος εκτέλεσης / caches | Desktop και cloud CPUs | Timers υψηλής ακρίβειας (`rdtsc`/`rdtscp`) ή απομακρυσμένη μέτρηση time-of-flight |
| Ακουστική / μηχανική | Πληκτρολόγια, 3-D printers, printers, relays και voltage regulators CPU | MEMS microphone ή laser vibrometer<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Οπτική και θερμική | Status LEDs, displays, DRAM και θερμικά συνδεδεμένες συσκευές | Photodiode, high-speed camera ή IR camera<sup>[[7]](#references)[[16]](#references)</sup> |
| Fault injection | Κρυπτογραφία ASIC/MCU | Clock/voltage glitch, EMFI ή laser injection |

---

## Ανάλυση Ισχύος

### Simple Power Analysis (SPA)
Παρατηρήστε ένα *μεμονωμένο* trace και συσχετίστε ορατά χαρακτηριστικά με λειτουργίες όπως branches, modular multiplication ή διαφορετικές instruction sequences.<sup>[[1]](#references)</sup>

Η ακριβής εγκατάσταση εξαρτάται από τον στόχο. Το παρακάτω χρησιμοποιεί το current high-level ChipWhisperer capture API, αφού το scope και το target έχουν συνδεθεί και ρυθμιστεί:<sup>[[1]](#references)</sup>
```python
import chipwhisperer as cw

scope = cw.scope()
scope.default_setup()
target = cw.target(scope)
ktp = cw.ktp.Basic()
key, plaintext = ktp.next()
trace = cw.capture_trace(scope, target, plaintext, key)
if trace is not None:
print(trace.wave)  # NumPy array of power samples
```
### Differential/Correlation Power Analysis (DPA/CPA)
Αποκτήστε πολλαπλά traces, υποθέστε ένα byte κλειδιού `k`, υπολογίστε ένα μοντέλο leakage Hamming-weight (HW) ή Hamming-distance (HD) και συσχετίστε το με κάθε sample. Ο απαιτούμενος αριθμός traces καθορίζεται από τον στόχο, τον θόρυβο, το alignment, τα countermeasures και το μοντέλο leakage· δεν αποτελεί σταθερό όριο.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA είναι ένα τυπικό baseline. Τα Template attacks, η mutual-information analysis και οι προσεγγίσεις machine learning μπορούν να φανούν χρήσιμες όταν το leakage είναι μη γραμμικό ή τα traces δεν είναι σωστά ευθυγραμμισμένα.

---

## Electromagnetic Analysis (EMA)
Η near-field EM analysis μπορεί να παρατηρήσει δραστηριότητα που εξαρτάται από τα δεδομένα, χωρίς την εισαγωγή shunt στη διαδρομή τροφοδοσίας. Δεν εκθέτει απαραίτητα το ίδιο σήμα με ένα power trace: η θέση και ο προσανατολισμός του probe, το bandwidth, το front-end gain, η ποιότητα του trigger και η απόσταση παίζουν όλα ρόλο.

---

## Timing & Micro-architectural Attacks
Οι σύγχρονοι CPUs κάνουν leak secrets μέσω shared resources:
* **Hertzbleed (2022)** – Το dynamic voltage and frequency scaling που εξαρτάται από τα δεδομένα δημιουργεί ένα remote timing channel. Η αρχική end-to-end επίδειξη key-recovery στόχευε το SIKE· μεταγενέστερες εργασίες συζητούν άλλα primitives.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – Η transient execution μπορεί να εκθέσει δεδομένα που χρησιμοποιούνται από vector gather instructions πέρα από security boundaries.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – Ο εσφαλμένος χειρισμός της speculative κατάστασης των vector registers μπορεί να αποκαλύψει δεδομένα από τον ίδιο physical core.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – Ένα transient-execution attack συνδυάζει phantom execution με training σε transient execution, ώστε να δημιουργήσει attacker-controlled misprediction gadgets.<sup>[[5]](#references)</sup>

---

## Acoustic & Optical Attacks
Το acoustic leakage έχει χρησιμοποιηθεί για την ανάκτηση RSA keys από τον θόρυβο laptop σε ελεγχόμενο πείραμα, μεταξύ άλλων με το μικρόφωνο ενός κοντινού mobile phone.<sup>[[6]](#references)</sup> Μια ξεχωριστή μελέτη keyboard του 2023 ταξινόμησε keystrokes με ακρίβεια 95% όταν εκπαιδεύτηκε σε recordings από κοντινό phone και 93% όταν εκπαιδεύτηκε σε Zoom audio· αυτά τα ποσοστά περιγράφουν το trained-device experiment της συγκεκριμένης μελέτης και όχι οποιοδήποτε keyboard ή victim.<sup>[[9]](#references)</sup> Τα optical emanations από status LEDs μπορούν επίσης να συσχετιστούν με τα δεδομένα που υποβάλλονται σε επεξεργασία. Αυτά τα αποτελέσματα εξαρτώνται από το target και το setup· μην γενικεύετε το range ή το success rate τους σε άσχετες συσκευές.<sup>[[7]](#references)</sup>

---

## Fault Injection & Differential Fault Analysis (DFA)
Ο συνδυασμός controlled faults με side-channel observations μπορεί να μειώσει το key search για ορισμένους αλγορίθμους και implementations. Συνήθεις lab platforms περιλαμβάνουν τις δυνατότητες voltage/clock glitching του ChipWhisperer και dedicated EM fault-injection tools, όπως τα ChipSHOUTER ή PicoEMP. Η προηγούμενη διατύπωση του draft περί “sub-1 ns” δεν πρέπει να χρησιμοποιείται ως specification: το published manual του ChipSHOUTER αναφέρει typical inserted-pulse widths **15–80 ns** με το tip των 1 mm και **24–480 ns** με το tip των 4 mm (παρότι το trigger/pulse jitter καθορίζεται σε picoseconds). Η απαιτούμενη timing resolution, η τοποθέτηση του probe και ο αριθμός των faulty outputs εξαρτώνται από το target και το fault model.<sup>[[1]](#references)[[10]](#references)</sup>

## Unverified Research Leads Retained from the Earlier Draft

Το προηγούμενο draft ανέφερε επίσης: ένα **500 MHz–3 GHz** EM setup που ανακτά ένα STM32 key από απόσταση μεγαλύτερη των **10 cm** χρησιμοποιώντας RTL-SDR· ένα DDR4 activity LED που αποκαλύπτει ένα AES round key σε λιγότερο από ένα λεπτό στο “Black Hat 2023”· και μια open-source RISC-V glitching platform του 2025 με την ονομασία **GlitchKit-R5**. Κατά τη διάρκεια αυτού του audit δεν εντοπίστηκε matching primary paper, conference material ή project repository. Αυτές οι ακριβείς λεπτομέρειες διατηρούνται ως search/reproduction leads και όχι ως established results ή tooling recommendations.

---

## Typical Attack Workflow
1. Εντοπίστε το leakage channel και το mount point (VCC pin, decoupling cap, near-field spot).
2. Εισαγάγετε trigger (GPIO ή pattern-based).
3. Συλλέξτε αρκετά traces για το επιλεγμένο statistical test, καταγράφοντας plaintext/ciphertext και άλλα metadata.
4. Εκτελέστε pre-process (alignment, mean removal, LP/HP filter, wavelet, PCA).
5. Statistical ή ML key recovery (CPA, MIA, DL-SCA).
6. Επικυρώστε και επαναλάβετε τη διαδικασία για τα outliers.

---

## Defences & Hardening
* **Constant-time** implementations και memory-hard algorithms.
* **Masking/shuffling** – διαχωρισμός των secrets σε random shares· first-order resistance πιστοποιημένη μέσω TVLA.
* **Hiding** – on-chip voltage regulators, randomised clock, dual-rail logic, EM shields.
* **Fault detection** – redundant computation, threshold signatures.
* **Operational** – απενεργοποίηση του DVFS/turbo σε crypto kernels, απομόνωση του SMT, απαγόρευση co-location σε multi-tenant clouds.

---

## Tools & Frameworks
* **ChipWhisperer-Husky** (2024) – 500 MS/s scope + Cortex-M trigger· Python API όπως παραπάνω.<sup>[[1]](#references)</sup>
* **Riscure Inspector and fault-injection products** – commercial analysis και automated test tooling.
* **scaaml** – TensorFlow-based deep-learning SCA tooling και datasets.<sup>[[12]](#references)</sup>
* **pyecsca** – open-source toolkit για reverse-engineering black-box ECC implementations μέσω side channels.<sup>[[8]](#references)</sup>

---

## References

- [1] [Τεκμηρίωση ChipWhisperer](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Paper του Hertzbleed Attack](https://www.hertzbleed.com/)
- [3] [Downfall: Εκμετάλλευση Speculative Data Gathering](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Αποκάλυψη νέων Attack Surfaces με Training σε Transient Execution](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [Εξαγωγή RSA Key μέσω Low-Bandwidth Acoustic Cryptanalysis](https://eprint.iacr.org/2013/857.pdf)
- [7] [Information Leakage από Optical Emanations](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [Τεκμηρίωση artifact του pyecsca](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Μια Practical Deep Learning-Based Acoustic Side Channel Attack σε Keyboards](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - Εγχειρίδιο χρήσης ChipSHOUTER](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [Τεκμηρίωση ChipWhisperer — CW503 probe power supply](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Τεκμηρίωση Google SCAAML](https://google.github.io/scaaml/)
- [13] [FOSDEM — Εκτέλεση low-cost electromagnetic side-channel attacks με χρήση RTL-SDR](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Αποκωδικοποίηση Intellectual Property: Acoustic and Magnetic Side-Channel Attack σε 3-D Printer](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — Acoustic Side-Channel Attacks σε Printers](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Κατασκοπεία της Temperature με χρήση DRAM](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
{{#include ../../banners/hacktricks-training.md}}
