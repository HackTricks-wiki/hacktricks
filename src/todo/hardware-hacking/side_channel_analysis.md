# Επιθέσεις Side Channel Analysis

{{#include ../../banners/hacktricks-training.md}}

Οι επιθέσεις side-channel ανακτούν μυστικά παρατηρώντας φυσικό ή μικροαρχιτεκτονικό «leakage» που *συσχετίζεται* με την εσωτερική κατάσταση, αλλά *δεν* αποτελεί μέρος της λογικής διεπαφής της συσκευής.  Τα παραδείγματα κυμαίνονται από τη μέτρηση του στιγμιαίου ρεύματος που καταναλώνει μια smart-card έως την εκμετάλλευση επιδράσεων διαχείρισης ισχύος της CPU μέσω δικτύου.

---

## Κύρια Κανάλια Leakage

| Κανάλι | Τυπικός Στόχος | Εργαλεία Μέτρησης |
|---------|---------------|-----------------|
| Κατανάλωση ισχύος | Smart-cards, IoT MCUs, FPGAs | Παλμογράφος + shunt resistor/HS probe (π.χ. CW503)
| Ηλεκτρομαγνητικό πεδίο (EM) | CPUs, RFID, AES accelerators | H-field probe + LNA, ChipWhisperer/RTL-SDR
| Χρόνος εκτέλεσης / caches | Desktop και cloud CPUs | Timers υψηλής ακρίβειας (rdtsc/rdtscp), remote time-of-flight
| Ακουστικό / μηχανικό | Πληκτρολόγια, 3-D printers, relays | MEMS microphone, laser vibrometer
| Οπτικό και θερμικό | LEDs, laser printers, DRAM | Photodiode / high-speed camera, IR camera
| Προκαλούμενα faults | ASIC/MCU cryptos | Clock/voltage glitch, EMFI, laser injection

---

## Ανάλυση Ισχύος

### Simple Power Analysis (SPA)
Παρατηρήστε ένα *μεμονωμένο* trace και συσχετίστε άμεσα τις κορυφές/κοιλάδες με operations (π.χ. DES S-boxes).<sup>[[1]](#references)</sup>
```python
# ChipWhisperer-husky example – capture one AES trace
from chipwhisperer.capture.api.programmers import STMLink
from chipwhisperer.capture import CWSession
cw = CWSession(project='aes')
trig = cw.scope.trig
cw.connect(cw.capture.scopes[0])
cw.capture.init()
trace = cw.capture.capture_trace()
print(trace.wave)  # numpy array of power samples
```
### Differential/Correlation Power Analysis (DPA/CPA)
Συλλέξτε *N > 1 000* ίχνη, υποθέστε το byte κλειδιού `k`, υπολογίστε το μοντέλο HW/HD και συσχετίστε το με τη διαρροή.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
Το CPA παραμένει state-of-the-art, αλλά οι παραλλαγές machine-learning (MLA, deep-learning SCA) κυριαρχούν πλέον σε διαγωνισμούς όπως το ASCAD-v2 (2023).

---

## Electromagnetic Analysis (EMA)
Οι near-field EM probes (500 MHz–3 GHz) κάνουν leak identical information με το power analysis *χωρίς* την εισαγωγή shunts. Έρευνα του 2024 απέδειξε key recovery σε απόσταση **>10 cm** από ένα STM32, χρησιμοποιώντας spectrum correlation και low-cost RTL-SDR front-ends.

---

## Timing & Micro-architectural Attacks
Οι σύγχρονοι CPUs κάνουν leak secrets μέσω shared resources:
* **Hertzbleed (2022)** – το DVFS frequency scaling συσχετίζεται με το Hamming weight, επιτρέποντας *remote* extraction κλειδιών EdDSA.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – transient-execution για ανάγνωση AVX-gather data μεταξύ SMT threads.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – speculative vector mis-prediction κάνει leak registers cross-domain.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

---

## Acoustic & Optical Attacks
* Το "iLeakKeys" του 2024 έδειξε ακρίβεια 95 % στην ανάκτηση laptop keystrokes από **smart-phone microphone μέσω Zoom**, χρησιμοποιώντας CNN classifier.
* High-speed photodiodes καταγράφουν το activity LED του DDR4 και ανακατασκευάζουν AES round keys σε <1 λεπτό (BlackHat 2023).

---

## Fault Injection & Differential Fault Analysis (DFA)
Ο συνδυασμός faults με side-channel leakage συντομεύει το key search (π.χ. 1-trace AES DFA). Πρόσφατα tools σε τιμές hobbyist:
* **ChipSHOUTER & PicoEMP** – electromagnetic pulse glitching κάτω του 1 ns.
* **GlitchKit-R5 (2025)** – open-source clock/voltage glitch platform με υποστήριξη για RISC-V SoCs.

---

## Typical Attack Workflow
1. Εντοπισμός του leakage channel και του mount point (VCC pin, decoupling cap, near-field spot).
2. Εισαγωγή trigger (GPIO ή pattern-based).
3. Συλλογή >1 k traces με κατάλληλο sampling/filters.
4. Pre-process (alignment, mean removal, LP/HP filter, wavelet, PCA).
5. Statistical ή ML key recovery (CPA, MIA, DL-SCA).
6. Validation και iteration στα outliers.

---

## Defences & Hardening
* **Constant-time** implementations και memory-hard algorithms.
* **Masking/shuffling** – διαχωρισμός των secrets σε random shares· first-order resistance πιστοποιημένη μέσω TVLA.
* **Hiding** – on-chip voltage regulators, randomised clock, dual-rail logic, EM shields.
* **Fault detection** – redundant computation, threshold signatures.
* **Operational** – απενεργοποίηση DVFS/turbo σε crypto kernels, απομόνωση SMT, απαγόρευση co-location σε multi-tenant clouds.

---

## Tools & Frameworks
* **ChipWhisperer-Husky** (2024) – 500 MS/s scope + Cortex-M trigger· Python API όπως παραπάνω.<sup>[[1]](#references)</sup>
* **Riscure Inspector & FI** – commercial, με υποστήριξη automated leakage assessment (TVLA-2.0).
* **scaaml** – TensorFlow-based deep-learning SCA library (v1.2 – 2025).
* **pyecsca** – ANSSI open-source ECC SCA framework.

---

## References

- [1] [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)
- [3] [Downfall: Exploiting Speculative Data Gathering](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Exposing New Attack Surfaces with Training in Transient Execution](https://comsec.ethz.ch/research/microarch/inception/)

{{#include ../../banners/hacktricks-training.md}}
