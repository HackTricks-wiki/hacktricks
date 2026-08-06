# Side-Channel-Analyse-Angriffe

{{#include ../../banners/hacktricks-training.md}}

Side-channel attacks gewinnen Geheimnisse durch die Beobachtung physischer oder mikroarchitektonischer „leakage“, die mit dem internen Zustand *korreliert*, aber *nicht* Teil der logischen Schnittstelle des Geräts ist. Beispiele reichen von der Messung der momentan von einer Smartcard aufgenommenen Stromstärke bis zur Ausnutzung von CPU-Energieverwaltungseffekten über ein Netzwerk.

---

## Wichtige Leakage-Kanäle

| Kanal | Typisches Ziel | Instrumentierung |
|---------|---------------|-----------------|
| Stromverbrauch | Smartcards, IoT-MCUs, FPGAs | Oszilloskop + Shunt-Widerstand/HS-Probe (z. B. CW503)
| Elektromagnetisches Feld (EM) | CPUs, RFID, AES-Beschleuniger | H-Feld-Probe + LNA, ChipWhisperer/RTL-SDR
| Ausführungszeit / Caches | Desktop- und Cloud-CPUs | Hochpräzise Timer (rdtsc/rdtscp), Remote-Time-of-Flight
| Akustik / Mechanik | Tastaturen, 3D-Drucker, Relais | MEMS-Mikrofon, Laservibrometer
| Optisch und thermisch | LEDs, Laserdrucker, DRAM | Photodiode / Hochgeschwindigkeitskamera, IR-Kamera
| Fehlerinduziert | ASIC/MCU-Kryptografie | Clock-/Voltage-Glitch, EMFI, Laser-Injektion

---

## Power Analysis

### Simple Power Analysis (SPA)
Eine *einzelne* Trace beobachten und Peaks/Valleys direkt mit Operationen verknüpfen (z. B. DES-S-Boxen).<sup>[[1]](#references)</sup>
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
Erfasse *N > 1 000* Traces, stelle eine Hypothese für das Schlüsselbyte `k` auf, berechne das HW/HD-Modell und korreliere es mit der leakage.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA bleibt state-of-the-art, aber Machine-Learning-Varianten (MLA, Deep-Learning-SCA) dominieren inzwischen Wettbewerbe wie ASCAD-v2 (2023).

---

## Elektromagnetische Analyse (EMA)
Nahfeld-EM-Sonden (500 MHz–3 GHz) leaken identische Informationen wie Power Analysis, *ohne* Shunts einzusetzen. Forschungsarbeiten aus dem Jahr 2024 zeigten die Wiederherstellung von Schlüsseln in einer Entfernung von **>10 cm** von einem STM32 mithilfe von Spectrum Correlation und kostengünstigen RTL-SDR-Frontends.

---

## Timing- und mikroarchitektonische Angriffe
Moderne CPUs leaken Geheimnisse über gemeinsam genutzte Ressourcen:
* **Hertzbleed (2022)** – Die DVFS-Frequenzskalierung korreliert mit der Hamming Weight und ermöglicht die *remote* Extraktion von EdDSA-Schlüsseln.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – Transient Execution zum Lesen von AVX-Gather-Daten über SMT-Threads hinweg.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – Spekulative Vector-Misprediction leakt Register domainübergreifend.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

---

## Akustische und optische Angriffe
* 2024 zeigte "​iLeakKeys" eine Genauigkeit von 95 %, wenn Laptop-Tastatureingaben mithilfe eines **Smartphone-Mikrofons über Zoom** und eines CNN-Klassifikators wiederhergestellt wurden.
* Hochgeschwindigkeits-Photodioden erfassen die Aktivitäts-LED von DDR4 und rekonstruieren AES-Rundenschlüssel innerhalb von <1 Minute (BlackHat 2023).

---

## Fault Injection und Differential Fault Analysis (DFA)
Die Kombination von Faults mit Side-Channel-Leakage verkürzt die Schlüsselsuche (z. B. 1-trace AES DFA). Aktuelle Tools zu Hobbyistenpreisen:
* **ChipSHOUTER & PicoEMP** – elektromagnetisches Pulse Glitching unter 1 ns.
* **GlitchKit-R5 (2025)** – Open-Source-Plattform für Clock/Voltage Glitching mit Unterstützung für RISC-V-SoCs.

---

## Typischer Attack-Workflow
1. Leakage-Kanal und Mounting Point identifizieren (VCC-Pin, Decoupling-Kondensator, Nahfeld-Punkt).
2. Trigger einfügen (GPIO oder patternbasiert).
3. >1 k Traces mit geeigneter Abtastung und geeigneten Filtern sammeln.
4. Vorverarbeiten (Alignment, Mean Removal, LP/HP-Filter, Wavelet, PCA).
5. Statistische oder ML-Key-Recovery (CPA, MIA, DL-SCA).
6. Validieren und bei Outliers iterieren.

---

## Defences und Hardening
* **Constant-Time**-Implementierungen und Memory-Hard-Algorithmen.
* **Masking/Shuffling** – Geheimnisse in zufällige Shares aufteilen; First-Order-Resistance durch TVLA zertifiziert.
* **Hiding** – On-Chip-Spannungsregler, randomisierte Clock, Dual-Rail-Logik, EM-Schilde.
* **Fault Detection** – redundante Berechnung, Threshold Signatures.
* **Operational** – DVFS/Turbo in Crypto-Kernels deaktivieren, SMT isolieren, Co-Location in Multi-Tenant-Clouds verbieten.

---

## Tools und Frameworks
* **ChipWhisperer-Husky** (2024) – 500-MS/s-Scope + Cortex-M-Trigger; Python-API wie oben.<sup>[[1]](#references)</sup>
* **Riscure Inspector & FI** – kommerziell, unterstützt automatisierte Leakage-Bewertung (TVLA-2.0).
* **scaaml** – TensorFlow-basierte Deep-Learning-SCA-Library (v1.2 – 2025).
* **pyecsca** – ANSSI-Open-Source-ECC-SCA-Framework.

---

## Referenzen

- [1] [ChipWhisperer-Dokumentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed-Angriffspapier](https://www.hertzbleed.com/)
- [3] [Downfall: Ausnutzung spekulativer Datensammlung](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Aufdeckung neuer Angriffsflächen durch Training bei transienter Ausführung](https://comsec.ethz.ch/research/microarch/inception/)

{{#include ../../banners/hacktricks-training.md}}
