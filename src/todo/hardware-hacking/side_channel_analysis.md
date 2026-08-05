# Angriffe durch Side Channel Analysis

{{#include ../../banners/hacktricks-training.md}}

Side-channel attacks gewinnen Geheimnisse, indem sie physische oder mikroarchitektonische „Leakage“ beobachten, die mit dem internen Zustand *korreliert* ist, aber *nicht* Teil der logischen Schnittstelle des Geräts ist. Beispiele reichen von der Messung des momentan von einer Smartcard aufgenommenen Stroms bis zur Ausnutzung von CPU-Power-Management-Effekten über ein Netzwerk.

---

## Wichtige Leakage-Kanäle

| Kanal | Typisches Ziel | Instrumentierung |
|---------|---------------|-----------------|
| Stromverbrauch | Smartcards, IoT-MCUs, FPGAs | Oszilloskop + Shunt-Widerstand/HS-Probe (z. B. CW503)
| Elektromagnetisches Feld (EM) | CPUs, RFID, AES-Beschleuniger | H-Feld-Sonde + LNA, ChipWhisperer/RTL-SDR
| Ausführungszeit / Caches | Desktop- und Cloud-CPUs | Hochpräzise Timer (rdtsc/rdtscp), Remote-Time-of-Flight
| Akustisch / mechanisch | Tastaturen, 3D-Drucker, Relais | MEMS-Mikrofon, Laser-Vibrometer
| Optisch und thermisch | LEDs, Laserdrucker, DRAM | Fotodiode / Hochgeschwindigkeitskamera, IR-Kamera
| Fehlerinduziert | ASIC/MCU-Kryptos | Clock-/Voltage-Glitch, EMFI, Laser-Injektion

---

## Power Analysis

### Simple Power Analysis (SPA)
Eine *einzelne* Trace beobachten und Peaks/Valleys direkt mit Operationen verknüpfen (z. B. DES-S-Boxen).
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
Erfasse *N > 1 000* traces, stelle eine Hypothese für das key byte `k` auf, berechne das HW/HD model und korreliere es mit der leakage.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA bleibt state-of-the-art, aber Machine-Learning-Varianten (MLA, Deep-Learning-SCA) dominieren inzwischen Wettbewerbe wie ASCAD-v2 (2023).

---

## Elektromagnetische Analyse (EMA)
Nahfeld-EM-Sonden (500 MHz–3 GHz) leaken identische Informationen wie Power Analysis, *ohne* Shunts einzusetzen. Forschungen aus dem Jahr 2024 demonstrierten die Wiederherstellung von Schlüsseln in **>10 cm** Entfernung von einem STM32 mithilfe von Spektrumskorrelation und kostengünstigen RTL-SDR-Frontends.

---

## Timing- & mikroarchitektonische Angriffe
Moderne CPUs leaken Geheimnisse über gemeinsam genutzte Ressourcen:
* **Hertzbleed (2022)** – Die DVFS-Frequenzskalierung korreliert mit dem Hamming-Gewicht und ermöglicht die *Remote*-Extraktion von EdDSA-Schlüsseln.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – Transient Execution zum Lesen von AVX-Gather-Daten über SMT-Threads hinweg.
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – Spekulative Vektor-Fehlvorhersagen leaken Register domänenübergreifend.

---

## Akustische & optische Angriffe
* Das 2024 vorgestellte „​iLeakKeys“ zeigte eine Genauigkeit von 95 %, bei der Laptop-Tastatureingaben von einem **Smartphone-Mikrofon über Zoom** mithilfe eines CNN-Klassifikators wiederhergestellt wurden.
* Hochgeschwindigkeits-Fotodioden erfassen die Aktivitäts-LED von DDR4 und rekonstruieren AES-Runden-Schlüssel innerhalb von <1 Minute (BlackHat 2023).

---

## Fault Injection & Differential Fault Analysis (DFA)
Die Kombination von Faults mit Side-Channel-Leakage verkürzt die Schlüsselsuche (z. B. 1-trace AES DFA). Aktuelle Tools zu Hobbyistenpreisen:
* **ChipSHOUTER & PicoEMP** – Elektromagnetische Pulse-Glitching-Tools mit einer Dauer von unter 1 ns.
* **GlitchKit-R5 (2025)** – Open-Source-Clock-/Voltage-Glitch-Plattform mit Unterstützung für RISC-V-SoCs.

---

## Typischer Angriffs-Workflow
1. Leakage-Kanal & Messpunkt identifizieren (VCC-Pin, Entkopplungskondensator, Nahfeldpunkt).
2. Trigger einfügen (GPIO oder pattern-basiert).
3. >1 k Traces mit geeigneter Abtastung und geeigneten Filtern erfassen.
4. Vorverarbeitung (Alignment, Mittelwertentfernung, LP-/HP-Filter, Wavelet, PCA).
5. Statistische oder ML-Schlüsselwiederherstellung (CPA, MIA, DL-SCA).
6. Validieren und anhand von Ausreißern iterieren.

---

## Abwehrmaßnahmen & Hardening
* **Constant-time**-Implementierungen & speicherharte Algorithmen.
* **Masking/Shuffling** – Geheimnisse in zufällige Shares aufteilen; First-Order-Resistenz durch TVLA zertifiziert.
* **Hiding** – On-Chip-Spannungsregler, randomisierte Clock, Dual-Rail-Logik, EM-Schilde.
* **Fault Detection** – redundante Berechnung, Threshold-Signaturen.
* **Operational** – DVFS/Turbo in Crypto-Kernels deaktivieren, SMT isolieren, Co-Location in Multi-Tenant-Clouds untersagen.

---

## Tools & Frameworks
* **ChipWhisperer-Husky** (2024) – 500 MS/s Scope + Cortex-M-Trigger; Python-API wie oben.<sup>[[1]](#references)</sup>
* **Riscure Inspector & FI** – kommerziell, unterstützt automatisierte Leakage-Bewertung (TVLA-2.0).
* **scaaml** – TensorFlow-basierte Deep-Learning-SCA-Library (v1.2 – 2025).
* **pyecsca** – Open-Source-ECC-SCA-Framework von ANSSI.

---

## Referenzen

- [1] [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)


{{#include ../../banners/hacktricks-training.md}}
