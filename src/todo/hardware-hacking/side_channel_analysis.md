# Seitenkanalanalyse-Angriffe

{{#include ../../banners/hacktricks-training.md}}

Seitenkanalangriffe erholen Geheimnisse, indem sie physikalische oder mikroarchitektonische "Lecks" beobachten, die *korreliert* mit dem internen Zustand sind, aber *nicht* Teil der logischen Schnittstelle des Geräts sind. Beispiele reichen von der Messung des momentanen Stroms, der von einer Smartcard gezogen wird, bis hin zum Missbrauch von CPU-Leistungsmanagementeffekten über ein Netzwerk.

---

## Hauptleckkanäle

| Kanal | Typisches Ziel | Instrumentierung |
|-------|----------------|------------------|
| Stromverbrauch | Smartcards, IoT-Mikrocontroller, FPGAs | Oszilloskop + Shunt-Widerstand/HS-Sonde (z.B. CW503) |
| Elektromagnetisches Feld (EM) | CPUs, RFID, AES-Beschleuniger | H-Feld-Sonde + LNA, ChipWhisperer/RTL-SDR |
| Ausführungszeit / Caches | Desktop- & Cloud-CPUs | Hochpräzise Timer (rdtsc/rdtscp), Remote-Zeitmessung |
| Akustisch / mechanisch | Tastaturen, 3D-Drucker, Relais | MEMS-Mikrofon, Laser-Vibrometer |
| Optisch & thermisch | LEDs, Laserdrucker, DRAM | Photodiode / Hochgeschwindigkeitskamera, IR-Kamera |
| Fehlerinduziert | ASIC/MCU-Kryptos | Takt-/Spannungsstörung, EMFI, Laserinjektion |

---

## Leistungsanalyse

### Einfache Leistungsanalyse (SPA)
Beobachten Sie eine *einzelne* Spur und assoziieren Sie direkt Spitzen/Täler mit Operationen (z.B. DES S-Boxen).
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
Erwerben Sie *N > 1 000* Spuren, hypothesieren Sie das Schlüsselbyte `k`, berechnen Sie das HW/HD-Modell und korrelieren Sie mit dem Leak.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA bleibt auf dem neuesten Stand, aber Varianten des maschinellen Lernens (MLA, Deep-Learning SCA) dominieren jetzt Wettbewerbe wie ASCAD-v2 (2023).

---

## Elektromagnetische Analyse (EMA)
Nahfeld-EM-Sonden (500 MHz–3 GHz) lecken identische Informationen wie die Leistungsanalyse *ohne* Shunts einzufügen. Forschungen aus 2024 zeigten die Schlüsselrückgewinnung in **>10 cm** von einem STM32 unter Verwendung von Spektralkorrelation und kostengünstigen RTL-SDR-Frontends.

---

## Timing- und Mikroarchitekturangriffe
Moderne CPUs lecken Geheimnisse durch gemeinsame Ressourcen:
* **Hertzbleed (2022)** – DVFS-Frequenzskalierung korreliert mit Hamming-Gewicht, was die *remote* Extraktion von EdDSA-Schlüsseln ermöglicht.
* **Downfall / Gather Data Sampling (Intel, 2023)** – Transient-Execution zum Lesen von AVX-Gather-Daten über SMT-Threads.
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – spekulative Vektorfehlvorhersage leckt Register über Domänen hinweg.

---

## Akustische & optische Angriffe
* 2024 "​iLeakKeys" zeigte eine Genauigkeit von 95 %, um Laptop-Tastatureingaben von einem **Smartphone-Mikrofon über Zoom** mit einem CNN-Klassifikator wiederherzustellen.
* Hochgeschwindigkeits-Photodioden erfassen DDR4-Aktivitäts-LED und rekonstruieren AES-Rundenschlüssel innerhalb von <1 Minute (BlackHat 2023).

---

## Fehlerinjektion & Differentielle Fehleranalyse (DFA)
Die Kombination von Fehlern mit Seitenkanalleckagen verkürzt die Schlüsselsuche (z. B. 1-Trac AES DFA). Neueste, für Hobbyisten erschwingliche Werkzeuge:
* **ChipSHOUTER & PicoEMP** – Sub-1 ns elektromagnetische Pulsstörungen.
* **GlitchKit-R5 (2025)** – Open-Source-Plattform für Takt-/Spannungsstörungen, die RISC-V SoCs unterstützt.

---

## Typischer Angriffsworkflow
1. Identifizieren Sie den Leckkanal & den Montagepunkt (VCC-Pin, Entkopplungskondensator, Nahfeldstelle).
2. Trigger einfügen (GPIO oder musterbasiert).
3. >1 k Traces mit ordnungsgemäßer Abtastung/Filtern sammeln.
4. Vorverarbeiten (Ausrichtung, Mittelwertentfernung, LP/HP-Filter, Wavelet, PCA).
5. Statistische oder ML-Schlüsselrückgewinnung (CPA, MIA, DL-SCA).
6. Validieren und Iteration bei Ausreißern.

---

## Abwehrmaßnahmen & Härtung
* **Konstantzeit**-Implementierungen & speicherharte Algorithmen.
* **Maskierung/Mischen** – Geheimnisse in zufällige Anteile aufteilen; Erstordnungswiderstand zertifiziert durch TVLA.
* **Verbergen** – On-Chip-Spannungsregler, randomisierte Taktung, Dual-Rail-Logik, EM-Schutz.
* **Fehlererkennung** – redundante Berechnung, Schwellenwertsignaturen.
* **Betrieblich** – DVFS/Turbo in Kryptokernen deaktivieren, SMT isolieren, Co-Location in Multi-Tenant-Clouds verbieten.

---

## Werkzeuge & Frameworks
* **ChipWhisperer-Husky** (2024) – 500 MS/s Oszilloskop + Cortex-M-Trigger; Python-API wie oben.
* **Riscure Inspector & FI** – kommerziell, unterstützt automatisierte Leckagebewertung (TVLA-2.0).
* **scaaml** – TensorFlow-basierte Deep-Learning-SCA-Bibliothek (v1.2 – 2025).
* **pyecsca** – ANSSI Open-Source ECC SCA-Framework.

---

## Referenzen

* [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
* [Hertzbleed Attack Paper](https://www.hertzbleed.com/)


{{#include ../../banners/hacktricks-training.md}}
