# Side-Channel-Analysis-Angriffe

{{#include ../../banners/hacktricks-training.md}}

Side-channel attacks gewinnen Geheimnisse durch die Beobachtung physischer oder mikroarchitektonischer „leakage“, die *mit* dem internen Zustand *korreliert*, aber *nicht* Teil der logischen Schnittstelle des Geräts ist. Beispiele reichen von der Messung des momentanen Stromverbrauchs einer Smartcard bis zur Ausnutzung von CPU-Power-Management-Effekten über ein Netzwerk.

---

## Wichtige Leakage-Kanäle

| Kanal | Typisches Ziel | Instrumentierung |
|---------|---------------|-----------------|
| Stromverbrauch | Smartcards, IoT-MCUs, FPGAs | Oszilloskop plus Shunt-Widerstand oder Differenzialsonde; der CW503 ist ein Netzteil für Sonden/LNAs und selbst keine Sonde<sup>[[11]](#references)</sup> |
| Elektromagnetisches Feld (EM) | CPUs, RFID, AES-Beschleuniger | H-Feld-/Nahfeldsonde plus rauscharmen Verstärker und Oszilloskop oder SDR-Empfänger wie ein RTL-SDR<sup>[[13]](#references)</sup> |
| Ausführungszeit / Caches | Desktop- und Cloud-CPUs | Hochpräzise Timer (`rdtsc`/`rdtscp`) oder Remote-Time-of-Flight |
| Akustisch / mechanisch | Tastaturen, 3-D-Drucker, Drucker, Relais und CPU-Spannungsregler | MEMS-Mikrofon oder Laser-Vibrometer<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Optisch & thermisch | Status-LEDs, Displays, DRAM und thermisch gekoppelte Geräte | Fotodiode, Hochgeschwindigkeitskamera oder IR-Kamera<sup>[[7]](#references)[[16]](#references)</sup> |
| Fault injection | ASIC-/MCU-Kryptografie | Clock-/Voltage-Glitch, EMFI oder Laser-Injektion |

---

## Power Analysis

### Simple Power Analysis (SPA)
Beobachte einen *einzelnen* Trace und ordne sichtbare Merkmale Operationen wie Verzweigungen, modularer Multiplikation oder unterschiedlichen Instruktionssequenzen zu.<sup>[[1]](#references)</sup>

Das genaue Setup ist zielspezifisch. Das folgende Beispiel verwendet die aktuelle High-Level-Capture-API von ChipWhisperer, nachdem Scope und Target verbunden und konfiguriert wurden:<sup>[[1]](#references)</sup>
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
Erfasse mehrere Traces, stelle eine Hypothese für ein Schlüsselbyte `k` auf, berechne ein Hamming-Gewichts- (HW) oder Hamming-Distanz- (HD)-Leakage-Modell und korreliere es mit jedem Sample. Die erforderliche Anzahl an Traces wird durch das Ziel, das Rauschen, die Ausrichtung, Gegenmaßnahmen und das Leakage-Modell bestimmt; sie ist kein fester Schwellenwert.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA ist eine standardmäßige Baseline. Template attacks, mutual-information analysis und Machine-Learning-Ansätze können nützlich sein, wenn der leak nichtlinear ist oder Traces schlecht ausgerichtet sind.

---

## Elektromagnetische Analyse (EMA)
Near-field-EM-Analyse kann datenabhängige Aktivität beobachten, ohne einen Shunt in den Versorgungspfad einzufügen. Sie legt nicht unbedingt dasselbe Signal offen wie ein Power-Trace: Sondenposition, Ausrichtung, Bandbreite, Frontend-Verstärkung, Trigger-Qualität und Abstand sind entscheidend.

---

## Timing- und mikroarchitektonische Angriffe
Moderne CPUs leaken Geheimnisse über gemeinsam genutzte Ressourcen:
* **Hertzbleed (2022)** – Datenabhängige dynamische Spannungs- und Frequenzskalierung erzeugt einen Remote-Timing-Kanal. Die ursprüngliche End-to-End-Demonstration zur Schlüsselwiederherstellung zielte auf SIKE; Folgearbeiten behandeln weitere Primitive.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – Transient execution kann Daten offenlegen, die von Vector-Gather-Instruktionen über Sicherheitsgrenzen hinweg verwendet werden.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – Eine fehlerhafte Behandlung des spekulativen Zustands von Vector-Registern kann Daten vom selben physischen Core offenlegen.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – Ein Transient-Execution-Angriff kombiniert Phantom Execution mit Training in transient execution, um vom Angreifer kontrollierte Misprediction-Gadgets zu erzeugen.<sup>[[5]](#references)</sup>

---

## Akustische und optische Angriffe
Akustische Leaks wurden in einem kontrollierten Experiment verwendet, um RSA-Schlüssel aus Laptop-Geräuschen wiederherzustellen, auch mithilfe des Mikrofons eines nahegelegenen Mobiltelefons.<sup>[[6]](#references)</sup> Eine separate Keyboard-Studie aus dem Jahr 2023 klassifizierte Tastendrücke mit 95 % Genauigkeit, wenn sie mit Aufnahmen von einem nahegelegenen Telefon trainiert wurde, und mit 93 % bei Training mit Zoom-Audio; diese Werte beschreiben das Training-auf-dem-Gerät-Experiment dieser Studie, nicht beliebige Tastaturen oder Opfer.<sup>[[9]](#references)</sup> Optische Emissionen von Status-LEDs können ebenfalls mit verarbeiteten Daten korreliert werden. Diese Ergebnisse sind ziel- und setupspezifisch; ihre Reichweite oder Erfolgsrate sollte nicht auf andere Geräte verallgemeinert werden.<sup>[[7]](#references)</sup>

---

## Fault Injection und Differential Fault Analysis (DFA)
Die Kombination kontrollierter Fehler mit Side-Channel-Beobachtungen kann die Schlüsselsuche für manche Algorithmen und Implementierungen verkürzen. Zu den üblichen Laborplattformen gehören die Voltage-/Clock-Glitching-Funktionen von ChipWhisperer sowie dedizierte EM-Fault-Injection-Tools wie ChipSHOUTER oder PicoEMP. Die Beschreibung „sub-1 ns“ aus dem früheren Entwurf sollte nicht als Spezifikation verwendet werden: Das veröffentlichte Handbuch von ChipSHOUTER nennt typische eingefügte Pulsbreiten von **15–80 ns** mit seiner 1-mm-Spitze und **24–480 ns** mit seiner 4-mm-Spitze (obwohl Trigger-/Puls-Jitter in Pikosekunden spezifiziert wird). Die erforderliche Timing-Auflösung, Sondenplatzierung und Anzahl fehlerhafter Ausgaben hängen vom Ziel und Fault Model ab.<sup>[[1]](#references)[[10]](#references)</sup>

## Nicht verifizierte Forschungsansätze aus dem früheren Entwurf

Der frühere Entwurf behauptete außerdem: ein **500 MHz–3 GHz**-EM-Setup, das mithilfe eines RTL-SDR einen STM32-Schlüssel aus mehr als **10 cm** Entfernung wiederherstellt; eine DDR4-Aktivitäts-LED, die bei „Black Hat 2023“ innerhalb von weniger als einer Minute einen AES-Rundenschlüssel offenlegt; sowie eine Open-Source-RISC-V-Glitching-Plattform namens **GlitchKit-R5** aus dem Jahr 2025. Während dieses Audits konnte keine passende Primärarbeit, kein Konferenzmaterial und kein Projekt-Repository gefunden werden. Diese exakten Details werden als Ansätze für Suche und Reproduktion beibehalten, nicht als etablierte Ergebnisse oder Tooling-Empfehlungen.

---

## Typischer Angriffs-Workflow
1. Leak-Kanal und Mounting-Point identifizieren (VCC-Pin, Entkopplungskondensator, Near-Field-Punkt).
2. Trigger einfügen (GPIO- oder pattern-basiert).
3. Ausreichend viele Traces für den gewählten statistischen Test erfassen und dabei Plaintext/Ciphertext sowie weitere Metadaten aufzeichnen.
4. Vorverarbeitung durchführen (Alignment, Mittelwertentfernung, LP-/HP-Filter, Wavelet, PCA).
5. Statistische oder ML-Schlüsselwiederherstellung (CPA, MIA, DL-SCA).
6. Ausreißer validieren und iterativ weiterarbeiten.

---

## Abwehrmaßnahmen und Hardening
* **Constant-Time**-Implementierungen und Memory-Hard-Algorithmen.
* **Masking/Shuffling** – Geheimnisse in zufällige Shares aufteilen; First-Order-Resistenz durch TVLA zertifiziert.
* **Hiding** – On-Chip-Spannungsregler, randomisierter Takt, Dual-Rail-Logik, EM-Schilde.
* **Fault Detection** – redundante Berechnung, Threshold-Signaturen.
* **Betrieblich** – DVFS/Turbo in Crypto-Kernels deaktivieren, SMT isolieren, Co-Location in Multi-Tenant-Clouds untersagen.

---

## Tools und Frameworks
* **ChipWhisperer-Husky** (2024) – 500-MS/s-Scope plus Cortex-M-Trigger; Python-API wie oben.<sup>[[1]](#references)</sup>
* **Riscure Inspector und Fault-Injection-Produkte** – kommerzielle Analyse- und automatisierte Test-Tools.
* **scaaml** – TensorFlow-basierte Deep-Learning-SCA-Tools und Datasets.<sup>[[12]](#references)</sup>
* **pyecsca** – Open-Source-Toolkit für Reverse Engineering von Black-Box-ECC-Implementierungen durch Side-Channels.<sup>[[8]](#references)</sup>

---

## References

- [1] [ChipWhisperer-Dokumentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed-Angriffspapier](https://www.hertzbleed.com/)
- [3] [Downfall: Ausnutzung spekulativer Datensammlung](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Neue Angriffsflächen durch Training in transient execution offenlegen](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [RSA-Schlüsselextraktion durch akustische Kryptanalyse mit niedriger Bandbreite](https://eprint.iacr.org/2013/857.pdf)
- [7] [Informationsleck durch optische Emissionen](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [pyecsca-Artefaktdokumentation](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Ein praktischer, auf Deep Learning basierender akustischer Side-Channel-Angriff auf Tastaturen](https://arxiv.org/abs/2308.01074)
- [10] [NewAE – ChipSHOUTER-Benutzerhandbuch](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [ChipWhisperer-Dokumentation – CW503-Sondenstromversorgung](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Google-SCAAML-Dokumentation](https://google.github.io/scaaml/)
- [13] [FOSDEM – Durchführung kostengünstiger elektromagnetischer Side-Channel-Angriffe mit RTL-SDR](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Geistiges Eigentum entschlüsseln: Akustischer und magnetischer Side-Channel-Angriff auf einen 3D-Drucker](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security – Akustische Side-Channel-Angriffe auf Drucker](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Temperaturüberwachung mithilfe von DRAM](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
{{#include ../../banners/hacktricks-training.md}}
