# Seitenkanalangriffe

{{#include ../../banners/hacktricks-training.md}}

Side-Channel-Angriffe gewinnen Geheimnisse, indem sie physische oder mikroarchitektonische „Leakage“ beobachten, die mit dem internen Zustand *korreliert*, aber *nicht* Teil der logischen Schnittstelle des Geräts ist. Die Beispiele reichen vom Messen des momentanen Stromverbrauchs einer Smartcard bis zur Ausnutzung von CPU-Energiespareffekten über ein Netzwerk.

Bei einem Ziel mit zugänglicher ARM-Debug-Hardware kann [CoreSight ETM tracing over SWO](arm-coresight-instruction-tracing.md) neben Strom- oder EM-Aufzeichnungen eine Referenz für den Ausführungspfad liefern; es handelt sich um einen Debug-Trace, nicht um einen Leakage-Kanal.<sup>[[17]](#references)</sup>

---

## Hauptkanäle für Leakage

| Kanal | Typisches Ziel | Instrumentierung |
|---------|---------------|-----------------|
| Stromverbrauch | Smartcards, IoT-MCUs, FPGAs | Oszilloskop mit Shunt-Widerstand oder Differenzialsonde; der CW503 ist ein Netzteil für Sonden/LNAs und selbst keine Sonde<sup>[[11]](#references)</sup> |
| Elektromagnetisches Feld (EM) | CPUs, RFID, AES-Beschleuniger | H-Feld-/Nahfeldsonde mit rauscharmer Verstärkerstufe und Oszilloskop oder SDR-Empfänger wie einem RTL-SDR<sup>[[13]](#references)</sup> |
| Ausführungszeit / Caches | Desktop- und Cloud-CPUs | Hochpräzise Timer (`rdtsc`/`rdtscp`) oder remote gemessene Laufzeit |
| Akustik / Mechanik | Tastaturen, 3D-Drucker, Drucker, Relais und CPU-Spannungsregler | MEMS-Mikrofon oder Laser-Vibrometer<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Optik und Wärme | Status-LEDs, Displays, DRAM und thermisch gekoppelte Geräte | Photodiode, Hochgeschwindigkeitskamera oder IR-Kamera<sup>[[7]](#references)[[16]](#references)</sup> |
| Fault Injection | ASIC-/MCU-Kryptografie | Clock-/Voltage-Glitching, EMFI oder Laser-Injection |

---

## Leistungsanalyse

### Simple Power Analysis (SPA)
Beobachte einen *einzelnen* Trace und ordne sichtbare Merkmale Operationen wie Verzweigungen, modularen Multiplikationen oder unterschiedlichen Instruktionssequenzen zu.<sup>[[1]](#references)</sup>

Das genaue Setup hängt vom Ziel ab. Das folgende Beispiel verwendet die aktuelle High-Level-Capture-API von ChipWhisperer, nachdem Oszilloskop und Zielgerät verbunden und konfiguriert wurden:<sup>[[1]](#references)</sup>

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
Erfasse mehrere Traces, stelle eine Hypothese für ein Schlüsselbyte `k` auf, berechne ein Hamming-Gewicht- (HW) oder Hamming-Distanz-Leakage-Modell (HD) und korreliere es mit jedem Sample. Die erforderliche Anzahl an Traces hängt vom Ziel, Rauschen, Alignment, Gegenmaßnahmen und Leakage-Modell ab; es gibt keinen festen Schwellenwert.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA ist eine standardmäßige Baseline. Template-Angriffe, Mutual-Information-Analyse und Machine-Learning-Ansätze können nützlich sein, wenn die Leckage nichtlinear ist oder die Traces schlecht ausgerichtet sind.

---

## Elektromagnetische Analyse (EMA)
Nahfeld-EM-Analyse kann datenabhängige Aktivität beobachten, ohne einen Shunt in den Versorgungspfad einzufügen. Sie macht nicht unbedingt dasselbe Signal sichtbar wie ein Power-Trace: Sondenposition, Ausrichtung, Bandbreite, Front-End-Verstärkung, Triggerqualität und Abstand spielen alle eine Rolle.

---

## Timing- und Mikroarchitektur-Angriffe
Moderne CPUs leaken Geheimnisse über gemeinsam genutzte Ressourcen:
* **Hertzbleed (2022)** – Datenabhängige dynamische Spannungs- und Frequenzskalierung erzeugt einen Remote-Timing-Kanal. Die ursprüngliche End-to-End-Demonstration der Schlüsselwiederherstellung zielte auf SIKE; Folgearbeiten behandeln weitere Primitive.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – Transiente Ausführung kann Daten offenlegen, die von Vector-Gather-Instruktionen über Sicherheitsgrenzen hinweg verwendet werden.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – Die fehlerhafte Behandlung des Zustands spekulativer Vektorregister kann Daten vom selben physischen Kern offenlegen.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – Ein Angriff über transiente Ausführung kombiniert Phantom-Ausführung mit Training während der transienten Ausführung, um vom Angreifer kontrollierte Misprediction-Gadgets zu erzeugen.<sup>[[5]](#references)</sup>

---

## Akustische und optische Angriffe
Akustische Leckage wurde in einem kontrollierten Experiment verwendet, um RSA-Schlüssel aus Laptopgeräuschen wiederherzustellen, auch mithilfe eines Mikrofons in einem nahegelegenen Mobiltelefon.<sup>[[6]](#references)</sup> Eine separate Tastaturstudie aus dem Jahr 2023 klassifizierte Tastenanschläge mit 95 % Genauigkeit, wenn sie mit Aufnahmen von einem nahegelegenen Telefon trainiert wurde, und mit 93 % bei Training mit Zoom-Audio; diese Werte beschreiben das Trainingsexperiment mit dem untersuchten Gerät aus dieser Studie, nicht beliebige Tastaturen oder Opfer.<sup>[[9]](#references)</sup> Optische Abstrahlungen von Status-LEDs können ebenfalls mit verarbeiteten Daten korreliert werden. Diese Ergebnisse sind ziel- und aufbauspezifisch; die Reichweite oder Erfolgsrate sollte nicht auf andere Geräte verallgemeinert werden.<sup>[[7]](#references)</sup>

---

## Fault Injection und Differential Fault Analysis (DFA)
Die Kombination kontrollierter Fehler mit Side-Channel-Beobachtungen kann den Schlüsselsuchraum für bestimmte Algorithmen und Implementierungen verkleinern. Zu den gängigen Laborplattformen gehören die Voltage-/Clock-Glitching-Funktionen von ChipWhisperer und dedizierte EM-Fault-Injection-Tools wie ChipSHOUTER oder PicoEMP. Die Angabe „sub-1 ns“ aus dem früheren Entwurf sollte nicht als Spezifikation verwendet werden: Im veröffentlichten Handbuch von ChipSHOUTER werden typische eingefügte Pulsbreiten von **15–80 ns** mit der 1-mm-Spitze und **24–480 ns** mit der 4-mm-Spitze angegeben (Trigger-/Puls-Jitter wird jedoch in Pikosekunden spezifiziert). Die erforderliche Timing-Auflösung, Sondenposition und Anzahl fehlerhafter Ausgaben hängen vom Ziel und Fehlermodell ab.<sup>[[1]](#references)[[10]](#references)</sup>

## Unbestätigte Forschungshinweise aus dem früheren Entwurf

Der frühere Entwurf behauptete außerdem: ein **500 MHz–3 GHz**-EM-Aufbau, der mithilfe eines RTL-SDR einen STM32-Schlüssel aus mehr als **10 cm** Entfernung wiederherstellt; eine DDR4-Aktivitäts-LED, die bei „Black Hat 2023“ in weniger als einer Minute einen AES-Rundenschlüssel offenlegt; und eine Open-Source-RISC-V-Glitching-Plattform namens **GlitchKit-R5** aus dem Jahr 2025. Bei dieser Prüfung ließ sich keine passende Primärveröffentlichung, kein Konferenzmaterial und kein Projekt-Repository finden. Diese konkreten Angaben bleiben als Such- und Reproduktionshinweise erhalten, nicht als bestätigte Ergebnisse oder Tool-Empfehlungen.

---

## Typischer Angriffsablauf
1. Leckagekanal und Messpunkt bestimmen (VCC-Pin, Entkopplungskondensator, Nahfeldpunkt).
2. Trigger einfügen (GPIO oder musterbasiert).  
3. Genügend Traces für den gewählten statistischen Test sammeln und Klartext/Ciphertext sowie weitere Metadaten aufzeichnen.
4. Vorverarbeiten (Ausrichtung, Mittelwertentfernung, LP-/HP-Filter, Wavelet, PCA).
5. Statistische oder ML-Schlüsselwiederherstellung (CPA, MIA, DL-SCA).
6. Ergebnisse validieren und bei Ausreißern iterieren.

---

## Abwehrmaßnahmen und Härtung
* **Constant-Time**-Implementierungen und speicherharte Algorithmen.
* **Masking/Shuffling** – Geheimnisse in zufällige Anteile aufteilen; Widerstand gegen Angriffe erster Ordnung durch TVLA zertifizieren.
* **Hiding** – On-Chip-Spannungsregler, randomisierter Takt, Dual-Rail-Logik, EM-Abschirmungen.
* **Fehlererkennung** – redundante Berechnungen, Threshold-Signaturen.
* **Betrieblich** – DVFS/Turbo in Krypto-Kernels deaktivieren, SMT isolieren, Co-Location in mandantenfähigen Clouds verhindern.

---

## Tools und Frameworks
* **ChipWhisperer-Husky** (2024) – 500-MS/s-Oszilloskop + Cortex-M-Trigger; Python-API wie oben.<sup>[[1]](#references)</sup>
* **Riscure Inspector und Fault-Injection-Produkte** – kommerzielle Analyse- und automatisierte Test-Tools.
* **scaaml** – TensorFlow-basierte Deep-Learning-SCA-Tools und Datensätze.<sup>[[12]](#references)</sup>
* **pyecsca** – Open-Source-Toolkit für Reverse Engineering von Black-Box-ECC-Implementierungen über Side-Channels.<sup>[[8]](#references)</sup>

---

## References

- [1] [ChipWhisperer-Dokumentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed-Angriffspapier](https://www.hertzbleed.com/)
- [3] [Downfall: Ausnutzen spekulativer Datenerfassung](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Aufdecken neuer Angriffsflächen durch Training während der transienten Ausführung](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [RSA-Schlüsselextraktion mittels akustischer Kryptanalyse mit geringer Bandbreite](https://eprint.iacr.org/2013/857.pdf)
- [7] [Informationsleckage durch optische Abstrahlungen](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [pyecsca-Artefaktdokumentation](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Ein praktischer akustischer Side-Channel-Angriff auf Tastaturen auf Basis von Deep Learning](https://arxiv.org/abs/2308.01074)
- [10] [NewAE – ChipSHOUTER-Benutzerhandbuch](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [ChipWhisperer-Dokumentation — CW503-Sondenstromversorgung](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Google-SCAAML-Dokumentation](https://google.github.io/scaaml/)
- [13] [FOSDEM — Kostengünstige elektromagnetische Side-Channel-Angriffe mit RTL-SDR durchführen](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Geistiges Eigentum entschlüsseln: Akustischer und magnetischer Side-Channel-Angriff auf einen 3D-Drucker](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — Akustische Side-Channel-Angriffe auf Drucker](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Temperaturüberwachung mittels DRAM](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
- [17] [Den Instruktionen folgen: Live-ARM-Tracing mit ETM, ITM und TPIU](https://voidstarsec.com/blog/arm-tracing-etm-itm)
{{#include ../../banners/hacktricks-training.md}}
