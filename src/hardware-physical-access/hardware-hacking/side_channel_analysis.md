# Side-Channel-Analyse-Angriffe

{{#include ../../banners/hacktricks-training.md}}

Side-Channel-Angriffe gewinnen Geheimnisse zurück, indem sie physische oder mikroarchitektonische „Leakage“ beobachten, die mit dem internen Zustand *korreliert*, aber *nicht* Teil der logischen Schnittstelle des Geräts ist. Beispiele reichen von der Messung des momentanen Stromverbrauchs einer Smartcard bis hin zur Ausnutzung von CPU-Energieverwaltungseffekten über ein Netzwerk.

---

## Wichtige Leakage-Kanäle

| Kanal | Typisches Ziel | Instrumentierung |
|---------|---------------|-----------------|
| Stromverbrauch | Smartcards, IoT-MCUs, FPGAs | Oszilloskop plus Shunt-Widerstand oder Differenzialsonde; der CW503 ist ein Netzteil für Sonden/LNAs und selbst keine Sonde<sup>[[11]](#references)</sup> |
| Elektromagnetisches Feld (EM) | CPUs, RFID, AES-Beschleuniger | H-Feld-/Nahfeldsonde plus rauscharmer Verstärker und Oszilloskop oder SDR-Empfänger wie ein RTL-SDR<sup>[[13]](#references)</sup> |
| Ausführungszeit / Caches | Desktop- und Cloud-CPUs | Hochpräzise Timer (`rdtsc`/`rdtscp`) oder Remote-Laufzeitmessung |
| Akustik / Mechanik | Tastaturen, 3D-Drucker, Drucker, Relais und CPU-Spannungsregler | MEMS-Mikrofon oder Laser-Vibrometer<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Optik & Wärme | Status-LEDs, Displays, DRAM und thermisch gekoppelte Geräte | Fotodiode, Hochgeschwindigkeitskamera oder IR-Kamera<sup>[[7]](#references)[[16]](#references)</sup> |
| Fault Injection | ASIC-/MCU-Kryptografie | Clock-/Voltage-Glitching, EMFI oder Laser-Injektion |

---

## Power Analysis

### Simple Power Analysis (SPA)
Beobachte eine *einzelne* Messkurve und ordne sichtbare Merkmale Vorgängen wie Verzweigungen, modularer Multiplikation oder unterschiedlichen Befehlssequenzen zu.<sup>[[1]](#references)</sup>

Die genaue Konfiguration hängt vom Ziel ab. Im Folgenden wird die aktuelle High-Level-Capture-API von ChipWhisperer verwendet, nachdem das Oszilloskop und das Zielgerät angeschlossen und konfiguriert wurden:<sup>[[1]](#references)</sup>

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
Erfasse mehrere Traces, stelle eine Hypothese für ein Schlüsselbyte `k` auf, berechne ein Hamming-Gewicht- (HW) oder Hamming-Distanz-Leakage-Modell (HD) und korreliere es mit jedem Sample. Die erforderliche Anzahl an Traces hängt vom Ziel, Rauschen, Alignment, Gegenmaßnahmen und Leakage-Modell ab; sie ist kein fester Schwellenwert.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA ist eine etablierte Basis. Template-Angriffe, Mutual-Information-Analyse und Machine-Learning-Ansätze können nützlich sein, wenn die Leakage nichtlinear ist oder die Traces schlecht ausgerichtet sind.

---

## Elektromagnetische Analyse (EMA)
Nahfeld-EM-Analysen können datenabhängige Aktivität beobachten, ohne einen Shunt in den Versorgungspfad einzufügen. Sie legen nicht zwangsläufig dasselbe Signal offen wie eine Leistungsspur: Sondenposition, Ausrichtung, Bandbreite, Front-End-Verstärkung, Triggerqualität und Abstand spielen alle eine Rolle.

---

## Timing- und Mikroarchitektur-Angriffe
Moderne CPUs leaken Geheimnisse über gemeinsam genutzte Ressourcen:
* **Hertzbleed (2022)** – Datenabhängige dynamische Spannungs- und Frequenzskalierung erzeugt einen Remote-Timing-Kanal. Die ursprüngliche End-to-End-Demonstration zur Schlüsselwiederherstellung zielte auf SIKE; Folgearbeiten behandeln weitere Primitiven.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – Transiente Ausführung kann Daten offenlegen, die von Vector-Gather-Instruktionen über Sicherheitsgrenzen hinweg verwendet werden.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – Eine fehlerhafte Behandlung des spekulativen Vector-Registerzustands kann Daten desselben physischen Kerns offenlegen.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – Ein Angriff auf die transiente Ausführung kombiniert Phantom Execution mit Training in der transienten Ausführung, um vom Angreifer kontrollierte Misprediction-Gadgets zu erzeugen.<sup>[[5]](#references)</sup>

---

## Akustische und optische Angriffe
Akustische Leakage wurde in einem kontrollierten Experiment dazu verwendet, RSA-Schlüssel anhand von Laptopgeräuschen wiederherzustellen, auch mithilfe des Mikrofons eines nahegelegenen Mobiltelefons.<sup>[[6]](#references)</sup> Eine separate Tastaturstudie aus dem Jahr 2023 klassifizierte Tastenanschläge mit 95 % Genauigkeit, wenn sie mit Aufnahmen eines nahegelegenen Telefons trainiert wurde, und mit 93 %, wenn sie mit Zoom-Audio trainiert wurde; diese Werte beziehen sich auf das in der Studie trainierte Gerät und nicht auf beliebige Tastaturen oder Opfer.<sup>[[9]](#references)</sup> Optische Emissionen von Status-LEDs können ebenfalls mit verarbeiteten Daten korreliert werden. Diese Ergebnisse sind spezifisch für das jeweilige Ziel und den Versuchsaufbau; ihre Reichweite oder Erfolgsquote lässt sich nicht auf andere Geräte übertragen.<sup>[[7]](#references)</sup>

---

## Fehlerinduktion und Differential Fault Analysis (DFA)
Die Kombination kontrollierter Fehler mit Side-Channel-Beobachtungen kann bei einigen Algorithmen und Implementierungen den Schlüsselsuchraum verkleinern. Zu den gängigen Laborplattformen gehören die Voltage- und Clock-Glitching-Funktionen von ChipWhisperer sowie dedizierte EM-Fehlerinduktionswerkzeuge wie ChipSHOUTER oder PicoEMP. Die Angabe „unter 1 ns“ aus dem früheren Entwurf sollte nicht als Spezifikation verwendet werden: Im veröffentlichten Handbuch von ChipSHOUTER werden typische Pulsbreiten von **15–80 ns** mit der 1-mm-Spitze und **24–480 ns** mit der 4-mm-Spitze angegeben (der Trigger-/Puls-Jitter wird jedoch in Pikosekunden spezifiziert). Die erforderliche Zeitauflösung, Sondenplatzierung und Anzahl fehlerhafter Ausgaben hängen vom Ziel und Fehlermodell ab.<sup>[[1]](#references)[[10]](#references)</sup>

## Nicht verifizierte Recherchehinweise aus dem früheren Entwurf

Der frühere Entwurf behauptete außerdem: ein **500 MHz–3 GHz**-EM-Setup, das mit einem RTL-SDR einen STM32-Schlüssel aus mehr als **10 cm** Entfernung wiederherstellt; eine DDR4-Aktivitäts-LED, die bei „Black Hat 2023“ in weniger als einer Minute einen AES-Rundenschlüssel preisgibt; sowie eine Open-Source-RISC-V-Glitching-Plattform namens **GlitchKit-R5** aus dem Jahr 2025. Bei dieser Prüfung konnten keine passenden Primärarbeiten, Konferenzmaterialien oder Projektrepositories gefunden werden. Diese konkreten Angaben bleiben als Recherche- und Reproduktionshinweise erhalten, nicht als bestätigte Ergebnisse oder Werkzeugempfehlungen.

---

## Typischer Angriffsablauf
1. Leakage-Kanal und Messpunkt identifizieren (VCC-Pin, Entkopplungskondensator, Nahfeldbereich).
2. Trigger einfügen (GPIO oder musterbasiert).  
3. Genügend Traces für den gewählten statistischen Test erfassen und Klartext/Chiffrat sowie weitere Metadaten aufzeichnen.
4. Vorverarbeitung durchführen (Ausrichtung, Mittelwertentfernung, LP-/HP-Filter, Wavelet, PCA).
5. Statistische oder ML-Schlüsselwiederherstellung (CPA, MIA, DL-SCA).
6. Ausreißer überprüfen und den Ablauf wiederholen.

---

## Abwehrmaßnahmen und Härtung
* **Constant-time**-Implementierungen und speicherharte Algorithmen.
* **Masking/Shuffling** – Geheimnisse in zufällige Anteile aufteilen; Widerstand gegen Angriffe erster Ordnung durch TVLA zertifiziert.
* **Hiding** – On-Chip-Spannungsregler, randomisierter Takt, Dual-Rail-Logik, EM-Abschirmungen.
* **Fehlererkennung** – redundante Berechnungen, Schwellwertsignaturen.
* **Betrieblich** – DVFS/Turbo in Crypto-Kernels deaktivieren, SMT isolieren, Co-Location in Multi-Tenant-Clouds untersagen.

---

## Tools und Frameworks
* **ChipWhisperer-Husky** (2024) – 500-MS/s-Oszilloskop + Cortex-M-Trigger; Python-API wie oben.<sup>[[1]](#references)</sup>
* **Riscure Inspector und Fault-Injection-Produkte** – kommerzielle Analyse- und automatisierte Testwerkzeuge.
* **scaaml** – TensorFlow-basierte Deep-Learning-SCA-Tools und Datensätze.<sup>[[12]](#references)</sup>
* **pyecsca** – Open-Source-Toolkit für Reverse Engineering von Black-Box-ECC-Implementierungen mithilfe von Side Channels.<sup>[[8]](#references)</sup>

---

## References

- [1] [ChipWhisperer-Dokumentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed-Angriffspapier](https://www.hertzbleed.com/)
- [3] [Downfall: Ausnutzung spekulativer Datenerfassung](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Neue Angriffsflächen durch Training in der transienten Ausführung aufdecken](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [RSA-Schlüsselextraktion durch akustische Kryptanalyse mit geringer Bandbreite](https://eprint.iacr.org/2013/857.pdf)
- [7] [Informationsleckage durch optische Emissionen](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [pyecsca-Artefaktdokumentation](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Ein praktischer Deep-Learning-basierter akustischer Side-Channel-Angriff auf Tastaturen](https://arxiv.org/abs/2308.01074)
- [10] [NewAE – ChipSHOUTER-Benutzerhandbuch](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [ChipWhisperer-Dokumentation — CW503-Sondenstromversorgung](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Google-SCAAML-Dokumentation](https://google.github.io/scaaml/)
- [13] [FOSDEM — Kostengünstige elektromagnetische Side-Channel-Angriffe mit RTL-SDR durchführen](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Geistiges Eigentum entschlüsseln: Akustischer und magnetischer Side-Channel-Angriff auf einen 3D-Drucker](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — Akustische Side-Channel-Angriffe auf Drucker](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Temperaturüberwachung mithilfe von DRAM](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
{{#include ../../banners/hacktricks-training.md}}
