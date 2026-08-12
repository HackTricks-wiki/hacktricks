# Fault Injection Attacks

{{#include ../../banners/hacktricks-training.md}}

Fault injection - in der Hardware-Sicherheit oft als **glitching** bezeichnet - stört ein Gerät während des Betriebs absichtlich, sodass es eine falsche Berechnung durchführt. Ein nützlicher Fehler kann eine Instruktion überspringen, Daten beschädigen, eine Sicherheitsprüfung umgehen oder eine fehlerhafte kryptografische Ausgabe erzeugen, aus der sich geheime Informationen ableiten lassen.<sup>[[1]](#references)</sup>

Übliche Techniken manipulieren die Versorgungsspannung oder den Takt, injizieren elektromagnetische Störungen oder verwenden optische beziehungsweise Laser-Stimulation.<sup>[[1]](#references)</sup> Ihre Präzision und Invasivität unterscheiden sich, aber erfolgreiche Tests erfordern im Allgemeinen einen wiederholbaren trigger und systematische Sweeps über Timing, Impulsbreite und Intensität. Beginne mit einer stabilen baseline, erfasse Resets und fehlerhafte Ausgaben getrennt und ändere jeweils nur einen Parameter.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - Nicht-invasive trigger-freie Methode zur Fault Injection auf Grundlage absichtlich erzeugter elektromagnetischer Störungen](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [ChipWhisperer-Dokumentation - Übersicht und Vergleich der Capture-Hardware](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
