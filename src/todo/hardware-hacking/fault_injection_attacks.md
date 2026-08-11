# Fault-Injection-Angriffe

{{#include ../../banners/hacktricks-training.md}}

Fault Injection stört ein Gerät während des Betriebs gezielt, sodass es eine falsche Berechnung ausführt. Ein nützlicher Fehler kann eine Instruktion überspringen, Daten beschädigen, eine Sicherheitsprüfung umgehen oder fehlerhafte kryptografische Ausgaben erzeugen, aus denen sich geheime Informationen ableiten lassen.<sup>[[1]](#references)</sup>

Gängige Techniken manipulieren die Versorgungsspannung oder den Takt, injizieren elektromagnetische Störungen oder verwenden optische bzw. laserbasierte Anregung.<sup>[[1]](#references)</sup> Ihre Präzision und Invasivität unterscheiden sich, aber erfolgreiche Tests erfordern im Allgemeinen einen wiederholbaren Trigger und systematische Durchläufe über Zeitsteuerung, Impulsbreite und Intensität. Beginne mit einer stabilen Baseline, erfasse Resets und fehlerhafte Ausgaben getrennt und ändere jeweils nur einen Parameter.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - Nicht-invasive Trigger-freie Fault-Injection-Methode auf Basis gezielter elektromagnetischer Interferenz](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [ChipWhisperer-Dokumentation - Übersicht und Vergleich der Capture-Hardware](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
