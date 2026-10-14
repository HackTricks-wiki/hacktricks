# Fault-Injection-Angriffe

{{#include ../../banners/hacktricks-training.md}}

Fault Injection – in der Hardware-Sicherheit oft **Glitching** genannt – stört ein Gerät während des Betriebs gezielt, damit es eine fehlerhafte Berechnung ausführt. Ein nützlicher Fehler kann eine Instruktion überspringen, Daten beschädigen, eine Sicherheitsprüfung umgehen oder fehlerhafte kryptografische Ausgaben erzeugen, aus denen sich geheime Informationen ableiten lassen.<sup>[[1]](#references)</sup>

Gängige Techniken verändern die Versorgungsspannung oder den Takt, erzeugen elektromagnetische Störungen oder verwenden optische beziehungsweise Laser-Stimulation.<sup>[[1]](#references)</sup> Sie unterscheiden sich hinsichtlich Präzision und Invasivität. Erfolgreiche Tests erfordern jedoch in der Regel einen reproduzierbaren Trigger und systematische Variationen von Timing, Impulsbreite und Intensität. Beginne mit einer stabilen Ausgangsbasis, erfasse Resets und fehlerhafte Ausgaben getrennt und ändere jeweils nur einen Parameter.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. – Nicht-invasive Trigger-freie Fault-Injection-Methode auf Basis gezielter elektromagnetischer Störungen](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [ChipWhisperer-Dokumentation – Übersicht und Vergleich der Capture-Hardware](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
