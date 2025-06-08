# AI-Risiken

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Schwachstellen

Owasp hat die Top 10 Machine Learning Schwachstellen identifiziert, die AI-Systeme betreffen können. Diese Schwachstellen können zu verschiedenen Sicherheitsproblemen führen, einschließlich Datenvergiftung, Modellinversion und adversarialen Angriffen. Das Verständnis dieser Schwachstellen ist entscheidend für den Aufbau sicherer AI-Systeme.

Für eine aktualisierte und detaillierte Liste der Top 10 Machine Learning Schwachstellen verweisen Sie auf das [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) Projekt.

- **Eingabemanipulationsangriff**: Ein Angreifer fügt winzige, oft unsichtbare Änderungen an **eingehenden Daten** hinzu, sodass das Modell die falsche Entscheidung trifft.\
*Beispiel*: Ein paar Farbspritzer auf einem Stoppschild täuschen ein selbstfahrendes Auto, sodass es ein Geschwindigkeitsbegrenzungsschild "sieht".

- **Datenvergiftungsangriff**: Der **Trainingssatz** wird absichtlich mit schlechten Proben kontaminiert, wodurch das Modell schädliche Regeln lernt.\
*Beispiel*: Malware-Binärdateien werden in einem Antivirus-Trainingskorpus fälschlicherweise als "gutartig" gekennzeichnet, sodass ähnliche Malware später durchrutscht.

- **Modellinversionsangriff**: Durch das Abfragen von Ausgaben erstellt ein Angreifer ein **Umkehrmodell**, das sensible Merkmale der ursprünglichen Eingaben rekonstruiert.\
*Beispiel*: Rekonstruktion eines MRI-Bildes eines Patienten aus den Vorhersagen eines Krebsdiagnosemodells.

- **Mitgliedschaftsinferenzangriff**: Der Angreifer testet, ob ein **bestimmter Datensatz** während des Trainings verwendet wurde, indem er Unterschiede in der Zuversicht erkennt.\
*Beispiel*: Bestätigung, dass eine Banktransaktion einer Person in den Trainingsdaten eines Betrugserkennungsmodells erscheint.

- **Modellklau**: Wiederholtes Abfragen ermöglicht es einem Angreifer, Entscheidungsgrenzen zu lernen und das **Verhalten des Modells zu klonen** (und IP).\
*Beispiel*: Ernte von genügend Q&A-Paaren aus einer ML-as-a-Service-API, um ein nahezu gleichwertiges lokales Modell zu erstellen.

- **AI-Lieferkettenangriff**: Kompromittieren Sie jede Komponente (Daten, Bibliotheken, vortrainierte Gewichte, CI/CD) in der **ML-Pipeline**, um nachgelagerte Modelle zu korrumpieren.\
*Beispiel*: Eine vergiftete Abhängigkeit auf einem Modell-Hub installiert ein mit einem Hintertür versehenes Sentiment-Analyse-Modell in vielen Apps.

- **Transfer-Learning-Angriff**: Bösartige Logik wird in ein **vortrainiertes Modell** eingebaut und übersteht das Feintuning für die Aufgabe des Opfers.\
*Beispiel*: Ein Vision-Backbone mit einem versteckten Trigger ändert weiterhin Labels, nachdem es für die medizinische Bildgebung angepasst wurde.

- **Modellverzerrung**: Subtil voreingenommene oder falsch gekennzeichnete Daten **verschieben die Ausgaben des Modells**, um die Agenda des Angreifers zu begünstigen.\
*Beispiel*: Einspeisung von "sauberen" Spam-E-Mails, die als Ham gekennzeichnet sind, sodass ein Spam-Filter ähnliche zukünftige E-Mails durchlässt.

- **Ausgabeintegritätsangriff**: Der Angreifer **ändert die Modellvorhersagen während des Transports**, nicht das Modell selbst, und täuscht nachgelagerte Systeme.\
*Beispiel*: Ändern des "bösartigen" Urteils eines Malware-Klassifizierers in "gutartig", bevor die Datei-Quarantäne-Phase sie sieht.

- **Modellvergiftung** --- Direkte, gezielte Änderungen an den **Modellparametern** selbst, oft nach Erlangung von Schreibzugriff, um das Verhalten zu ändern.\
*Beispiel*: Anpassen der Gewichte eines Betrugserkennungsmodells in der Produktion, sodass Transaktionen von bestimmten Karten immer genehmigt werden.


## Google SAIF Risiken

Google's [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) skizziert verschiedene Risiken, die mit AI-Systemen verbunden sind:

- **Datenvergiftung**: Böswillige Akteure ändern oder injizieren Trainings-/Feinabstimmungsdaten, um die Genauigkeit zu verringern, Hintertüren einzufügen oder Ergebnisse zu verzerren, was die Integrität des Modells über den gesamten Datenlebenszyklus untergräbt.

- **Unbefugte Trainingsdaten**: Das Einpflegen von urheberrechtlich geschützten, sensiblen oder unzulässigen Datensätzen schafft rechtliche, ethische und leistungsbezogene Haftungen, da das Modell aus Daten lernt, die es niemals verwenden durfte.

- **Manipulation der Modellquelle**: Manipulation des Modellcodes, der Abhängigkeiten oder der Gewichte in der Lieferkette oder durch Insider vor oder während des Trainings kann versteckte Logik einbetten, die auch nach dem Retraining bestehen bleibt.

- **Übermäßige Datenverarbeitung**: Schwache Datenaufbewahrungs- und Governance-Kontrollen führen dazu, dass Systeme mehr persönliche Daten speichern oder verarbeiten, als notwendig, was die Exposition und das Compliance-Risiko erhöht.

- **Modell-Exfiltration**: Angreifer stehlen Modell-Dateien/Gewichte, was zu einem Verlust von geistigem Eigentum führt und Nachahmungsdienste oder Folgetransaktionen ermöglicht.

- **Manipulation der Modellbereitstellung**: Gegner ändern Modellartefakte oder Bereitstellungsinfrastruktur, sodass das laufende Modell von der geprüften Version abweicht, was das Verhalten potenziell ändert.

- **Verweigerung des ML-Dienstes**: Überflutung von APIs oder das Senden von "Schwamm"-Eingaben kann Rechen-/Energieressourcen erschöpfen und das Modell offline nehmen, was klassischen DoS-Angriffen ähnelt.

- **Modell-Rückentwicklung**: Durch das Ernten großer Mengen von Eingabe-Ausgabe-Paaren können Angreifer das Modell klonen oder destillieren, was Nachahmungsprodukte und angepasste adversariale Angriffe anheizt.

- **Unsichere integrierte Komponente**: Verwundbare Plugins, Agenten oder Upstream-Dienste ermöglichen es Angreifern, Code einzuschleusen oder Berechtigungen innerhalb der AI-Pipeline zu eskalieren.

- **Prompt-Injektion**: Das Erstellen von Eingabeaufforderungen (direkt oder indirekt), um Anweisungen zu schmuggeln, die die Systemabsicht überschreiben, sodass das Modell unbeabsichtigte Befehle ausführt.

- **Modell-Umgehung**: Sorgfältig gestaltete Eingaben bringen das Modell dazu, falsch zu klassifizieren, zu halluzinieren oder unerlaubte Inhalte auszugeben, was Sicherheit und Vertrauen untergräbt.

- **Offenlegung sensibler Daten**: Das Modell gibt private oder vertrauliche Informationen aus seinen Trainingsdaten oder dem Benutzerkontext preis, was gegen Datenschutz und Vorschriften verstößt.

- **Inferenz sensibler Daten**: Das Modell schlussfolgert persönliche Attribute, die niemals bereitgestellt wurden, und schafft neue Datenschutzschäden durch Inferenz.

- **Unsichere Modellausgabe**: Unsaniertes Antworten übermitteln schädlichen Code, Fehlinformationen oder unangemessene Inhalte an Benutzer oder nachgelagerte Systeme.

- **Rogue-Aktionen**: Autonom integrierte Agenten führen unbeabsichtigte reale Operationen (Dateischreibvorgänge, API-Aufrufe, Käufe usw.) ohne angemessene Benutzeraufsicht aus.

## Mitre AI ATLAS Matrix

Die [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) bietet einen umfassenden Rahmen zum Verständnis und zur Minderung von Risiken, die mit AI-Systemen verbunden sind. Sie kategorisiert verschiedene Angriffstechniken und Taktiken, die Gegner gegen AI-Modelle verwenden können, und auch, wie AI-Systeme verwendet werden können, um verschiedene Angriffe durchzuführen.


{{#include ../banners/hacktricks-training.md}}
