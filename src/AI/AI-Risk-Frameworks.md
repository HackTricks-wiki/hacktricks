# KI-Risiken

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Schwachstellen

Owasp hat die Top‑10‑Machine‑Learning‑Schwachstellen identifiziert, die AI‑Systeme betreffen können. Diese Schwachstellen können zu verschiedenen Sicherheitsproblemen führen, darunter Data Poisoning, Model Inversion und adversariale Angriffe. Das Verständnis dieser Schwachstellen ist entscheidend, um sichere AI‑Systeme zu bauen.

Für eine aktualisierte und detaillierte Liste der Top‑10 Machine‑Learning‑Schwachstellen siehe das Projekt [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Ein Angreifer fügt winzige, oft unsichtbare Änderungen an **eingehenden Daten** hinzu, sodass das Modell die falsche Entscheidung trifft.\
*Beispiel*: Ein paar Farbspritzer auf einem Stoppschild veranlassen ein selbstfahrendes Auto dazu, ein Tempolimitschild "zu sehen".

- **Data Poisoning Attack**: Der **Trainingssatz** wird vorsätzlich mit fehlerhaften Beispielen verseucht, wodurch das Modell schädliche Regeln lernt.\
*Beispiel*: Malware‑Binaries werden in einem Antivirus‑Trainingskorpus als "benign" falsch etikettiert, sodass ähnliche Malware später durchrutscht.

- **Model Inversion Attack**: Durch Abfragen der Ausgaben baut ein Angreifer ein **Reverse‑Modell** auf, das sensible Merkmale der ursprünglichen Eingaben rekonstruiert.\
*Beispiel*: Ein MRT‑Bild eines Patienten aus den Vorhersagen eines Krebs‑Erkennungsmodells rekonstruieren.

- **Membership Inference Attack**: Der Angreifer prüft, ob ein **bestimmter Datensatz** im Training verwendet wurde, indem er Unterschiede in der Confidence erkennt.\
*Beispiel*: Bestätigen, dass eine Personstransaktion in den Trainingsdaten eines Betrugserkennungsmodells vorkommt.

- **Model Theft**: Wiederholte Abfragen erlauben einem Angreifer, Entscheidungsgrenzen zu lernen und **das Verhalten des Modells zu klonen** (und geistiges Eigentum).\
*Beispiel*: Genug Q&A‑Paare von einer ML‑as‑a‑Service API sammeln, um ein nahezu äquivalentes lokales Modell zu erstellen.

- **AI Supply‑Chain Attack**: Kompromittierung einer beliebigen Komponente (Daten, Bibliotheken, vortrainierte Gewichte, CI/CD) in der **ML‑Pipeline**, um nachgelagerte Modelle zu korrumpieren.\
*Beispiel*: Eine vergiftete Abhängigkeit in einem model‑hub installiert ein mit Backdoor versehenes Sentiment‑Analyse‑Modell in vielen Apps.

- **Transfer Learning Attack**: Bösartige Logik wird in ein **pre‑trained model** eingebettet und überlebt das Fine‑Tuning für die Aufgabe des Opfers.\
*Beispiel*: Ein Vision‑Backbone mit einem versteckten Trigger ändert trotz Anpassung für medizinische Bildgebung weiterhin Labels.

- **Model Skewing**: Subtil voreingenommene oder falsch gelabelte Daten **verschieben die Modell‑Ausgaben**, sodass sie die Agenda des Angreifers begünstigen.\
*Beispiel*: "Saubere" Spam‑E‑Mails als ham labeln, damit ein Spam‑Filter ähnliche zukünftige E‑Mails durchlässt.

- **Output Integrity Attack**: Der Angreifer **verändert Modell‑Vorhersagen auf dem Weg**, nicht das Modell selbst, und täuscht nachgelagerte Systeme.\
*Beispiel*: Ein Malware‑Classifier‑Verdikt von "malicious" auf "benign" umschreiben, bevor die Datei‑Quarantäne es sieht.

- **Model Poisoning** --- Direkte, gezielte Änderungen an den **Modellparametern** selbst, oft nachdem Schreibzugriff erlangt wurde, um das Verhalten zu verändern.\
*Beispiel*: Gewichte in einem Produktions‑Betrugserkennungsmodell so anpassen, dass Transaktionen bestimmter Karten immer genehmigt werden.


## Google SAIF Risks

Googles [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) beschreibt verschiedene Risiken, die mit AI‑Systemen verbunden sind:

- **Data Poisoning**: Böswillige Akteure verändern oder injizieren Trainings-/Tuning‑Daten, um die Genauigkeit zu verschlechtern, Backdoors einzupflanzen oder Ergebnisse zu verzerren und so die Modellintegrität über den gesamten Datenlebenszyklus zu untergraben.

- **Unauthorized Training Data**: Das Einlesen von urheberrechtlich geschützten, sensiblen oder nicht genehmigten Datensätzen schafft rechtliche, ethische und Performance‑Risiken, weil das Modell von Daten lernt, die nie verwendet werden durften.

- **Model Source Tampering**: Supply‑Chain‑ oder Insider‑Manipulation von Modellcode, Abhängigkeiten oder Gewichten vor oder während des Trainings kann versteckte Logik einbetten, die auch nach Retraining bestehen bleibt.

- **Excessive Data Handling**: Schwache Daten‑Aufbewahrungs‑ und Governance‑Kontrollen führen dazu, dass Systeme mehr personenbezogene Daten speichern oder verarbeiten als nötig, was die Exponierung und Compliance‑Risiken erhöht.

- **Model Exfiltration**: Angreifer stehlen Modelfiles/Gewichte, was zum Verlust geistigen Eigentums führt und Nachahmungsdienste oder Folgeangriffe ermöglicht.

- **Model Deployment Tampering**: Gegner verändern Modellartefakte oder Serving‑Infrastruktur, sodass das laufende Modell von der geprüften Version abweicht und eventuell anderes Verhalten zeigt.

- **Denial of ML Service**: APIs überfluten oder "sponge" Inputs senden kann Compute/Energie erschöpfen und das Modell offline nehmen, analog klassischen DoS‑Angriffen.

- **Model Reverse Engineering**: Durch das Sammeln großer Mengen von Input‑Output‑Paaren können Angreifer das Modell klonen oder distillieren, was Nachahmungsprodukte und maßgeschneiderte adversariale Angriffe begünstigt.

- **Insecure Integrated Component**: Verwundbare Plugins, Agents oder Upstream‑Services erlauben Angreifern, Code einzuschleusen oder Privilegien innerhalb der AI‑Pipeline zu eskalieren.

- **Prompt Injection**: Prompts (direkt oder indirekt) so gestalten, dass Anweisungen eingeschleust werden, die die System‑Intention außer Kraft setzen und das Modell unerwünschte Befehle ausführen lassen.

- **Model Evasion**: Sorgfältig gestaltete Eingaben bringen das Modell dazu, falsch zu klassifizieren, zu halluzinieren oder unerlaubte Inhalte auszugeben und untergraben so Sicherheit und Vertrauen.

- **Sensitive Data Disclosure**: Das Modell gibt private oder vertrauliche Informationen aus seinen Trainingsdaten oder dem Benutzerkontext preis, was Datenschutz und Regulierung verletzt.

- **Inferred Sensitive Data**: Das Modell leitet persönliche Attribute ab, die nie bereitgestellt wurden, und schafft so neue Datenschutzschäden durch Inferenz.

- **Insecure Model Output**: Ungefilterte Antworten geben schädlichen Code, Fehlinformationen oder unangemessene Inhalte an Benutzer oder nachgelagerte Systeme weiter.

- **Rogue Actions**: Autonom integrierte Agents führen unbeabsichtigte reale Aktionen aus (Dateischreiben, API‑Aufrufe, Käufe etc.) ohne ausreichende Nutzeraufsicht.

## Mitre AI ATLAS Matrix

Die [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) bietet einen umfassenden Rahmen, um Risiken im Zusammenhang mit AI‑Systemen zu verstehen und zu mindern. Sie kategorisiert verschiedene Angriffs‑Techniken und Taktiken, die Gegner gegen AI‑Modelle einsetzen können, sowie wie man AI‑Systeme für unterschiedliche Angriffe nutzen kann.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Angreifer stehlen aktive Session‑Tokens oder Cloud‑API‑Credentials und rufen bezahlte, cloud‑gehostete LLMs ohne Autorisierung auf. Zugriff wird oft über Reverse‑Proxies weiterverkauft, die das Konto des Opfers "vorneweg" benutzen, z. B. oai‑reverse‑proxy‑Deployments. Konsequenzen sind finanzielle Verluste, Missbrauch von Modellen außerhalb der Richtlinien und Zuordnungen zum Opfer‑Tenant.

TTPs:
- Harvest tokens from infected developer machines or browsers; steal CI/CD secrets; buy leaked cookies.
- Stand up a reverse proxy that forwards requests to the genuine provider, hiding the upstream key and multiplexing many customers.
- Abuse direct base‑model endpoints to bypass enterprise guardrails and rate limits.

Mitigations:
- Bind tokens to device fingerprint, IP ranges, and client attestation; enforce short expirations and refresh with MFA.
- Scope keys minimally (no tool access, read‑only where applicable); rotate on anomaly.
- Terminate all traffic server‑side behind a policy gateway that enforces safety filters, per‑route quotas, and tenant isolation.
- Monitor for unusual usage patterns (sudden spend spikes, atypical regions, UA strings) and auto‑revoke suspicious sessions.
- Prefer mTLS or signed JWTs issued by your IdP over long‑lived static API keys.

## References
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)

{{#include ../banners/hacktricks-training.md}}
