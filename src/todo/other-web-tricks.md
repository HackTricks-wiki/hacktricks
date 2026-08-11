# Andere Web-Tricks

{{#include ../banners/hacktricks-training.md}}

## Host header

Backends vertrauen beim Erstellen absoluter Links manchmal dem HTTP-Feld `Host`. Wenn eine E-Mail zum Zurücksetzen des Passworts einen vom Angreifer vorgegebenen Host verwendet, kann das Anfordern einer Zurücksetzung für ein Opfer einen tokenhaltigen Link über eine vom Angreifer kontrollierte Domain senden. Teste außerdem Felder für weitergeleitete Hosts, den Umgang mit doppelten `Host`-Headern und absolute Request-Ziele an jedem Proxy-Hop.<sup>[[1]](#references)</sup>

> [!WARNING]
> Ein Klick des Benutzers ist möglicherweise nicht erforderlich: **E-Mail-Sicherheits-Scanner, Vorschau-Dienste oder andere Vermittler können den vom Angreifer kontrollierten Link automatisch anfordern** und dadurch das Zurücksetzungstoken offenlegen.

## Session booleans

Einige Anwendungen speichern eine abgeschlossene Verifizierung als Boolean in der Session und lassen anschließend einen anderen Endpunkt von diesem Flag abhängig sein. Nachdem du die Prüfung für eine Ressource ordnungsgemäß bestanden hast, teste, ob dasselbe Flag fälschlicherweise einen anderen Benutzer, ein anderes Objekt oder einen anderen Workflow autorisiert. Dies ist ein Second-Order-Autorisierungs-/State-Reuse-Fehler und nicht lediglich ein IDOR.<sup>[[2]](#references)</sup>

## Registrierungsfunktionalität

Versuche, dich als bereits existierender Benutzer zu registrieren. Versuche es außerdem mit gleichwertigen Zeichen (Punkten, vielen Leerzeichen und Unicode).

## Verwirrung beim Status der E-Mail-Änderung

Registriere eine E-Mail-Adresse und ändere sie, bevor du sie bestätigst. Prüfe, ob die Bestätigung für die neue Adresse an die alte Adresse gesendet wird oder ob die Bestätigung des alten Tokens die neue Adresse aktiviert. Bestätigungstokens müssen an das exakt passende Konto, die ausstehende Adresse, den Zweck und den aktuellen Status gebunden sein.

## Exponierte Atlassian-Service-Desks


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

## TRACE-Methode

Die HTTP-`TRACE`-Methode fordert für Diagnosezwecke eine Rückgabe der empfangenen Anfrage an. RFC 9110 verlangt von Empfängern, dass sie sensible Felder wie Zugangsdaten und Cookies aus dem reflektierten Inhalt auslassen. Unsichere Implementierungen oder von Vermittlern hinzugefügte Header können jedoch weiterhin interne Änderungen an der Anfrage offenlegen. Browser verhindern durch Skripte erzeugte `TRACE`-Anfragen, daher ist der historische Cross-Site-Tracing-Angriff ebenfalls von einer separaten Möglichkeit abhängig, geschützte Felder einzuschleusen.<sup>[[3]](#references)</sup>![Bild mit einer TRACE-Antwort](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Bild für den Beitrag](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [Wie ich durch Host Header Injection jedes Benutzerkonto übernehmen konnte](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [Ein weniger bekannter Angriffsvektor: Second-Order-IDOR-Angriffe](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)
- [3] [RFC 9110, Abschnitt 9.3.8 — TRACE](https://www.rfc-editor.org/rfc/rfc9110.html#name-trace)
{{#include ../banners/hacktricks-training.md}}
