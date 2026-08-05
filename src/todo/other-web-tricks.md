# Andere Web-Tricks

{{#include ../banners/hacktricks-training.md}}

### Host header

Mehrmals vertraut das Back-End auf den **Host header**, um bestimmte Aktionen auszuführen. Beispielsweise könnte es dessen Wert als **Domain zum Senden eines Passwort-Resets** verwenden. Wenn du also eine E-Mail mit einem Link zum Zurücksetzen deines Passworts erhältst, wird die verwendete Domain aus dem Wert übernommen, den du im Host header angegeben hast. Anschließend kannst du den Passwort-Reset anderer Benutzer anfordern und die Domain in eine von dir kontrollierte ändern, um deren Passwort-Reset-Codes zu stehlen. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).<sup>[[1]](#references)</sup>

> [!WARNING]
> Beachte, dass du möglicherweise nicht einmal warten musst, bis der Benutzer auf den Link zum Zurücksetzen des Passworts klickt, um den Token zu erhalten, da möglicherweise sogar **Spamfilter oder andere zwischengeschaltete Geräte/Bots darauf klicken, um ihn zu analysieren**.

### Session booleans

Manchmal fügt das Back-End, wenn du eine Überprüfung erfolgreich abschließt, **einfach einen Boolean mit dem Wert "True" zu einem Sicherheitsattribut deiner Session hinzu**. Anschließend weiß ein anderer Endpunkt, ob du diese Prüfung erfolgreich bestanden hast.\
Wenn du jedoch **die Prüfung bestehst** und deiner Session dieser Wert "True" im Sicherheitsattribut zugewiesen wird, kannst du versuchen, auf **andere Ressourcen zuzugreifen**, die **von demselben Attribut abhängen**, auf die du jedoch **keine Berechtigung haben solltest**. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).<sup>[[2]](#references)</sup>

### Registrierungsfunktion

Versuche, dich als bereits vorhandener Benutzer zu registrieren. Versuche auch, gleichwertige Zeichen zu verwenden (Punkte, viele Leerzeichen und Unicode).

### E-Mail-Übernahme

Registriere eine E-Mail-Adresse und ändere sie vor der Bestätigung. Wenn die neue Bestätigungs-E-Mail an die zuerst registrierte E-Mail-Adresse gesendet wird, kannst du jede E-Mail-Adresse übernehmen. Wenn du die zweite E-Mail-Adresse durch Bestätigung der ersten aktivieren kannst, kannst du ebenfalls jedes Konto übernehmen.

### Zugriff auf den internen Servicedesk von Unternehmen über Atlassian


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### TRACE method

Entwickler vergessen möglicherweise, verschiedene Debugging-Optionen in der Produktionsumgebung zu deaktivieren. Beispielsweise ist die HTTP-`TRACE`-Methode für Diagnosezwecke vorgesehen. Wenn sie aktiviert ist, antwortet der Webserver auf Anfragen mit der `TRACE`-Methode, indem er in der Antwort exakt die empfangene Anfrage wiedergibt. Dieses Verhalten ist oft harmlos, führt gelegentlich jedoch zur Offenlegung von Informationen, etwa des Namens interner Authentifizierungs-Header, die von Reverse Proxies an Anfragen angehängt werden.![Bild für Beitrag](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Bild für Beitrag](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## Referenzen

- [1] [How I was able to take over any user's account with Host Header injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [A less known attack vector: Second order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)

{{#include ../banners/hacktricks-training.md}}
