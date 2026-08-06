# Andere Web-Tricks

{{#include ../banners/hacktricks-training.md}}

### Host header

Mehrmals vertraut das **Back-End** auf den **Host header**, um bestimmte Aktionen auszuführen. Zum Beispiel könnte es dessen Wert als **Domain zum Senden eines Passwort-Resets** verwenden. Wenn du also eine E-Mail mit einem Link zum Zurücksetzen deines Passworts erhältst, wird die verwendete Domain aus dem Wert übernommen, den du im Host header angegeben hast. Anschließend kannst du den Passwort-Reset anderer Benutzer anfordern und die Domain in eine von dir kontrollierte Domain ändern, um deren Passwort-Reset-Codes zu stehlen. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).<sup>[[1]](#references)</sup>

> [!WARNING]
> Beachte, dass du möglicherweise nicht einmal warten musst, bis der Benutzer auf den Link zum Zurücksetzen des Passworts klickt, um das Token zu erhalten, da möglicherweise sogar **Spamfilter oder andere zwischengeschaltete Geräte/Bots darauf klicken, um ihn zu analysieren**.

### Session booleans

Manchmal fügt das Back-End einfach einen Boolean mit dem Wert `"True"` zu einem Sicherheitsattribut deiner Session hinzu, wenn du eine Überprüfung erfolgreich abschließt. Ein anderer Endpoint kann dann feststellen, ob du diese Prüfung erfolgreich bestanden hast.\
Wenn du jedoch **die Prüfung bestehst** und deiner Session dieser Wert `"True"` im Sicherheitsattribut zugewiesen wird, kannst du versuchen, auf **andere Ressourcen** zuzugreifen, die von demselben Attribut **abhängen**, auf die du aber **keine Berechtigungen** haben solltest. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).<sup>[[2]](#references)</sup>

### Register functionality

Versuche, dich als bereits existierender Benutzer zu registrieren. Versuche auch, äquivalente Zeichen zu verwenden (Punkte, viele Leerzeichen und Unicode).

### Takeover emails

Registriere eine E-Mail-Adresse und ändere sie vor der Bestätigung. Wenn die neue Bestätigungs-E-Mail an die zuerst registrierte E-Mail-Adresse gesendet wird, kannst du jede E-Mail-Adresse übernehmen. Oder wenn du die zweite E-Mail-Adresse durch Bestätigung der ersten aktivieren kannst, kannst du ebenfalls jedes Konto übernehmen.

### Internen Servicedesk von Unternehmen mit Atlassian aufrufen


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### TRACE method

Entwickler vergessen möglicherweise, verschiedene Debugging-Optionen in der Produktionsumgebung zu deaktivieren. Die HTTP-`TRACE`-Methode wurde beispielsweise für Diagnosezwecke entwickelt. Wenn sie aktiviert ist, antwortet der Webserver auf Anfragen mit der `TRACE`-Methode, indem er in der Antwort die exakt empfangene Anfrage wiedergibt. Dieses Verhalten ist oft harmlos, führt aber gelegentlich zur Offenlegung von Informationen, beispielsweise des Namens interner Authentifizierungs-Header, die von Reverse Proxies an Anfragen angehängt werden.![Bild für Beitrag](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Bild für Beitrag](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [How I was able to take over any user's account with Host Header Injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [A less known attack vector: Second Order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)

{{#include ../banners/hacktricks-training.md}}
