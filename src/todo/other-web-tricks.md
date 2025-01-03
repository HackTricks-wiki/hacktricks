# Andere Web-Tricks

{{#include ../banners/hacktricks-training.md}}

### Host-Header

Mehrmals vertraut das Backend dem **Host-Header**, um einige Aktionen durchzuführen. Zum Beispiel könnte es seinen Wert als **Domain für das Senden eines Passwort-Reset** verwenden. Wenn Sie also eine E-Mail mit einem Link zum Zurücksetzen Ihres Passworts erhalten, ist die verwendete Domain die, die Sie im Host-Header eingegeben haben. Dann können Sie das Passwort-Reset anderer Benutzer anfordern und die Domain auf eine von Ihnen kontrollierte ändern, um deren Passwort-Reset-Codes zu stehlen. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

> [!WARNING]
> Beachten Sie, dass es möglich ist, dass Sie nicht einmal warten müssen, bis der Benutzer auf den Link zum Zurücksetzen des Passworts klickt, um das Token zu erhalten, da möglicherweise sogar **Spam-Filter oder andere Zwischengeräte/Bots darauf klicken, um es zu analysieren**.

### Sitzungs-Boolean

Manchmal, wenn Sie eine Überprüfung korrekt abschließen, wird das Backend **einfach ein Boolean mit dem Wert "True" zu einem Sicherheitsattribut Ihrer Sitzung hinzufügen**. Dann wird ein anderer Endpunkt wissen, ob Sie diese Überprüfung erfolgreich bestanden haben.\
Wenn Sie jedoch **die Überprüfung bestehen** und Ihre Sitzung diesen "True"-Wert im Sicherheitsattribut erhält, können Sie versuchen, **auf andere Ressourcen zuzugreifen**, die **von demselben Attribut abhängen**, auf die Sie **keine Berechtigung** haben sollten. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Registrierungsfunktion

Versuchen Sie, sich als bereits existierender Benutzer zu registrieren. Versuchen Sie auch, äquivalente Zeichen (Punkte, viele Leerzeichen und Unicode) zu verwenden.

### E-Mail-Übernahme

Registrieren Sie eine E-Mail, ändern Sie die E-Mail, bevor Sie sie bestätigen, und wenn die neue Bestätigungs-E-Mail an die zuerst registrierte E-Mail gesendet wird, können Sie jede E-Mail übernehmen. Oder wenn Sie die zweite E-Mail aktivieren können, die die erste bestätigt, können Sie auch jedes Konto übernehmen.

### Zugriff auf den internen Servicedesk von Unternehmen, die Atlassian verwenden

{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### TRACE-Methode

Entwickler könnten vergessen, verschiedene Debugging-Optionen in der Produktionsumgebung zu deaktivieren. Zum Beispiel ist die HTTP `TRACE`-Methode für Diagnosezwecke gedacht. Wenn sie aktiviert ist, wird der Webserver auf Anfragen, die die `TRACE`-Methode verwenden, mit der genauen Anfrage, die empfangen wurde, in der Antwort antworten. Dieses Verhalten ist oft harmlos, führt aber gelegentlich zu Informationslecks, wie z.B. den Namen interner Authentifizierungsheader, die von Reverse-Proxys an Anfragen angehängt werden können.![Image for post](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

{{#include ../banners/hacktricks-training.md}}
