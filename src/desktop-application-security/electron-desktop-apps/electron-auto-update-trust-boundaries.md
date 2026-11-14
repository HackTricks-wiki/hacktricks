# Electron-Auto-Update-Vertrauensgrenzen

{{#include ../../banners/hacktricks-training.md}}

## Angriffsfläche von Electron-Auto-Updates

Behandle einen Updater als Remote-Code-Execution-Grenze: Er ruft ausführbare Inhalte ab, entscheidet, ob diese Inhalte neuer und vertrauenswürdig sind, legt sie lokal bereit und übergibt sie einem Installer. Überprüfe den vollständigen Vertrauensgraphen – Release-Index, Metadaten pro Version, Artefakt, detached signatures, eingebetteter Verifizierungsschlüssel, Cache, temporärer Pfad und Installer – und nicht nur, ob die endgültige `.app` signiert ist.<sup>[[1]](#references)[[2]](#references)</sup>

### Besonders relevante Tests

- **Rollback/Replay:** Spiele ein zuvor gültiges Manifest und das dazugehörige, weiterhin signierte Artefakt erneut ein. Eine Signatur authentifiziert ihre Eingabe, bietet aber keine Aktualitätsgarantie; der Client muss Versionen unterhalb einer persistenten monotonen Untergrenze ablehnen, sofern eine authentifizierte Wiederherstellungsrichtlinie den Rollback nicht ausdrücklich erlaubt.<sup>[[2]](#references)</sup>
- **Metadaten-/Artefakt-Ersetzung:** Ändere unabhängig voneinander die Version, URL, den erwarteten Hash, das Artefakt und die detached signature. Versuche außerdem, ein gültiges Artefakt-Signatur-Paar aus einem Release mit Metadaten eines anderen Releases zu kombinieren. Sind die Release-Metadaten nicht signiert, verhindern weder TLS noch eine signierte endgültige ausführbare Datei, dass ein kompromittierter Origin/CDN die Auswahllogik ändert.<sup>[[1]](#references)[[2]](#references)</sup>
- **Verwechslung signierter Channels:** Stelle einen legitim signierten Alpha-, Beta-, Development- oder Debug-Build über den Production-Feed bereit. Werden Schlüssel und Richtlinie für mehrere Umgebungen wiederverwendet, kann das Artefakt eine reine Signer-Prüfung bestehen; die Production-Identität bzw. der Channel muss Teil der authentifizierten Richtlinie sein oder eine separate Trust Root verwenden.<sup>[[2]](#references)</sup>
- **TOCTOU bei temporären Dateien:** Ermittle, ob die Verifizierung einen Pfad öffnet und die Installation diesen Pfad später erneut öffnet. Kann ein lokaler Angreifer das bereitgestellte Objekt zwischen diesen Vorgängen umbenennen, ersetzen oder umleiten, konsumiert der Installer möglicherweise Bytes, die nie verifiziert wurden. Ein Staging-Verzeichnis mit Modus `0700` schränkt den Zugriff ein, macht die beiden Vorgänge jedoch nicht atomar.<sup>[[2]](#references)</sup>

Statische Analyse und Laufzeit-Triage können diese Grenzen schnell aufdecken.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
npx asar extract /path/to/app.asar /tmp/app-src
rg -n 'autoUpdater|electron-updater|setFeedURL|latest\.yml|allowInsecureTLS|downgrade' /tmp/app-src
rg -n 'sha(256|512)|ed25519|verify|signature|version|mkdtemp|chmod|rename' /tmp/app-src
sudo fs_usage -w -f filesystem "$PID" | rg -i 'update|latest|\.ya?ml|\.zip|\.dmg|tmp'
```

Während eines autorisierten Tests den Update-Check abfangen, jede Antwort archivieren und jeweils nur ein Feld ändern. Anschließend Eigentümer und Berechtigungen des Staging-Verzeichnisses prüfen und die Dateizugriffe vom Download bis zur Installation nachverfolgen. Unter macOS mit [Tests der Vertrauensgrenze des Installers](../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/macos-installers-abuse.md) fortfahren, wenn der Ablauf einen privilegierten Helfer erreicht, und [Schwachstellen bei der Codesignierung](../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing-weaknesses-and-sandbox-escapes.md) prüfen, statt „signiert“ als vollständige Identitätsprüfung zu betrachten.<sup>[[2]](#references)</sup>

### Erwartete Bindung und Richtlinie

Ein belastbares Design authentifiziert sowohl Auswahlmetadaten als auch die Artefakt-Bytes. Das SafeUpdater-Referenzdesign demonstriert einen eingebetteten öffentlichen Ed25519-Schlüssel, signierte Manifeste und Artefakte, eine signierte Nachricht, die aus `SHA-256(file)` und der Version abgeleitet wird, sowie einen SHA-512-Artefakt-Hash, der in signierten Metadaten gespeichert ist; es handelt sich ausdrücklich um eine Forschungsreferenz und nicht um ein produktionsreifes Paket.<sup>[[1]](#references)[[2]](#references)</sup>

Prüfen, ob das Zielsystem zusätzlich die folgenden Eigenschaften aufweist.<sup>[[1]](#references)[[2]](#references)</sup>

- verwendet eine eindeutige signierte Darstellung, die den Artefakt-Hash an die kanonische Version und Release-Umgebung bindet;
- deaktiviert Downgrades standardmäßig und erzwingt eine Mindestversion für autorisierte Rollbacks;
- trennt Produktion und Nichtproduktion durch unterschiedliche Schlüssel/Kanäle oder authentifizierte Release-Richtliniendaten; und
- installiert die bereits verifizierte geöffnete Datei (oder ein gleichwertiges unveränderliches Handle/Objekt), statt denselben Pfad erneut aufzulösen.

## References

- [1] [Doyensec ElectronSafeUpdater-Referenzimplementierung](https://github.com/doyensec/ElectronSafeUpdater)
- [2] [Electron SafeUpdater: Entwicklung eines sicheren Electron-Auto-Update-Mechanismus](https://blog.doyensec.com/2026/02/16/electron-safe-updater.html)
{{#include ../../banners/hacktricks-training.md}}
