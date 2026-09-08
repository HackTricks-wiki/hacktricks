# Betriebssysteme für den Datenschutz

Datenschutzorientierte Betriebssysteme reduzieren Fehler bei Routing und Persistenz, aber keines kann identifizierbares Verhalten oder kompromittierte Hardware ausgleichen.

## Isolationsmodell auswählen

| System | Am besten geeignet für | Persistenz | Netzwerkdurchsetzung | Wichtigster Kompromiss |
|---|---|---|---|---|
| **Tor Browser auf einem gepflegten OS** | Gelegentliches anonymes Web-Browsing | Browserzustand normalerweise auf die Sitzung beschränkt | Nur Browser-Traffic | Andere Apps und der Host bleiben außerhalb von Tor |
| **Tails** | Portable, amnesische Sitzungen mit einem einzigen Zweck | Optionaler verschlüsselter Persistent Storage | Internet-Traffic wird durch Tor geleitet | Neustarts/umständlicher Workflow; Vertrauen in Firmware/Hardware |
| **Whonix** | Persistente Anwendungen, die erzwungenes Tor-Routing benötigen | Persistente VMs | Aufteilung in Gateway/Workstation | Host/Hypervisor und Vermischung von Identitäten bleiben relevant |
| **Qubes-Whonix** | Strikte Trennung von Compartments für fortgeschrittene Benutzer | Pro Qube | Dedizierte Netzwerk-Qubes und Whonix | Hardwareanforderungen und operative Komplexität |

## Tails

Tails startet unabhängig von Wechseldatenträgern, leitet Internet-Traffic durch Tor und ist darauf ausgelegt, möglichst wenige lokale Zustände zu hinterlassen. Die eigenen Warnungen betonen, dass es nicht vor kompromittiertem BIOS/Firmware/Hardware, identifizierenden Offenlegungen, Dateimetadaten oder einem mächtigen Beobachter schützen kann, der beide Enden korreliert.<sup>[[1]](#references)</sup>

### Tails-Workflow mit einem einzigen Zweck

1. Lade Tails von der offiziellen Website auf einem vertrauenswürdigen, aktualisierten Computer herunter und befolge den offiziellen Verifizierungs-/Installationsprozess.
2. Verwende ein unterstütztes USB-Laufwerk nur zum Booten von Tails; verwende es nicht zusätzlich als allgemeines Laufwerk für Dateiübertragungen.
3. Boote auf Hardware, die du physisch kontrollierst. Ein Live-OS kann keinen Hardware-Keylogger oder bösartige Firmware neutralisieren.
4. Lass Persistent Storage deaktiviert, sofern der Workflow es nicht wirklich benötigt. Falls aktiviert, speichere nur die erforderlichen Kategorien dauerhaft und verwende eine starke Passphrase.
5. Verbinde dich mit einem rechtmäßigen Netzwerk. Falls ein Captive Portal unvermeidbar ist, verwende Tails' Unsafe Browser nur für das Portal, gib keine unnötigen Identitätsdaten preis, schließe ihn sofort und verbinde dich mit Tor, bevor du sensible Aktivitäten ausführst.<sup>[[2]](#references)</sup>
6. Konfiguriere eine Tor Bridge, wenn direkte Sichtbarkeit oder Blockierung von Tor relevant ist.
7. Führe **pro Sitzung eine kontextbezogene Identität/einen Zweck** aus. Tails empfiehlt, zwischen Aktivitäten, die nicht miteinander verknüpft werden sollen, neu zu starten.<sup>[[1]](#references)</sup>
8. Prüfe und bereinige Dateien vor der Veröffentlichung. Öffne heruntergeladene aktive Dokumente nicht in einer Anwendung, die den vorgesehenen Kontext umgehen könnte.
9. Führe beim Beenden ein vollständiges Herunterfahren durch und bewahre den USB-Datenträger physisch sicher auf.

## Whonix

Whonix trennt ein Tor-routing-fähiges **Gateway** von einer **Workstation**, deren Anwendungen die externe IP-Adresse nicht direkt erfahren können. Dies reduziert Fehler bei Proxy/DNS erheblich, aber der Host, der Hypervisor, das Verhalten und Dokumente können weiterhin die Identität offenlegen. Whonix warnt ausdrücklich davor, eine Workstation für mehrere Identitäten zu verwenden oder anonyme und nicht anonyme Aktivitäten zu kombinieren.<sup>[[3]](#references)</sup>

### Compartment-Workflow

1. Verifiziere das Whonix-Image und die Virtualisierungsplattform anhand offizieller Quellen.
2. Aktualisiere Host, Hypervisor, Gateway und Workstation vor der Verwendung.
3. Klone für jede Identität oder jedes Engagement eine frische Workstation; klone niemals eine VM, nachdem identitätsbezogener Zustand eingeführt wurde.
4. Halte persönliche Konten, freigegebene Host-Ordner, Zwischenablagesynchronisierung, USB-Geräte sowie Zeit-/Standortdaten aus der Workstation heraus.
5. Verwende Snapshots zur Wiederherstellung, nicht als Ersatz für Backups oder die Trennung von Identitäten.
6. Bestätige, dass die Workstation das Internet nicht erreichen kann, wenn das Gateway gestoppt wurde.
7. Verwende für besonders riskante Dateien eine Disposable VM/Qube und exportiere nur ein bereinigtes Ergebnis.

## Qubes OS und Qubes-Whonix

Qubes implementiert Sicherheit durch Compartmentalization mit Xen-basierten Qubes. Sein Design begrenzt, dass eine Kompromittierung in einer Domain automatisch andere erreicht, aber Anwendungen innerhalb desselben **Qube** sind nicht voneinander isoliert.<sup>[[4]](#references)</sup> Disposable Qubes stellen einen frischen Zustand für nicht vertrauenswürdige Websites, Dateien und Geräte bereit.<sup>[[5]](#references)</sup>

Ein praktisches Layout:
```text
vault-offline        keys, recovery codes; no network
personal             real-identity daily accounts
client-red-2026      engagement administration only
client-red-net       approved VPN/bastion routing
anon-research        Qubes-Whonix Workstation
anon-research-net    Whonix Gateway
disp-untrusted       links and document rendering
```
Regeln:

- Weise jedem qube genau eine Vertrauensstufe und einen Identitätszweck zu.
- Bewahre Geheimnisse in einem Offline-Vault-qube auf und verwende explizite qube-übergreifende Kopier-/Dateioperationen.
- Öffne nicht angeforderte Dateien und Links in Disposables.
- Leite nur die vorgesehenen qubes über Whonix oder einen dedizierten VPN-qube.
- Kennzeichne Fenster eindeutig und stoppe während sensibler Arbeiten nicht verwandte qubes.
- Gehe nicht davon aus, dass zwei qubes eine Korrelation verhindern, wenn sie Konten, Inhalte, Zeitpläne oder Zahlungen gemeinsam verwenden.

## Verifizierung und Wartung

- Verifiziere Installer-Signaturen/Checksummen gemäß den offiziellen Anweisungen.
- Patche zuerst Templates und starte anschließend abhängige qubes/VMs neu.
- Bestätige das Verhalten bei verweigerter Netzwerkverbindung sowie DNS, IPv6, Uhrzeit, Zwischenablage, gemeinsam genutzte Verzeichnisse und USB-Zuweisungen.
- Überprüfe Persistent Storage und VM-Snapshots auf alte identitätsbezogene Daten.
- Bewahre verschlüsselte Offline-Backups von Seeds/Keys auf und teste die Wiederherstellung in einer isolierten Umgebung.
- Baue ein Compartment nach einem vermuteten Compromise neu auf; das Ändern der Egress-IP ist unzureichend.

## References

- [1] [Tails — Warnungen: Tails ist sicher, aber keine Magie](https://tails.net/doc/about/warnings/index.en.html)
- [2] [Tails — Anmeldung bei einem Netzwerk über ein Captive Portal](https://tails.net/doc/anonymous_internet/unsafe_browser/index.en.html)
- [3] [Whonix — Einschränkungen von Whonix und Tor](https://www.whonix.org/wiki/Warning)
- [4] [Qubes OS — Sicherheitsdesignziele](https://doc.qubes-os.org/en/latest/developer/system/security-design-goals.html)
- [5] [Qubes OS — Verwendung von Disposables](https://doc.qubes-os.org/en/latest/user/how-to-guides/how-to-use-disposables.html)
