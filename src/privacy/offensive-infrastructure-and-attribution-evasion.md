# Offensive Infrastruktur und Verschleierung der Zuordnung

{{#include ../banners/hacktricks-training.md}}

Ein Operator erhält selten durch einen einzelnen Proxy nennenswerte Anonymität. Reale Kampagnen bauen einen **Trennungsgraphen** auf: Der Operator erreicht einen Zugangsknoten, Transitknoten verbergen diesen vor dem Exit, Redirectors schützen das echte C2, und kurzlebige Namen verweisen auf den öffentlichen Rand.

Nutze den [Katalog anonymer Internetzugriffstechniken](anonymous-internet-access-techniques.md), um einen einheitlichen Überblick über Vor- und Nachteile, Bereitstellung und Erkennung der einzelnen Pfade zu erhalten. Diese Seite geht näher auf die Zusammensetzung adversärer Infrastruktur ein.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

Die letzte von einem Ziel erkannte Adresse ist daher ein Hinweis auf einen Pfad, aber kein Beweis dafür, wer die Tastatur bediente. MITRE ordnet die wichtigsten Komponenten den Techniken Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) und Web Service (T1102) zu.<sup>[[1]](#references)</sup>

## Infrastrukturklassen

| Klasse | Warum ein Akteur sie nutzt | Dauerhafte Spuren | Bester Ansatzpunkt für Defender |
|---|---|---|---|
| Gemieteter VPS/Cloud | Schnell, vorhersehbar, routbar, einfach neu aufzusetzen | Tenant-, Abrechnungs-, Konsolen-, Quell-Login- und Image-Verlauf | Konto-/Control-Plane-Ereignisse und wiederkehrender Server-Fingerprint |
| Kommerzielles VPN/Tor | Großer geteilter Egress-Pool; keine Serververwaltung | Einblick des Anbieters/Aufsicht und Ende-zu-Ende-Timing | Verhalten am Ziel, Endpoint-Evidenz und Flow-Korrelation |
| Residential/Mobile Proxy | Consumer-ASN und geografische Plausibilität | Broker-/Kundendaten; Proxyware- oder Verhalten infizierter Hosts | Unmögliche Reiseverläufe, Proxy-Protokolle und adressbezogene Rotation pro Sitzung |
| Kompromittierter Server/Router/IoT | Nutzt die Reputation und Gerichtsbarkeit des Opfers | Implantat, Verwaltungs-Flow und wiederkehrender vorgelagerter Controller | Gerätetelemetrie und ORB-Topologie, nicht eine einzelne Exit-IP |
| CDN/Redirector | Trennt den öffentlichen Edge vom C2-Backend | TLS-/HTTP-Grammatik, Zertifikat, Routing- und Cloud-Konto-Artefakte | Korrelation von Edge und Origin sowie Clusterbildung nach Anfrageform |
| Legitimer Web Service | Fügt sich in erlaubten GitHub-/Cloud-/Social-Traffic ein | API-Token, Tenant-/Objektkennungen und ungewöhnliche Prozessabstammung | Endpoint-Prozess plus Service-/API-Semantik |
| Physischer/Mobilfunk-/Satellitenpfad | Ändert den scheinbaren physischen Ursprung | Funk-, Mobilfunkanbieter-, Teilnehmer-, Geräte- und Standortdaten | Kombinierte Funk-/physische und Netzwerk-Evidenz |

## Operative Relay-Box-Netzwerke

Ein **ORB-Netzwerk** ist eine verwaltete Proxy-Flotte, die als Vermittlungsdienst eingesetzt wird. Mandiant unterteilt sie in bereitgestellte Netzwerke aus gemieteten Servern, nicht bereitgestellte Netzwerke aus kompromittierten Routern/IoT-Geräten und hybride Netzwerke. Eine ausgereifte Topologie hat vier logische Rollen:<sup>[[2]](#references)</sup>

1. **Administrationsserver (ACOS):** Verwaltet Bestand, Zugangsdaten, Zustand und Routing-Richtlinien.
2. **Zugriffs-/Relay-Node:** Authentifiziert Kunden oder Operatoren; sie ist der stabile Einstiegspunkt in ein wechselndes Mesh.
3. **Traversal-Nodes:** Ein oder mehrere gemietete oder kompromittierte Systeme leiten undurchsichtige Verbindungen weiter.
4. **Exit-/Staging-Node:** Präsentiert die endgültige Quelladresse gegenüber Zielen für Reconnaissance, Exploitation oder C2.

Das Mesh kann Exits nach Land, ASN, Latenz oder Verfügbarkeit auswählen und fehlerhafte Nodes austauschen. Mehrere Threat Groups können dasselbe Netzwerk mieten. Mandiant beobachtete, dass eine IPv4-Adresse bei manchen ORBs nur 31 Tage mit dem Netzwerk verbunden blieb. Daher empfiehlt es, das **Netzwerk als sich entwickelnde, akteursähnliche Entität** zu behandeln, statt eine veraltete IP-Liste zu blockieren.<sup>[[2]](#references)</sup>

### Was das ermöglicht – und was es leakt

- Das Ziel sieht einen Exit, der geografisch nahe und scheinbar einem Privathaushalt zugeordnet sein kann.
- Der Exit sieht das Ziel und den vorhergehenden Hop, aber nicht zwangsläufig den Operator.
- Der Zugriffsdienst sieht den Kunden und die Routenanfrage. Ein unabhängig verwaltetes Mesh kann den Kunden von den Exits trennen, erzeugt aber einen aussagekräftigen Datensatz bei einer Gegenpartei.
- Wiederkehrende Ports, Handshake-Reihenfolge, Server-Banner, Zertifikate, Verfügbarkeitsfenster und Controller-Beziehungen können die Flotte offenlegen, selbst wenn die IPs rotieren.
- Ein kompromittierter Router verfügt häufig über keine Endpoint-Telemetrie, aber sein ISP hat weiterhin Teilnehmer- und Flow-Daten; eine Beschlagnahmung legt Implantat-/Konfigurationsartefakte offen.

{% hint style="info" %}
Führe für eine autorisierte Übung die Topologie mit organisationsinternen VMs oder Routern nach und bewahre die Attributionszuordnung des Controllers auf. Rekrutiere keine offenen Proxys oder Geräte Dritter. Der [Lab-Leitfaden](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) erstellt dieselbe für Defender sichtbare Hop-Struktur, ohne einen Vermittler zum Opfer zu machen.
{% endhint %}

## Residential- und Mobile-Proxy-Netzwerke

Residential-Proxy-Dienste weisen Sitzungen Adressen von privaten Breitbandanschlüssen zu; Mobile Proxys nutzen für den Egress Carrier-NAT-Pools. Die Kapazität kann von ausdrücklich angemeldeten Geräten, in Verbraucher-Apps gebündeltem SDK/Proxyware, Resellern oder Malware stammen. Diese Ursprünge sind nicht gleichwertig: Fehlt die informierte Zustimmung, wird aus einem Datenschutzdienst kompromittierte Infrastruktur.

Rotationsmodi beeinflussen die Erkennung:

- **Rotation pro Anfrage** führt zu schnellen Diskontinuitäten bei IP, ASN und Geografie, während die Identität auf höheren Ebenen stabil bleibt;
- **Sticky Sessions** behalten einen Exit minuten- oder stundenlang bei und ähneln einem gewöhnlichen Teilnehmer;
- **Backconnect-Gateways** zeigen dem Kunden einen einzelnen Broker-Endpunkt und wählen Exits intern aus;
- **Mobile Pools** bündeln viele echte Teilnehmer hinter einer kleinen Anzahl von Carrier-NAT-Adressen, wodurch eine IP-Sperre kostspielig wird.

Defender sollten die IP mit authentifizierter Sitzung, TLS-/Client-Fingerprint, HTTP-Reihenfolge, Geräte-Cookie und Verhalten korrelieren. Ein angeblich lokaler Residential-Login, auf den ein Login aus einem anderen Land folgt, während alle Merkmale auf höheren Ebenen identisch bleiben, ist aussagekräftiger als die Reputation allein. Umgekehrt verursachen geteilte Adressen und Mobilfunk-Handoffs legitime Wechsel. Daher darf eine Residential-/Proxy-Klassifizierung niemals als abschließendes Urteil gelten.

### Proxyware-Control-Planes und Überschneidungen bei Resellern

Modelliere einen Residential-Pool nicht als flache Liste von Exits. Die Analyse des IPIDEA-Ökosystems legte eine wiederverwendbare **zweistufige Control-Plane** offen: Ein eingebettetes SDK meldet zunächst Geräte-/Registrierungsmetadaten an eine Tier-One-Domain und erhält Scheduling-Informationen sowie `connect`-/`proxy`-IP:Port-Paare der Tier Two. Der Node fragt den Tier-Two-Connect-Port regelmäßig nach einer codierten Aufgabe ab, öffnet eine zweite Verbindung zum zugehörigen Proxy-Port und leitet die bereitgestellten Bytes an das angeforderte Ziel weiter. Nominell unterschiedliche SDKs und Proxy-Marken hatten getrennte Discovery-Domains, liefen aber aufgrund gemeinsamer Eigentums- und Reseller-Beziehungen auf gemeinsam genutzter Tier-Two-Infrastruktur und überlappenden Exit-Pools zusammen.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Dies liefert dauerhaftere Hunting-Pivots als ein Block mit privaten IP-Adressen:<sup>[[13]](#references)</sup>

- ein unerwarteter Prozess eines Utility-, VPN-, Game- oder Embedded-Geräts sendet eine stabile Geräte-ID/Kundenschlüssel und erhält eine wechselnde Serverliste;
- der Endpunkt fragt eine direkte IP an einem ungewöhnlichen Port ab und verbindet sich dann unmittelbar vor dem Öffnen eines Socket zu einem neuen Ziel mit einem anderen Port derselben Adresse;
- mehrere scheinbare Marken nutzen dieselben Tier-Two-Adressen, dieselbe Protokoll-Grammatik, denselben SDK-Code oder überschneiden sich bei ihren Exit-Nodes;
- verschiedene Anwendungen, die unterschiedliche Tier-One-Domains kontaktieren, erhalten Adressen aus demselben Tier-Two-Pool.

Die Überschneidungen schränken auch die Attribution ein: Eine IP in einem beworbenen Pool eines Anbieters zu sehen, belegt nicht, welcher Reseller, Kunde oder Threat Actor sie zum betreffenden Zeitpunkt genutzt hat. Bewahre Flow-Zeitstempel, Prozessabstammung, Antwortinhalte von Tier One und Tier-Two-Task-IDs auf.<sup>[[13]](#references)</sup> Emuliere diese Hierarchie in einer autorisierten Übung nur mit Endpunkten im Besitz der Organisation; binde niemals Geräte von Verbrauchern oder Proxyware Dritter ein.

## Multi-Hop-Proxyketten

MITRE unterscheidet externe Proxys von **multi-hop proxies (T1090.003)**. Entscheidend ist nicht die Anzahl der Hops, sondern die Trennung von Wissen und Verwaltung.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

Wenn eine Partei A und B betreibt, können gemeinsame Logs oder das Timing von Datenflüssen den Circuit rekonstruieren. Werden nacheinander kommerzielle VPNs vom selben Endpunkt/Konto aus hinzugefügt, kann das die Latenz erhöhen, während gemeinsame Identitäts-, Zahlungs- und Timing-Hinweise bestehen bleiben. Tor verringert dieses Problem durch unabhängig ausgewählte Relays und ein gemeinsames Clientdesign. Ein interaktives Netzwerk mit niedriger Latenz kann jedoch keinen Schutz vor einem Beobachter garantieren, der beide Enden überwacht.

Häufige Fehler sind DNS- oder IPv6-Bypass, Anwendungen, die eigene Sockets öffnen, Management-Traffic, der Relays direkt erreicht, synchronisierte Aktivitäten, wiederverwendete SSH-Schlüssel und Anmeldungen bei identifizierenden Konten. Die richtige Überprüfung ist ein Ausfalltest: Stoppe jedes Relay der Reihe nach und stelle sicher, dass die Workload nicht auf einen unverschlüsselten Pfad zurückfallen kann.

### Tunnel-Kollaps und Leaks zum Upstream

Eine Relay-Architektur lässt sich oft am leichtesten zuordnen, wenn sie ausfällt. Unit 42 dokumentierte einen mehrstufigen Spionagepfad mit VPSs auf Opferseite, Relay-VPSs, Residential Proxies, Tor und weiteren Proxy-Diensten. Wenn ein Tunnel fehlte oder zusammenbrach, verband sich verborgene Upstream-Infrastruktur direkt mit Relay- und opferseitigen Systemen. Dieselbe Untersuchung nutzte außerdem ein X.509-Zertifikat, das kurzzeitig auf der Upstream-Infrastruktur offengelegt war, als Pivot zwischen den Ebenen.<sup>[[14]](#references)</sup>

Halte die **Datenebene** (`victim <-> exit`) von der **Steuerungsebene** (`operator/upstream -> relay administration`) getrennt. Bewahre Ingress- und Authentifizierungs-Logs auf jeder eigenen Ebene, den Verlauf von Zertifikaten und kurze fehlgeschlagene Verbindungen auf – nicht nur erfolgreiche C2-Sitzungen. Eine Quelle, die nur bei Relay-Ausfällen auftaucht oder mehrere opferseitige Nodes direkt verwaltet, ist ein stärkerer Kandidat für einen Upstream als ein gewöhnlicher Exit. Ihre ASN/Geolokalisierung bleibt jedoch eine Hypothese und ist kein Beweis für die Identität eines Operators.

In einem autorisierten Lab sollte die Workload bei Fehlern geschlossen bleiben. Für eine in einem Linux-Network-Namespace isolierte Workload muss die erste Route den Tunnel verwenden. Wird dieser entfernt, müssen sowohl die Anfrage als auch die Routenabfrage fehlschlagen, statt die physische Uplink-Verbindung zu verwenden:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

Wiederhole den Test für DNS und IPv6 sowie an jeder Relay-Grenze. Wenn eine Probe erfolgreich ist, halte die tatsächliche Schnittstelle/Quelladresse fest, bevor du das Policy Routing oder die Firewall reparierst; diese Beobachtung ist der Attribution-Leak, den ein Ermittler sehen würde.

## Redirector tiers and traffic shaping

Ein öffentlicher **redirector** nimmt Datenverkehr an, der einer operationsspezifischen Grammatik entspricht, und leitet ihn an einen geschützten Teamserver weiter. Alles andere kann abgewiesen oder mit unbedenklichen Inhalten beantwortet werden.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Mehrere Ebenen begrenzen die Sichtbarkeit: Das Verbrennen einer öffentlichen Domain muss den Teamserver nicht offenlegen. CDNs bieten Anycast-Kapazität und eine seriöse äußere Domain, doch das CDN-Konto und die Edge-Logs werden zu Attributionspunkten. TLS-Fingerprints, Zertifikatshistorien, charakteristische Pfade/Header-Reihenfolgen, Antwortgrößen, Redirect-Verhalten und Origin-Allowlisten können vermeintlich unabhängige Fronts miteinander verknüpfen.

Für die Erkennung sollten Reverse-Proxy-Felder vor der Normalisierung aufgezeichnet, SNI/Host/Authority verglichen, seltene Header-Kombinationen untersucht, Antwort-Bodies und TLS-Fingerprints gruppiert sowie Cloud-/CDN-Audit-Logs auf Konfigurationsüberschneidungen geprüft werden. Autorisierte Red Teams sollten keine reale Marke kopieren und keine Erfassung von Zugangsdaten hinter einem unbeteiligten Drittanbieter platzieren.

## Domain fronting und domainless fronting

Beim klassischen **domain fronting (T1090.004)** gibt die TLS-Verbindung in SNI eine zulässige Front-Domain an, während der verschlüsselte HTTP-`Host`- oder HTTP/2-`:authority`-Header eine andere Back-End-Domain anfordert. Ein kooperierendes CDN leitet anhand des inneren Werts weiter. Ein Netzwerkbeobachter ohne TLS-Entschlüsselung sieht die Front; das CDN sieht beide Werte und den Origin. Bei domainless-Varianten kann SNI leer sein, während ein anderes Routing-Feld das Ziel bestimmt.<sup>[[4]](#references)</sup>

Das ist keine magische Identitätstäuschung: Es funktioniert nur, wenn der Intermediär die Abweichung absichtlich oder versehentlich zulässt und weiß, wie er den inneren Namen weiterleiten soll. Große Anbieter haben kontoübergreifendes Fronting eingeschränkt. Encrypted ClientHello (ECH) verändert, was ein Beobachter auf dem Übertragungsweg sehen kann, löscht aber keine CDN-, Endpoint- oder Anwendungsdaten.

Erkennungspunkte sind unter anderem:

- Prozessabstammung auf dem Endpoint und ein für die Anwendung unerwartetes Ziel;
- Abweichungen zwischen SNI und HTTP-Authority, sofern TLS-Inspektion rechtmäßig und verfügbar ist;
- CDN-Logs, die zeigen, dass ein Tenant/eine Front an eine andere Authority/einen anderen Origin weiterleitet;
- ungewöhnlich lange oder periodische Sitzungen zu einem normalerweise interaktiven Dienst;
- stabile Größen und Taktungen verschlüsselter Datenströme über wechselnde Front-Domains hinweg.

Das sichere Lab simuliert die Routing-Abweichung auf einem eigenen Reverse Proxy; es missbraucht kein öffentliches CDN.

## Dynamische Auflösung: DDNS, DGA und fast flux

Dynamische Auflösung entkoppelt einen logischen Dienst von einer festen Infrastruktur:

- **DDNS:** Ein authentifizierter Client aktualisiert einen stabilen Namen, wenn sich seine Adresse ändert.
- **DGA:** Endpoint und Controller leiten aus einem Zeit-/Schlüssel-Seed mögliche Domainnamen ab; der Betreiber registriert eine kleine Auswahl davon.
- **Fast flux:** Ein Name liefert eine schnell wechselnde Gruppe kompromittierter/Proxy-Adressen zurück, oft mit niedrigen TTLs.
- **Double flux:** Sowohl Dienstadressen als auch Adressen autoritativer Nameserver wechseln, wodurch auch die Control-Ebene verborgen wird.

Fast flux ist ein adversariales Lastverteilungsmuster, nicht einfach „viele DNS-Antworten“. Stärkere Indizien ergeben sich aus niedrigen TTLs, vielen eindeutigen Adressen, großer ASN-/geografischer Streuung, kurzer Lebensdauer von Nodes, wiederholtem Anwendungsverhalten und verdächtiger Registrierungshistorie. CDNs weisen legitimerweise mehrere dieser Merkmale auf. MITRE empfiehlt, DNS-Verhalten mit dem Prozess und nachfolgenden Verbindungen zu korrelieren.<sup>[[5]](#references)</sup>

Ein DGA lässt sich anhand lexikalischer Entropie, Konsonanten-/Ziffernmustern, NXDOMAIN-Spitzen, synchron erstmals beobachteten Domains und Prozesskontext erkennen. Wortlisten-DGAs und generative Modelle umgehen einfache Entropieregeln. Dadurch werden flottenweite zeitliche Gruppierung und Endpoint-Abstammung wichtiger.

## Kompromittierte Domains und Domain Shadowing

Ein Akteur kann ein Registrar-/DNS-Konto kapern, eine verwaiste Subdomain übernehmen oder Records unter einer ansonsten seriösen Domain hinzufügen. **Domain Shadowing** erhält die legitime Apex-Domain, während eine große Anzahl vom Angreifer kontrollierter Subdomains auf wechselnde Delivery- oder C2-Hosts verweist. So werden Alter und Reputation genutzt, und eine domainsweite Sperrung lässt sich möglicherweise umgehen.<sup>[[6]](#references)</sup>

Verteidiger benötigen Audit-Logs von Registraren und autoritativen DNS-Servern, MFA, Registry-/Registrar-Locks, Warnungen zu neuen Delegierungen/API-Tokens/Nameservern, Certificate-Transparency-Monitoring und ein Inventar der in DNS referenzierten Cloud-Ressourcen. Die Auflösung und Zertifikatshistorie einer Subdomain sollte unabhängig von der Reputation der Apex-Domain untersucht werden.

## Webdienste und Dead-Drop-Resolver

Ein **Dead-Drop-Resolver (T1102.001)** speichert einen codierten Verweis auf das aktuelle C2 in einem legitimen Beitrag, Profil, Dokument, Repository, Cloud-Objekt oder Blockchain-Feld. Malware ruft das öffentliche Objekt ab, decodiert eine Domain/IP-Adresse und kontaktiert die nächste Stufe. Bidirektionale Varianten tauschen Befehle oder Dateien über Service-APIs aus.<sup>[[7]](#references)</sup>

Eine GitHub-spezifische Resolver-Variante verwendet die Issues Search API nur dann, wenn ein authentifizierter Repository-Kanal ausfällt. Der Client sucht nach Issues, die dem aktuellen Datum, Repository und Issue-Typ entsprechen, ruft die Comments-URL jedes Issues auf und extrahiert Chiffretext zwischen den Markierungen `<!--` und `-->`. Nach einer pro Host und Datum abgeleiteten Entschlüsselung ersetzen Felder wie `Owner`, `LicRepo` und `LicToken` den primären Repository-Eigentümer, den Pfad und das Token. So kann der Betreiber Zugangsdaten und Endpoints wechseln, ohne den Client auszutauschen; der Issue-Kommentar dient als Resolver, während die Repository-Dateien der Tasking-Kanal bleiben.<sup>[[15]](#references)</sup>

Das sorgt für Resilienz und verbirgt das Back-End-C2 vor einer statischen Binäranalyse. Zugleich entstehen stabile Objekt-, Tenant-, Repository-, API- und Zugriffsmuster-Identifikatoren. Verteidiger sollten folgende Daten zusammenführen:

1. den Prozess, der den Dienst kontaktiert hat;
2. den genauen API-Pfad/das Objekt und den Antwort-Hash;
3. Decodierungs- oder String-Verarbeitungsaktivitäten;
4. die kurz darauf erfolgte neue ausgehende Verbindung; und
5. dasselbe Verhalten an anderen Stellen der Flotte.

GitHub, Cloud Storage oder soziale Medien vollständig zu sperren, ist selten praktikabel. Dienstbewusste Egress-Richtlinien und Prozesskorrelation sind wirksamer als eine reine Domain-Sperrung.

## Personas, Konten und Beschaffungskompartimente

Die Anonymität der Infrastruktur scheitert, wenn eine Persona, Wiederherstellungs-E-Mail-Adresse, Telefonnummer, Zahlung, ein Browser oder eine Admin-IP Kompartimente miteinander verbindet. Staatsnahe Operationen haben Social-Media-Profile, E-Mail-Identitäten und Cloud-Konten lange vor ihrer Nutzung aufgebaut; ATT&CK führt dies als Establish Accounts (T1585), einschließlich Social-, E-Mail- und Cloud-Untertechniken.<sup>[[8]](#references)</sup>

Verteidiger und Ermittler erstellen einen Graphen aus:

- Erstellungszeitpunkt und erster Anmeldung, Spracheinstellung, Zeitzone und Arbeitszeiten;
- Wiederherstellungsdaten, MFA-Geräten, Ausweisdokumenten und Zahlungsmitteln;
- Browser-/TLS-Fingerprints und Verlauf der Quellnetzwerke;
- wiederverwendeten Avataren, Bildherkunft, Schreibstil und Wachstum des sozialen Graphen;
- gemeinsamen Domain-Registranten, Nameservern, Zertifikaten, Analytics-IDs oder Repository-Commits;
- Aktionen auf der Management-Ebene, die die öffentliche Relay-Architektur umgehen.

Bei einem autorisierten Red Team sollten synthetische Personas gegenüber der für die Übung verantwortlichen Stelle dokumentiert, organisationsinterne Wiederherstellungs-/Zahlungskanäle genutzt, echte unbeteiligte Personen nicht imitiert und eine geplante Stilllegung vorgesehen werden. Das SOC darf im Unklaren bleiben; die Operation darf nicht unverantwortlich werden.

## Neue zusammengesetzte Muster für die Bedrohungsmodellierung

Die folgenden Muster sind **von Verteidigern entwickelte Kombinationen** und keine Behauptung, dass ein namentlich genannter Akteur jedes konkrete Design eingesetzt hat. Sie kombinieren bereits beobachtete Primitive und eignen sich als Purple-Team-Hypothesen.

### Asymmetrisches One-Way-Tasking

Befehle kommen über eine öffentliche, Broadcast- oder Append-only-Quelle an, während Ergebnisse verzögert über einen unabhängigen Kanal abfließen. Beispiele für die Primitive sind One-Way-Kommunikation über Webdienste und Dead Drops. Die Trennung verhindert, dass ein einzelner Datenstrom bidirektional wirkt, und erschwert eine einfache Request-/Response-Korrelation.<sup>[[9]](#references)</sup>

**Erkennung:** Objektbezogene Lesevorgänge aufbewahren und anschließend Änderungen am Prozesszustand mit späteren ausgehenden Übertragungen über ein größeres Zeitfenster hinweg korrelieren. Nach seltenen Prozessen suchen, die dasselbe öffentliche Objekt lesen, auch wenn keine unmittelbare Antwort folgt.

### Promotion zu mehrstufigen Kanälen

Eine unauffällige erste Stufe führt eine Bestandsaufnahme durch und schaltet nur ausgewählte Systeme auf einen unabhängigen Zweitkanal um. Endpoint, Protokoll und Prozess der zweiten Stufe können keinerlei Infrastruktur mit der ersten gemeinsam haben. Dadurch wird die exponierte leistungsfähige Infrastruktur begrenzt; das Modell ist in ATT&CK ausdrücklich als T1104 erfasst.<sup>[[10]](#references)</sup>

**Erkennung:** `first network process -> downloaded/configured state -> new process or injection -> unrelated destination` verknüpfen; den Vorfall nicht nach dem Sperren der ersten Domain schließen.

### Relay-Übersetzung zwischen Protokollen

Verschiedene Hops übersetzen HTTPS, QUIC, WebSocket, DNS, SSH oder eine Message-Queue-API, statt Pakete transparent weiterzuleiten. Die Übersetzung beseitigt einen einzelnen durchgängigen Protokoll-Fingerprint, erzeugt aber Gateways mit charakteristischen Zeitmustern, Pufferung und semantischer Konvertierung. Protocol Tunneling (T1572) kann mit Proxys und Service-Impersonation kombiniert werden.<sup>[[11]](#references)</sup>

**Erkennung:** Nach Gateway-Hosts suchen, die ein Protokoll empfangen und ein anderes initiieren, wobei Bytes und Zeitverhalten eng gekoppelt sind; die Absicht des Endpoints mit dem tatsächlich übertragenen Protokoll vergleichen.

### Passive Aktivierung auf Edge-Geräten

Statt zu beaconen, überwacht ein Implantat den bereits bei einem Router/VPN eintreffenden Datenverkehr und wird nur durch einen Magic Value, ein Quellportmuster oder ein authentifiziertes Token aktiviert. Normaler Datenverkehr wird weiterhin an den echten Dienst weitergeleitet. ATT&CK bezeichnet dies als Traffic Signaling (T1205) und führt dokumentierte Beispiele für Netzwerkgeräte und APTs auf.<sup>[[12]](#references)</sup>

**Erkennung:** Firmware-/Dateiintegrität, Packet Capture während einer autorisierten Untersuchung, unerwartete Socket-Filter und abweichendes Dienstverhalten. Das Fehlen eines periodischen Beacons beweist nicht, dass ein Edge-Gerät sauber ist.

### Serverless- und kurzlebiger Origin-Wechsel

Eine Front behält eine stabile logische Identität bei, während kurzlebige Functions/Container einzelne Stufen in mehreren Regionen/Konten abwickeln. Das verkürzt die Lebensdauer von Daten auf Datenträgern und vermeidet feste Origin-IPs; Telemetriedaten zu Control-Plane-Erstellung, Image/Layer, Rolle, Secret, Request-ID und Abrechnung werden jedoch zum dauerhaften Graphen.

**Erkennung:** Cloud-Audit- und Invocation-Logs außerhalb der Workload aufbewahren; Deployment-Templates, Rollen, Environment-Keys und Front-to-Origin-Beziehungen gruppieren.

### Vielfalt der Privacy-Ebenen

Eine Operation kann bewusst auf eine einheitliche Kette verzichten: Ein Kanal nutzt beispielsweise ein gemietetes Relay, das Tasking ein öffentliches Objekt, ein Exit eine eigene Mobilfunkverbindung im Lab und die Administration ein separates Organisationsnetzwerk. Das verringert den Nutzen einer Kompromittierung eines einzelnen Anbieters, erhöht aber das Risiko, dass zeitliche Zusammenhänge zwischen Ebenen oder operative Fehler auffallen.

**Erkennung:** Kampagnen-Zeitachsen über Identity-, DNS-, SaaS-, Netzwerk- und Cloud-Sensoren hinweg erstellen. Nach synchronisierten Zustandsänderungen statt identischen Indikatoren suchen.

### Dezentrale Dead Drops oder Dead Drops in Transparenz-Logs

Ein Akteur kann einen kleinen verschlüsselten Verweis in einem dauerhaften öffentlichen Append-only-System, einem content-addressed Store oder einem Transparenz-ähnlichen Feed ablegen. Das öffentliche Objekt ist resilient, doch sein genauer Index/Content-Hash und das Polling-Verhalten des Clients werden zu stabilen Identifikatoren.

**Erkennung:** Vollständige API-/Objekt-Identifikatoren und Antwort-Hashes protokollieren; bei ungewöhnlichen Prozessen alarmieren, die unveränderliche Objekte abfragen und anschließend decodieren oder neue Verbindungen herstellen.

### Verzögerte Store-and-Forward-Operationen

Interaktives C2 erzeugt starke zeitliche Zusammenhänge. Ein Store-and-Forward-Design bündelt verschlüsselte Aufträge und gibt Ergebnisse Minuten oder Stunden später über eine andere Queue oder einen physischen Transfer zurück. Es verzichtet auf Reaktionsgeschwindigkeit, um den durchgängigen zeitlichen Zusammenhang abzuschwächen.

**Erkennung:** Korrelationsfenster verlängern, periodischen Queue-Zugriff modellieren und das Staging auf Endpoints untersuchen. Batching verlagert das Signal vom Paket-Timing auf geplantes Prozess-/Dateiverhalten; es beseitigt es nicht.

## Designprüfung: In Beobachtern denken

Füllen Sie diese Tabelle für jeden Pfad vor der Bereitstellung und nach der Datenerfassung aus:

| Ebene | Sieht die Quelle? | Sieht das Ziel? | Sieht den Inhalt? | Stabile Identifikatoren | Aufbewahrung/verantwortliche Rechtsinstanz |
|---|---:|---:|---:|---|---|
| lokales Netzwerk/Mobilfunkanbieter | | | | | |
| Entry-/Zugriffsdienst | | | | | |
| Traversal-Betreiber | | | | | |
| Exit/Redirector/CDN | | | | | |
| autoritatives DNS/Registrar | | | | | |
| Ziel | | | | | |
| Konto-/Zahlungsanbieter | | | | | |

Kann ein einzelner gewöhnlicher Anbieter jede Spalte ausfüllen, bietet die Architektur zwar Verschleierung gegenüber dem Ziel, aber keine robuste Trennung. Kann kein interner Verantwortlicher Aktivitäten einem Engagement zuordnen, ist die Architektur für professionelles Red Teaming ungeeignet.

## References

- [1] [MITRE ATT&CK — Infrastruktur beschaffen (T1583), Infrastruktur kompromittieren (T1584) und Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — China-nahe Spionageakteure nutzen ORB-Netzwerke](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Infrastruktur kompromittieren: Domains (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Webdienst: Dead-Drop-Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Konten einrichten (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Webdienst: One-Way-Kommunikation (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Mehrstufige Kanäle (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Zerschlagung des weltweit größten Residential-Proxy-Netzwerks](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Die Shadow-Kampagnen: Globale Spionage aufgedeckt](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Die Blinder-Tunnel-Kampagne zielt auf irakische Infrastruktur](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
