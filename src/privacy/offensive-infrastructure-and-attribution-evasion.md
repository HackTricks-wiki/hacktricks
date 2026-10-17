# Offensive Infrastruktur und Attribution-Evasion

{{#include ../banners/hacktricks-training.md}}

Ein Operator erlangt durch einen einzelnen Proxy nur selten echte Anonymität. Reale Kampagnen bauen einen **Separation Graph** auf: Der Operator erreicht einen Access Node, Traversal Nodes verbergen diesen vor dem Exit, Redirectors schützen das echte C2 und kurzlebige Namen verweisen auf den öffentlichen Edge.

Nutze den [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md), um für jeden Pfad eine einheitliche Übersicht zu Vor- und Nachteilen, Deployment und Detection zu erhalten. Diese Seite geht näher auf die Zusammensetzung adversärer Infrastruktur ein.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

Die letzte Adresse, die ein Ziel sieht, ist daher ein Hinweis auf einen Pfad, aber kein Beweis dafür, wer die Tastatur bedient hat. MITRE ordnet die Hauptkomponenten den Techniken Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) und Web Service (T1102) zu.<sup>[[1]](#references)</sup>

## Infrastrukturklassen

| Klasse | Warum ein Akteur sie nutzt | Dauerhafte Angriffsfläche | Bester Ansatzpunkt für Verteidiger |
|---|---|---|---|
| Gemieteter VPS/Cloud | Schnell, vorhersehbar, routbar und leicht neu aufzusetzen | Mandant, Abrechnung, Konsole, Quell-Login und Image-Verlauf | Konto-/Control-Plane-Ereignisse und wiederkehrender Server-Fingerprint |
| Kommerzielles VPN/Tor | Große gemeinsam genutzte Egress-Menge; keine Serveradministration | Einblick des Anbieters/Betreibers und Ende-zu-Ende-Timing | Verhalten am Ziel, Endpunktnachweise und Flow-Korrelation |
| Residential-/Mobile-Proxy | Consumer-ASN und geografische Plausibilität | Broker-/Kundendaten; Proxyware- oder Verhalten infizierter Hosts | Unmögliche Reisen, Proxy-Protokolle und Adresswechsel pro Sitzung |
| Kompromittierter Server/Router/IoT | Nutzt den Ruf und die Gerichtsbarkeit des Opfers | Implantat, Management-Flow und wiederkehrender vorgelagerter Controller | Geräte-Telemetrie und ORB-Topologie, nicht eine einzelne Exit-IP |
| CDN/Redirector | Trennt den öffentlichen Edge vom Back-End-C2 | TLS-/HTTP-Grammatik, Zertifikat, Routing- und Cloud-Konto-Artefakte | Korrelation zwischen Edge und Origin sowie Clustering nach Request-Mustern |
| Legitimierter Webdienst | Geht im erlaubten GitHub-/Cloud-/Social-Traffic unter | API-Token, Mandanten-/Objektkennungen und ungewöhnliche Prozessabfolge | Endpunktprozess plus Dienst-/API-Semantik |
| Physischer/Mobilfunk-/Satellitenpfad | Verändert den scheinbaren physischen Ursprung | Funk-, Anbieter-, Teilnehmer-, Geräte- und Standortdaten | Kombinierte Funk-/physische und Netzwerkbelege |

## Netzwerke mit operativen Relay-Boxen

Ein **ORB-Netzwerk** ist eine verwaltete Proxy-Flotte, die als Zwischendienst eingesetzt wird. Mandiant unterteilt sie in bereitgestellte Netzwerke aus gemieteten Servern, nicht bereitgestellte Netzwerke aus kompromittierten Routern/IoT-Geräten und hybride Netzwerke. Eine ausgereifte Topologie hat vier logische Rollen:<sup>[[2]](#references)</sup>

1. **Administrationsserver (ACOS):** Verwaltet Bestand, Zugangsdaten, Zustand und Routing-Richtlinien.
2. **Zugangs-/Relay-Knoten:** Authentifiziert Kunden oder Betreiber; er ist der stabile Einstiegspunkt in ein sich veränderndes Mesh.
3. **Traversal-Knoten:** Ein oder mehrere gemietete oder kompromittierte Systeme leiten undurchsichtige Verbindungen weiter.
4. **Exit-/Staging-Knoten:** Zeigt bei Aufklärung, Ausnutzung oder C2-Zielen die letzte Quelladresse an.

Das Mesh kann Exits nach Land, ASN, Latenz oder Verfügbarkeit auswählen und ausgefallene Knoten austauschen. Mehrere Bedrohungsgruppen können dasselbe Netzwerk mieten. Mandiant beobachtete, dass eine IPv4-Adresse bei einigen ORBs nur 31 Tage lang zugeordnet blieb. Daher empfiehlt es, das **Netzwerk als sich entwickelnde, akteurähnliche Entität** zu behandeln, statt eine veraltete IP-Liste zu blockieren.<sup>[[2]](#references)</sup>

### Was das ermöglicht – und was es leakt

- Das Ziel sieht einen Exit, der geografisch nahe und scheinbar privat wirkt.
- Der Exit sieht das Ziel und den vorherigen Hop, nicht unbedingt den Betreiber.
- Der Zugangsdienst sieht den Kunden und die Routenanfrage. Ein unabhängig verwaltetes Mesh kann den Kunden von den Exits getrennt halten, erzeugt aber aussagekräftige Daten beim Gegenüber.
- Wiederkehrende Ports, Handshake-Reihenfolgen, Server-Banner, Zertifikate, Verfügbarkeitsfenster und Controller-Beziehungen können die Flotte offenlegen, selbst wenn sich die IPs ändern.
- Bei einem kompromittierten Router fehlt häufig die Endpunkt-Telemetrie, aber der ISP verfügt weiterhin über Teilnehmer- und Flow-Daten; eine Beschlagnahmung legt Implantat-/Konfigurationsartefakte offen.

{% hint style="info" %}
Reproduziert für eine autorisierte Übung die Topologie mit organisationsinternen VMs oder Routern und bewahrt die Zuordnungskarte des Controllers auf. Bindet keine offenen Proxys oder Geräte Dritter ein. Der [Lab-Guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) bildet dieselbe für Verteidiger sichtbare Hop-Struktur ab, ohne einen Vermittler zum Opfer zu machen.
{% endhint %}

## Residential- und Mobile-Proxy-Netzwerke

Residential-Proxy-Dienste weisen Sitzungen Adressen von privaten Breitbandanschlüssen zu; Mobile-Proxys nutzen Carrier-NAT-Pools für den Egress. Die Infrastruktur kann aus ausdrücklich angemeldeten Geräten, in Consumer-Apps gebündelter SDK-/Proxyware, Resellern oder Malware stammen. Diese Ursprünge sind nicht gleichwertig: Fehlende informierte Einwilligung macht aus einem Datenschutzdienst kompromittierte Infrastruktur.

Rotationsmodi beeinflussen die Erkennung:

- **Rotation pro Request** erzeugt schnelle IP- und ASN-/Geografie-Wechsel, während die Identität auf höheren Protokollebenen stabil bleibt;
- **Sticky Sessions** behalten einen Exit minuten- oder stundenlang bei und ähneln dadurch einem gewöhnlichen Teilnehmer;
- **Backconnect-Gateways** zeigen dem Kunden einen einzigen Broker-Endpunkt und wählen die Exits intern aus;
- **Mobile Pools** bündeln viele echte Teilnehmer hinter wenigen Carrier-NAT-Adressen, wodurch eine IP-Sperre kostspielig wird.

Verteidiger sollten die IP mit der authentifizierten Sitzung, dem TLS-/Client-Fingerprint, der HTTP-Reihenfolge, dem Geräte-Cookie und dem Verhalten korrelieren. Ein vermeintlich lokaler Residential-Login, auf den ein Login aus einem anderen Land folgt, während alle Merkmale höherer Protokollebenen identisch bleiben, ist aussagekräftiger als der Ruf allein. Umgekehrt verursachen geteilte Adressen und Mobilfunk-Handoffs legitime Wechsel. Eine Residential-/Proxy-Klassifizierung sollte daher niemals als Urteil gelten.

### Proxyware-Control-Planes und Überschneidungen bei Resellern

Modelliert einen Residential-Pool nicht als flache Liste von Exits. Die Analyse des IPIDEA-Ökosystems deckte eine wiederverwendbare **zweistufige Control-Plane** auf: Ein eingebettetes SDK meldet zunächst Geräte-/Registrierungsmetadaten an eine Tier-One-Domain und erhält Scheduling-Informationen sowie IP:Port-Paare für `connect`/`proxy` auf Tier Two. Der Knoten fragt regelmäßig den Tier-Two-Connect-Port nach einer codierten Aufgabe ab, öffnet eine zweite Verbindung zum zugehörigen Proxy-Port und leitet die bereitgestellten Bytes an das angeforderte Ziel weiter. SDKs und Proxy-Marken, die nominell unterschiedlich waren, hatten separate Discovery-Domains, liefen jedoch über gemeinsame Eigentums- und Reseller-Beziehungen in einer geteilten Tier-Two-Infrastruktur und überlappenden Exit-Pools zusammen.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Dies erzeugt robustere Hunting-Pivots als ein Residential-IP-Block:<sup>[[13]](#references)</sup>

- Ein unerwarteter Utility-, VPN-, Game- oder Embedded-Device-Prozess sendet eine stabile Geräte-ID/Kundenkennung und erhält eine wechselnde Serverliste;
- der Endpunkt fragt eine direkte IP an einem ungewöhnlichen Port ab und verbindet sich dann unmittelbar vor dem Öffnen eines Sockets zu einem neuen Ziel mit einem anderen Port derselben Adresse;
- mehrere scheinbare Marken teilen Tier-Two-Adressen, Protokollgrammatik, SDK-Code oder Überschneidungen bei Exit-Nodes;
- verschiedene Anwendungen, die unterschiedliche Tier-One-Domains kontaktieren, erhalten Adressen aus demselben Tier-Two-Pool.

Die Überschneidungen schränken auch die Attribution ein: Eine IP im beworbenen Pool eines Anbieters belegt nicht, welcher Reseller, Kunde oder Threat Actor sie zum betreffenden Zeitpunkt verwendet hat. Sichert Flow-Zeitstempel, Prozessherkunft, Antwortinhalte von Tier One und Task-IDs von Tier Two.<sup>[[13]](#references)</sup> Emuliert diese Hierarchie in einer autorisierten Übung ausschließlich mit Endpunkten im Besitz der Organisation; bindet niemals Verbrauchergeräte oder Proxyware von Drittanbietern ein.

## Multi-Hop-Proxyketten

MITRE unterscheidet externe Proxies von **multi-hop proxies (T1090.003)**. Entscheidend ist nicht die Anzahl der Hops, sondern die Trennung von Wissen und Administration.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

Wenn eine Partei A und B betreibt, können gemeinsame Logs oder das Timing des Datenverkehrs den Circuit rekonstruieren. Werden vom selben Endpunkt/Konto aus nacheinander kommerzielle VPNs genutzt, kann das die Latenz erhöhen, während gemeinsame Identitäts-, Zahlungs- und Timing-Spuren bestehen bleiben. Tor verringert dieses Problem durch unabhängig ausgewählte Relays und ein gemeinsames Client-Design. Ein interaktives Netzwerk mit niedriger Latenz kann jedoch keinen Schutz vor einem Beobachter garantieren, der beide Enden überwacht.

Häufige Fehler sind DNS- oder IPv6-Bypass, Anwendungen, die eigene Sockets öffnen, Management-Datenverkehr, der Relays direkt erreicht, synchronisierte Aktivitäten, wiederverwendete SSH-Schlüssel und Anmeldungen bei identifizierenden Konten. Die korrekte Überprüfung ist ein Ausfalltest: Stoppe jedes Relay einzeln und stelle sicher, dass die Workload nicht auf einen unverschlüsselten Pfad ausweichen kann.

### Tunnelausfall und Leaks nach oben

Eine Relay-Architektur lässt sich häufig am besten zuordnen, wenn sie ausfällt. Unit 42 dokumentierte einen mehrstufigen Spionagepfad mit VPSs auf der Opferseite, Relay-VPSs, Residential Proxies, Tor und anderen Proxy-Diensten. Wenn ein Tunnel fehlte oder ausfiel, verband sich verborgene vorgelagerte Infrastruktur direkt mit Relay- und opferseitigen Systemen. Dieselbe Untersuchung nutzte außerdem ein X.509-Zertifikat, das kurzzeitig auf vorgelagerter Infrastruktur offengelegt wurde, als Anhaltspunkt für die Verknüpfung der Ebenen.<sup>[[14]](#references)</sup>

Halte die **Datenebene** (`victim <-> exit`) von der **Steuerungsebene** (`operator/upstream -> relay administration`) getrennt. Bewahre Eingangs- und Authentifizierungs-Logs auf jeder selbst betriebenen Ebene, Zertifikatverläufe und kurze fehlgeschlagene Verbindungen auf – nicht nur erfolgreiche C2-Sitzungen. Eine Quelle, die nur bei Relay-Ausfällen auftaucht oder mehrere opferseitige Knoten direkt verwaltet, ist ein vielversprechenderer Kandidat für vorgelagerte Infrastruktur als ein gewöhnlicher Exit. Ihre ASN/Geolokalisierung bleibt jedoch eine Hypothese, kein Beweis für die Identität eines Operators.

In einem autorisierten Lab sollte die Workload bei Fehlern geschlossen bleiben. Bei einer Workload, die in einem Linux-Netzwerk-Namespace isoliert ist, muss die erste Route den Tunnel verwenden. Wird dieser entfernt, müssen sowohl die Anfrage als auch die Routenabfrage fehlschlagen, statt die physische Uplink-Verbindung zu verwenden:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

Wiederhole den Test für DNS und IPv6 sowie an jeder Relay-Grenze. Wenn eine Probe erfolgreich ist, halte die tatsächliche Schnittstelle/Quelladresse fest, bevor du das Policy Routing oder die Firewall korrigierst; diese Beobachtung ist der Attribution-Leak, den ein Ermittler sehen würde.

## Redirector tiers and traffic shaping

Ein öffentlicher **Redirector** akzeptiert Datenverkehr, der einer operationsspezifischen Grammatik entspricht, und leitet ihn an einen geschützten Teamserver weiter. Alles andere kann abgewiesen oder mit harmlos wirkenden Inhalten beantwortet werden.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Mehrere Ebenen begrenzen die Offenlegung: Das Abbrennen einer Public Domain muss nicht den Teamserver offenlegen. CDNs bieten Anycast-Kapazität und eine renommierte äußere Domain, doch das CDN-Konto und die Edge-Logs werden zu Attributionspunkten. TLS-Fingerprints, Zertifikatshistorien, charakteristische Pfade/Header-Reihenfolgen, Antwortgrößen, Redirect-Verhalten und Origin-Allowlisten können vermeintlich unabhängige Fronts miteinander verknüpfen.

Zur Erkennung sollten Reverse-Proxy-Felder vor der Normalisierung erfasst, SNI/Host/authority verglichen, seltene Header-Kombinationen untersucht, Antwortinhalte und TLS-Fingerprints gruppiert sowie Cloud-/CDN-Audit-Logs auf Konfigurationsüberschneidungen geprüft werden. Autorisierte Red Teams sollten keine reale Marke kopieren und keine Erfassung von Zugangsdaten hinter einem unbeteiligten Dritten platzieren.

## Domain fronting und domainless fronting

Beim klassischen **domain fronting (T1090.004)** gibt die TLS-Verbindung eine zulässige Front-Domain in SNI an, während der verschlüsselte HTTP-`Host`-Header oder die HTTP/2-`:authority` eine andere Back-End-Domain anfordert. Ein kooperierendes CDN leitet anhand des inneren Werts weiter. Ein Netzwerkbeobachter ohne TLS-Entschlüsselung sieht die Front; das CDN sieht beide Werte und den Origin. Bei domainless-Varianten kann SNI leer sein, während ein anderes Routing-Feld das Ziel auswählt.<sup>[[4]](#references)</sup>

Das ist keine magische Identitätsvortäuschung: Es funktioniert nur, wenn der Intermediär die Abweichung absichtlich oder versehentlich zulässt und weiß, wie der innere Name weiterzuleiten ist. Große Anbieter haben kontoübergreifendes Fronting eingeschränkt. Encrypted ClientHello (ECH) verändert, was ein Beobachter auf dem Übertragungsweg sehen kann, löscht aber keine CDN-, Endpoint- oder Anwendungsdaten.

Zu den Erkennungspunkten gehören:

- Prozessabstammung auf dem Endpoint und ein für diese Anwendung unerwartetes Ziel;
- Abweichungen zwischen SNI und HTTP-authority, sofern TLS-Inspektion rechtmäßig und verfügbar ist;
- CDN-Logs, die zeigen, dass ein Tenant/eine Front zu einer anderen authority/einem anderen Origin weiterleitet;
- ungewöhnlich lange oder periodische Verbindungen zu einem normalerweise interaktiven Dienst;
- stabile Größen und Taktungen verschlüsselter Datenströme über wechselnde Front-Domains hinweg.

Das sichere Lab simuliert die Routing-Abweichung auf einem eigenen Reverse Proxy; es missbraucht kein öffentliches CDN.

## Dynamische Auflösung: DDNS, DGA und fast flux

Dynamische Auflösung entkoppelt einen logischen Dienst von fester Infrastruktur:

- **DDNS:** Ein authentifizierter Client aktualisiert einen stabilen Namen, wenn sich seine Adresse ändert.
- **DGA:** Endpoint und Controller leiten anhand eines Zeit-/Key-Seeds mögliche Domain-Namen ab; der Betreiber registriert eine kleine Teilmenge.
- **Fast flux:** Ein Name liefert eine schnell wechselnde Menge kompromittierter/Proxy-Adressen zurück, oft mit niedrigen TTLs.
- **Double flux:** Sowohl Dienstadressen als auch autoritative Nameserver-Adressen wechseln, wodurch auch die Kontrollebene verborgen wird.

Fast flux ist ein adversariales Lastverteilungsmuster, nicht einfach „viele DNS-Antworten“. Aussagekräftigere Indizien ergeben sich aus der Kombination von niedriger TTL, hoher Zahl eindeutiger Adressen, großer ASN-/Geografie-Streuung, kurzer Lebensdauer der Nodes, wiederholtem Anwendungsverhalten und verdächtiger Registrierungshistorie. CDNs weisen mehrere dieser Eigenschaften legitimerweise auf. MITRE empfiehlt, DNS-Verhalten mit dem Prozess und den anschließenden Verbindungen zu korrelieren.<sup>[[5]](#references)</sup>

Eine DGA lässt sich anhand lexikalischer Entropie, Konsonanten-/Ziffernmustern, NXDOMAIN-Spitzen, synchron auftauchenden neuen Domains und Prozesskontext erkennen. Wordlist-DGAs und generative Modelle umgehen einfache Entropieregeln; dadurch werden zeitliche, fleetweite Korrelationen und die Endpoint-Abstammung wichtiger.

## Kompromittierte Domains und domain shadowing

Ein Akteur kann ein Registrar-/DNS-Konto kapern, eine verwaiste Subdomain übernehmen oder Records unter einer ansonsten renommierten Domain hinzufügen. **Domain shadowing** lässt die legitime Apex-Domain bestehen, während zahlreiche vom Angreifer kontrollierte Subdomains auf wechselnde Delivery- oder C2-Hosts verweisen. So werden Alter und Reputation der Domain genutzt und domainweite Sperren möglicherweise umgangen.<sup>[[6]](#references)</sup>

Verteidiger benötigen Registrar- und autoritative DNS-Audit-Logs, MFA, Registry-/Registrar-Sperren, Warnmeldungen bei neuen Delegierungen/API-Tokens/Nameservern, Certificate-Transparency-Überwachung und ein Inventar der über DNS referenzierten Cloud-Ressourcen. Die Auflösung und Zertifikatshistorie einer Subdomain sollten unabhängig von der Reputation der Apex-Domain untersucht werden.

## Webdienste und dead-drop resolver

Ein **dead-drop resolver (T1102.001)** speichert einen codierten Verweis auf das aktuelle C2 in einem legitimen Beitrag, Profil, Dokument, Repository, Cloud-Objekt oder Blockchain-Feld. Malware ruft das öffentliche Objekt ab, decodiert eine Domain/IP und kontaktiert die nächste Stufe. Bidirektionale Varianten tauschen Befehle oder Dateien über Service-APIs aus.<sup>[[7]](#references)</sup>

Eine GitHub-spezifische Variante dieses Resolvers verwendet die Issues Search API nur dann, wenn ein authentifizierter Repository-Kanal ausfällt. Der Client sucht nach Issues, die dem aktuellen Datum, Repository und Issue-Typ entsprechen, ruft die Comments-URL jedes Issues ab und extrahiert Ciphertext zwischen den Markern `<!--` und `-->`. Nach einer hostbezogenen, datumsabhängigen Entschlüsselung ersetzen Felder wie `Owner`, `LicRepo` und `LicToken` den primären Repository-Eigentümer, Pfad und Token. Dadurch kann der Betreiber Zugangsdaten und Endpoints rotieren, ohne den Client zu ersetzen; der Issue-Kommentar dient als Resolver, während die Repository-Dateien der Tasking-Kanal bleiben.<sup>[[15]](#references)</sup>

Eine Android-Variante wählt beim Start eine von zwei öffentlichen Telegram-Seiten aus und extrahiert Ciphertext zwischen zwei Vorkommen eines in der APK eingebetteten Markers. Sie decodiert den Wert mit Base64URL und entschlüsselt ihn mit AES-128-CBC: Die ersten 16 Bytes von `SHA-256(marker)` bilden den Schlüssel, die übrigen 16 Bytes den IV. Der Klartext ist die tatsächliche C2-Basis-URL, nicht die URL der Telegram-Seite. Bei der Reproduktion der Auflösung müssen Seiteninhalt und exakter Marker erhalten bleiben; durch Änderung der öffentlichen Seite lässt sich der Endpoint rotieren, ohne die APK neu zu erstellen.<sup>[[16]](#references)</sup>

Das sorgt für Resilienz und verbirgt das Back-End-C2 vor statischer Binäranalyse. Gleichzeitig entstehen stabile Objekt-, Tenant-, Repository-, API- und Zugriffsmuster-Identifikatoren. Verteidiger sollten Folgendes miteinander verknüpfen:

1. den Prozess, der den Dienst kontaktiert hat;
2. den genauen API-Pfad/das Objekt und den Antwort-Hash;
3. Decodierungs- oder String-Verarbeitungsaktivitäten;
4. die kurz darauf folgende neue ausgehende Verbindung; und
5. dasselbe Verhalten an anderen Stellen der Flotte.

GitHub, Cloud-Speicher oder soziale Medien vollständig zu sperren, ist selten praktikabel. Dienstbezogene Egress-Richtlinien und Korrelation auf Prozessebene sind effektiver als reine Domain-Sperren.

## Personas, Konten und Beschaffungskompartimente

Die Anonymität der Infrastruktur scheitert, wenn eine Persona, Wiederherstellungs-E-Mail-Adresse, Telefonnummer, Zahlung, ein Browser oder eine Admin-IP verschiedene Kompartimente verbindet. Staatlich unterstützte Operationen haben Social-Media-Profile, E-Mail-Identitäten und Cloud-Konten lange vor ihrer Verwendung aufgebaut; ATT&CK führt dies als Establish Accounts (T1585), einschließlich Social-, E-Mail- und Cloud-Untertechniken.<sup>[[8]](#references)</sup>

Verteidiger oder Ermittler erstellen einen Graphen anhand folgender Merkmale:

- Erstellungszeit und erste Anmeldung, Locale, Zeitzone und Arbeitszeiten;
- Wiederherstellungsdaten, MFA-Geräte, Identitätsdokumente und Zahlungsmittel;
- Browser-/TLS-Fingerprints und Verlauf der Quellnetzwerke;
- Wiederverwendung von Avataren, Herkunft von Bildern, Schreibstil und Wachstum sozialer Verbindungen;
- gemeinsamer Domain-Registrant, Nameserver, Zertifikat, Analytics-ID oder Repository-Commit;
- Aktionen auf der Management-Ebene, die die öffentliche Relay-Architektur umgehen.

Bei einem autorisierten Red Team sollten synthetische Personas gegenüber der Übungsleitung dokumentiert, organisationsinterne Wiederherstellungs- und Zahlungskanäle verwendet, die Imitation unbeteiligter realer Personen vermieden und eine geplante Ausmusterung vorgesehen werden. Das SOC kann weiterhin im Unklaren bleiben; die Operation darf jedoch nicht unverantwortlich werden.

## Neue zusammengesetzte Muster für die Bedrohungsmodellierung

Die folgenden Beispiele sind **von Verteidigern entwickelte Kombinationen** und keine Behauptungen, dass ein namentlich genannter Akteur jedes genaue Design eingesetzt hat. Sie kombinieren bereits beobachtete Primitiven und eignen sich als Purple-Team-Hypothesen.

### Asymmetrisches One-Way-Tasking

Befehle treffen über eine öffentliche, Broadcast- oder Append-only-Quelle ein, während Ergebnisse nach einer Verzögerung über einen unabhängigen Kanal abfließen. Zu den Primitiven zählen unter anderem One-Way-Kommunikation über Webdienste und dead drops. Die Trennung verhindert, dass ein einzelner Datenstrom bidirektional wirkt, und erschwert einfache Request-/Response-Korrelationen.<sup>[[9]](#references)</sup>

**Erkennung:** Objektzugriffe erhalten und anschließend Prozesszustandsänderungen und spätere ausgehende Übertragungen über ein längeres Zeitfenster korrelieren. Nach einem seltenen Prozess suchen, der dasselbe öffentliche Objekt liest, auch wenn nicht unmittelbar darauf geantwortet wird.

### Promotion zu mehrstufigen Kanälen

Eine unauffällige erste Stufe führt eine Bestandsaufnahme durch und leitet nur ausgewählte Systeme an einen unabhängigen Kanal der zweiten Stufe weiter. Endpoint, Protokoll und Prozess der zweiten Stufe haben möglicherweise keinerlei Infrastruktur mit der ersten gemeinsam. Dadurch wird die Exposition leistungsfähiger Infrastruktur begrenzt; das Vorgehen ist explizit als ATT&CK T1104 modelliert.<sup>[[10]](#references)</sup>

**Erkennung:** `erster Netzwerkprozess -> heruntergeladener/konfigurierter Zustand -> neuer Prozess oder Injection -> unabhängiges Ziel` miteinander verknüpfen; den Vorfall nicht nach dem Sperren der ersten Domain schließen.

### Protokollübergreifende Relay-Übersetzung

Verschiedene Hops übersetzen HTTPS, QUIC, WebSocket, DNS, SSH oder eine Message-Queue-API, anstatt Pakete transparent weiterzuleiten. Die Übersetzung beseitigt einen einzelnen Ende-zu-Ende-Protokoll-Fingerprint, schafft aber Gateways mit charakteristischen Zeitmustern, Pufferungen und semantischen Konvertierungen. Protocol tunneling (T1572) lässt sich mit Proxys und der Vortäuschung legitimer Dienste kombinieren.<sup>[[11]](#references)</sup>

**Erkennung:** Nach Gateway-Hosts suchen, die ein Protokoll empfangen und ein anderes initiieren, wobei Byte- und Zeitverhalten eng gekoppelt sind; die Absicht des Endpoints mit dem tatsächlich übertragenen Protokoll vergleichen.

### Passive Aktivierung auf Edge-Geräten

Anstatt zu beaconen, überwacht ein Implantat den Verkehr, der bereits einen Router/VPN erreicht, und aktiviert sich nur bei einem Magic Value, einem Quellportmuster oder einem authentifizierten Token. Normaler Verkehr wird weiterhin an den echten Dienst weitergeleitet. ATT&CK bezeichnet dies als Traffic Signaling (T1205) und dokumentiert Beispiele für Netzwerkgeräte und APTs.<sup>[[12]](#references)</sup>

**Erkennung:** Integrität von Firmware/Dateien, rohe Paketerfassung bei einer autorisierten Suche, unerwartete Socket-Filter und abweichendes Dienstverhalten. Das Fehlen eines periodischen Beacons beweist nicht, dass ein Edge-Gerät sauber ist.

### Serverless- und kurzlebige Origin-Rotation

Eine Front behält eine stabile logische Identität, während kurzlebige Functions/Container einzelne Stufen in mehreren Regionen/Konten ausführen. Dadurch werden die Lebensdauer auf Datenträgern und feste Origin-IP-Adressen reduziert; Telemetriedaten zu Control-Plane-Erstellung, Image/Layer, Rolle, Secret, Request-ID und Abrechnung bilden jedoch den dauerhaften Graphen.

**Erkennung:** Cloud-Audit- und Invocation-Logs außerhalb der Workloads aufbewahren; Deployment-Vorlagen, Rollen, Umgebungsvariablen und Front-Origin-Beziehungen gruppieren.

### Vielfalt der Privacy-Layer

Eine Operation kann gezielt eine einheitliche Kette vermeiden: Beispielsweise nutzt ein Kanal ein gemietetes Relay, das Tasking ein öffentliches Objekt, ein Exit eine eigene Mobilfunkverbindung im Lab und die Administration ein separates Organisationsnetzwerk. Dadurch sinkt der Nutzen einer Kompromittierung eines einzelnen Anbieters, aber das Risiko für zeitliche Korrelationen über Ebenen hinweg und für operative Fehler steigt.

**Erkennung:** Kampagnen-Zeitachsen über Identitäts-, DNS-, SaaS-, Netzwerk- und Cloud-Sensoren hinweg erstellen. Nach synchronisierten Zustandsänderungen statt nach identischen Indikatoren suchen.

### Dezentrale Dead Drops oder Dead Drops in Transparenz-Logs

Ein Akteur kann einen kleinen verschlüsselten Verweis in einem beliebigen dauerhaften öffentlichen Append-only-System, Content-Addressed-Store oder Transparenz-ähnlichen Feed ablegen. Das öffentliche Objekt ist resilient, doch sein exakter Index/Content-Hash und das Abfrageverhalten des Clients werden zu stabilen Identifikatoren.

**Erkennung:** Vollständige API-/Objekt-Identifikatoren und Antwort-Hashes erfassen; bei ungewöhnlichen Prozessen warnen, die unveränderliche Objekte abfragen und anschließend Decodierungen oder neue Verbindungen durchführen.

### Verzögerte Store-and-Forward-Operationen

Interaktives C2 erzeugt starke zeitliche Korrelationen. Bei einem Store-and-Forward-Design werden verschlüsselte Aufgaben gebündelt und Ergebnisse Minuten oder Stunden später über eine andere Queue oder physische Übertragung zurückgesendet. Dafür wird die Reaktionsgeschwindigkeit zugunsten schwächerer Ende-zu-Ende-Zeitkorrelationen aufgegeben.

**Erkennung:** Korrelationsfenster verlängern, periodische Queue-Zugriffe modellieren und das Staging auf Endpoints untersuchen. Durch Bündelung verlagert sich das Signal vom Paket-Timing auf geplante Prozess-/Dateiaktivitäten; es verschwindet nicht.

## Designprüfung: In Beobachtern denken

Füllen Sie diese Tabelle vor dem Deployment und nach der Datenerfassung für jeden Pfad aus:

| Ebene | Sieht die Quelle? | Sieht das Ziel? | Sieht den Inhalt? | Stabile Identifikatoren | Aufbewahrung/verantwortliche Stelle |
|---|---:|---:|---:|---|---|
| lokales Netzwerk/Carrier | | | | | |
| Entry-/Access-Dienst | | | | | |
| Traversal-Betreiber | | | | | |
| Exit/Redirector/CDN | | | | | |
| autoritatives DNS/Registrar | | | | | |
| Ziel | | | | | |
| Konto-/Zahlungsanbieter | | | | | |

Wenn ein gewöhnlicher Anbieter jede Spalte ausfüllen kann, bietet die Architektur zwar Verschleierung gegenüber dem Ziel, aber keine robuste Trennung. Wenn kein interner Verantwortlicher Aktivitäten einem Engagement zuordnen kann, ist die Architektur für professionelles Red Teaming ungeeignet.

## References

- [1] [MITRE ATT&CK — Infrastruktur beschaffen (T1583), Infrastruktur kompromittieren (T1584) und Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — China-nahe Spionageakteure nutzen ORB-Netzwerke](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast-Flux-DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Infrastruktur kompromittieren: Domains (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Webdienst: Dead-Drop-Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Konten einrichten (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Webdienst: One-Way-Kommunikation (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Mehrstufige Kanäle (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protokoll-Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Zerschlagung des weltweit größten Residential-Proxy-Netzwerks](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Die Shadow-Kampagnen: Aufdeckung globaler Spionage](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Blinder-Tunnel-Kampagne zielt auf irakische Infrastruktur](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [16] [RemControl: KI erstellte die Overlays. Opfer verlieren ihre PINs](https://www.group-ib.com/blog/remcontrol-android-banking-trojan/)
{{#include ../banners/hacktricks-training.md}}
