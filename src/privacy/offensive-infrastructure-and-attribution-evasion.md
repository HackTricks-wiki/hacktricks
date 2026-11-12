# Offensive Infrastruktur und Attribution-Evasion

{{#include ../banners/hacktricks-training.md}}

Ein Operator erlangt durch einen einzelnen Proxy selten nennenswerte Anonymität. Reale Kampagnen bauen einen **Trennungsgraphen** auf: Der Operator erreicht einen Zugriffsknoten, Traversal-Knoten verbergen diesen vor dem Exit, Redirectors schützen das eigentliche C2, und kurzlebige Namen verweisen auf den öffentlichen Rand.

Nutze den [Katalog für Techniken zum anonymen Internetzugang](anonymous-internet-access-techniques.md), um für jeden Pfad eine einheitliche Übersicht zu Vor- und Nachteilen, Bereitstellung und Erkennung zu erhalten. Diese Seite geht näher auf die Zusammensetzung adversarialer Infrastruktur ein.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

Die letzte von einem Ziel beobachtete Adresse ist daher ein Hinweis auf einen Pfad, aber kein Beweis dafür, wer die Tastatur bedient hat. MITRE ordnet die wichtigsten Komponenten den Techniken Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) und Web Service (T1102) zu.<sup>[[1]](#references)</sup>

## Infrastrukturklassen

| Klasse | Warum ein Akteur sie nutzt | Dauerhafte Spuren | Bester Ansatzpunkt für Defender |
|---|---|---|---|
| Gemieteter VPS/Cloud | Schnell, vorhersehbar, routbar, einfach neu aufzusetzen | Mandant, Abrechnung, Konsole, Verlauf von Quell-Logins und Images | Ereignisse im Konto/in der Control Plane und wiederkehrender Server-Fingerprint |
| Kommerzielles VPN/Tor | Großer gemeinsam genutzter Egress-Pool; keine Serververwaltung | Einblick des Anbieters/Betreibers und Timing von Ende zu Ende | Verhalten am Ziel, Endpoint-Belege und Flow-Korrelation |
| Residential-/Mobile-Proxy | Consumer-ASN und geografische Plausibilität | Broker-/Kundendaten; Proxyware- oder Verhalten infizierter Hosts | Unmögliche Reiseverläufe, Proxy-Protokolle und Adresswechsel pro Session |
| Kompromittierter Server/Router/IoT | Nutzt Reputation und Jurisdiktion des Opfers | Implantat, Management-Flow und wiederkehrender vorgeschalteter Controller | Geräte-Telemetrie und ORB-Topologie, nicht eine einzelne Exit-IP |
| CDN/Redirector | Trennt den öffentlich sichtbaren Edge vom Back-End-C2 | TLS-/HTTP-Grammatik, Zertifikat, Routing- und Cloud-Konto-Artefakte | Korrelation zwischen Edge und Origin sowie Clustering nach Request-Form |
| Legitime Webdienste | Fügt sich in erlaubten GitHub-/Cloud-/Social-Traffic ein | API-Token, Mandanten-/Objektkennungen und ungewöhnliche Prozess-Abstammung | Endpoint-Prozess plus Dienst-/API-Semantik |
| Physischer/Mobilfunk-/Satellitenpfad | Verändert den scheinbaren physischen Ursprung | Funk-, Mobilfunkanbieter-, Teilnehmer-, Geräte- und Standortdaten | Kombinierte Funk-/physische und Netzwerkbelege |

## Operative Relay-Box-Netzwerke

Ein **ORB-Netzwerk** ist eine verwaltete Proxy-Flotte, die als zwischengeschalteter Dienst genutzt wird. Mandiant unterteilt sie in bereitgestellte Netzwerke aus gemieteten Servern, nicht bereitgestellte Netzwerke aus kompromittierten Routern/IoT-Geräten und hybride Netzwerke. Eine ausgereifte Topologie hat vier logische Rollen:<sup>[[2]](#references)</sup>

1. **Administrationsserver (ACOS):** Verwaltet Inventar, Zugangsdaten, Zustand und Routing-Richtlinien.
2. **Zugangs-/Relay-Node:** Authentifiziert Kunden oder Operatoren; sie ist der stabile Einstiegspunkt in ein sich veränderndes Mesh.
3. **Traversal-Nodes:** Ein oder mehrere gemietete oder kompromittierte Systeme leiten undurchsichtige Verbindungen weiter.
4. **Exit-/Staging-Node:** Zeigt Reconnaissance-, Exploitation- oder C2-Zielen die endgültige Quelladresse.

Das Mesh kann Exits nach Land, ASN, Latenz oder Verfügbarkeit auswählen und ausgefallene Nodes rotieren. Mehrere Threat Groups können dasselbe Netzwerk mieten. Mandiant beobachtete, dass eine IPv4-Adresse bei einigen ORBs nur 31 Tage lang zugeordnet blieb; deshalb empfiehlt es, das **Netzwerk als sich entwickelnde, einem Akteur ähnliche Entität** zu behandeln, statt eine veraltete IP-Liste zu blockieren.<sup>[[2]](#references)</sup>

### Was das bringt – und was es leakt

- Das Ziel sieht einen Exit, der geografisch nahe und scheinbar privat genutzt sein kann.
- Der Exit sieht das Ziel und den vorherigen Hop, aber nicht unbedingt den Operator.
- Der Zugangsdienst sieht den Kunden und die Routenanfrage. Ein unabhängig verwaltetes Mesh kann den Kunden von den Exits trennen, erzeugt aber einen aussagekräftigen Datensatz bei einem Dritten.
- Wiederkehrende Ports, Reihenfolge der Handshakes, Server-Banner, Zertifikate, Verfügbarkeitsfenster und Controller-Beziehungen können die Flotte offenlegen, selbst wenn sich die IPs ändern.
- Ein kompromittierter Router verfügt häufig über keine Endpoint-Telemetrie, aber sein ISP hat weiterhin Teilnehmer- und Flow-Daten; eine Beschlagnahmung legt Implantat-/Konfigurationsartefakte offen.

{% hint style="info" %}
Reproduziere für eine autorisierte Übung die Topologie mit organisationsinternen VMs oder Routern und bewahre die Attributionszuordnung des Controllers auf. Nutze keine offenen Proxys oder Geräte Dritter. Der [Lab-Guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) erstellt dieselbe für Defender sichtbare Hop-Struktur, ohne einen Vermittler zum Opfer zu machen.
{% endhint %}

## Residential- und Mobile-Proxy-Netzwerke

Residential-Proxy-Dienste weisen Sessions Consumer-Breitbandadressen zu; Mobile-Proxys nutzen Carrier-NAT-Pools als Egress. Die Infrastruktur kann von ausdrücklich registrierten Geräten, in Consumer-Apps gebündelter SDK-/Proxyware, Resellern oder Malware stammen. Diese Ursprünge sind nicht gleichwertig: Fehlende informierte Einwilligung macht aus einem Privacy-Dienst kompromittierte Infrastruktur.

Rotationsmodi beeinflussen die Erkennung:

- **Rotation pro Request** erzeugt schnelle IP- und ASN-/Geografie-Wechsel, während die Identität auf höheren Schichten stabil bleibt;
- **Sticky Sessions** behalten einen Exit minuten- oder stundenlang bei und ähneln dadurch einem gewöhnlichen Teilnehmer;
- **Backconnect-Gateways** zeigen dem Kunden einen einzelnen Broker-Endpunkt und wählen intern die Exits aus;
- **Mobile Pools** bündeln viele echte Teilnehmer hinter einer kleinen Zahl von Carrier-NAT-Adressen, wodurch eine IP-Sperre kostspielig wird.

Defender sollten die IP mit der authentifizierten Session, dem TLS-/Client-Fingerprint, der HTTP-Reihenfolge, dem Geräte-Cookie und dem Verhalten korrelieren. Ein vermeintlich lokaler Residential-Login, auf den ein Login aus einem anderen Land folgt, während alle Merkmale höherer Schichten identisch bleiben, ist aussagekräftiger als Reputation allein. Umgekehrt führen gemeinsam genutzte Adressen und Mobile-Handoffs zu legitimen Wechseln; daher darf eine Residential-/Proxy-Klassifizierung nie als endgültiges Urteil gelten.

### Proxyware-Control-Planes und Überschneidungen zwischen Resellern

Modelliere einen Residential-Pool nicht als flache Liste von Exits. Die Analyse des IPIDEA-Ökosystems offenbarte eine wiederverwendbare **zweistufige Control Plane**: Ein eingebettetes SDK meldet Geräte-/Registrierungsmetadaten zunächst an eine Tier-One-Domain und erhält Scheduling-Informationen sowie `connect`-/`proxy`-IP:Port-Paare der Tier Two. Der Node fragt regelmäßig den Tier-Two-Connect-Port nach einer codierten Aufgabe ab, öffnet eine zweite Verbindung zum zugehörigen Proxy-Port und leitet die bereitgestellten Bytes an das angeforderte Ziel weiter. SDKs und Proxy-Marken, die nominell unterschiedlich waren, hatten getrennte Discovery-Domains, liefen aber aufgrund gemeinsamer Eigentums- und Reseller-Beziehungen bei gemeinsamer Tier-Two-Infrastruktur und überlappenden Exit-Pools zusammen.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Dies liefert dauerhaftere Hunting-Pivots als ein residential IP-Block:<sup>[[13]](#references)</sup>

- Ein unerwarteter Prozess für Dienstprogramme, VPN, Spiele oder eingebettete Geräte sendet eine stabile Geräte-ID/Kundenkennung und erhält eine wechselnde Serverliste;
- der Endpunkt fragt eine direkte IP-Adresse an einem ungewöhnlichen Port ab und verbindet sich dann unmittelbar vor dem Öffnen eines Sockets zu einem neuen Ziel mit einem anderen Port derselben Adresse;
- mehrere scheinbare Marken teilen sich Tier-Two-Adressen, Protokollgrammatik, SDK-Code oder Überschneidungen bei Exit-Nodes;
- verschiedene Anwendungen, die unterschiedliche Tier-One-Domains kontaktieren, erhalten Adressen aus demselben Tier-Two-Pool.

Die Überschneidung schränkt auch die Attribution ein: Eine IP-Adresse im beworbenen Pool eines Anbieters belegt nicht, welcher Reseller, Kunde oder Threat Actor sie zum fraglichen Zeitpunkt verwendet hat. Sichert Flow-Zeitstempel, Prozessherkunft, Tier-One-Antwortinhalte und Tier-Two-Task-IDs.<sup>[[13]](#references)</sup> Emuliert diese Hierarchie bei einer genehmigten Übung ausschließlich mit organisationsinternen Endpunkten; bindet niemals Verbrauchergeräte oder Proxyware Dritter ein.

## Mehrstufige Proxy-Ketten

MITRE unterscheidet externe Proxies von **multi-hop proxies (T1090.003)**. Entscheidend ist nicht die Anzahl der Hops, sondern die Trennung von Wissen und Administration.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

Wenn eine Partei A und B betreibt, können gemeinsame Logs oder das Timing des Datenverkehrs den Circuit rekonstruieren. Werden vom selben Endpunkt/Konto aus mehrere kommerzielle VPNs hintereinandergeschaltet, kann das die Latenz erhöhen, während gemeinsame Identitäts-, Zahlungs- und Timing-Spuren bestehen bleiben. Tor verringert dieses Problem durch unabhängig ausgewählte Relays und ein gemeinsames Client-Design. Ein interaktives Netzwerk mit niedriger Latenz kann jedoch keinen Schutz vor einem Beobachter versprechen, der beide Enden misst.

Häufige Fehler sind DNS- oder IPv6-Bypass, Anwendungen, die eigene Sockets öffnen, Management-Datenverkehr, der Relays direkt erreicht, synchronisierte Aktivitäten, wiederverwendete SSH-Schlüssel und Anmeldungen bei identifizierenden Konten. Die richtige Überprüfung ist ein Ausfalltest: Stoppe jedes Relay der Reihe nach und zeige, dass die Workload nicht auf einen unverschlüsselten Pfad ausweichen kann.

### Tunnelausfall und Upstream-Leaks

Eine Relay-Architektur lässt sich häufig am besten zuordnen, wenn sie ausfällt. Unit 42 dokumentierte einen mehrstufigen Spionagepfad mit VPSs auf der Opferseite, Relay-VPSs, Residential Proxies, Tor und weiteren Proxy-Diensten. Wenn ein Tunnel fehlte oder zusammenbrach, verband sich verborgene Upstream-Infrastruktur direkt mit Relay-Systemen und Systemen auf der Opferseite. Dieselbe Untersuchung nutzte außerdem ein X.509-Zertifikat, das kurzzeitig auf der Upstream-Infrastruktur offengelegt wurde, als Pivot zwischen den Ebenen.<sup>[[14]](#references)</sup>

Halte die **data plane** (`victim <-> exit`) von der **control plane** (`operator/upstream -> relay administration`) getrennt. Bewahre Ingress- und Authentifizierungs-Logs auf jeder eigenen Ebene, Zertifikatshistorien und kurze fehlgeschlagene Verbindungen auf – nicht nur erfolgreiche C2-Sitzungen. Eine Quelle, die nur bei Relay-Ausfällen auftaucht oder mehrere Systeme auf der Opferseite direkt verwaltet, ist ein stärkerer Kandidat für einen Upstream als ein gewöhnlicher Exit. ASN und Geolokalisierung bleiben jedoch Hypothesen und sind kein Beweis für die Identität eines Operators.

Ein autorisiertes Lab sollte die Workload so konfigurieren, dass sie bei Ausfällen geschlossen bleibt. Bei einer in einem Linux-Netzwerk-Namespace isolierten Workload muss die erste Route den Tunnel verwenden. Nachdem dieser entfernt wurde, müssen sowohl die Anfrage als auch die Routenabfrage fehlschlagen, statt den physischen Uplink auszuwählen:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

Wiederhole den Test für DNS und IPv6 sowie an jeder Relay-Grenze. Wenn eine Probe erfolgreich ist, notiere die tatsächliche Schnittstelle/Quelladresse, bevor du das Policy-Routing oder die Firewall reparierst; diese Beobachtung ist der Attribution-Leak, den ein Ermittler sehen würde.

## Redirector-Ebenen und Traffic Shaping

Ein öffentlicher **Redirector** nimmt Datenverkehr an, der einer operationsspezifischen Grammatik entspricht, und leitet ihn an einen geschützten Teamserver weiter. Alles andere kann abgewiesen oder mit harmlosen Inhalten beantwortet werden.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Mehrere Ebenen begrenzen die Offenlegung: Das Aufgeben einer öffentlichen Domain muss den Teamserver nicht offenlegen. CDNs bieten Anycast-Kapazität und eine vertrauenswürdige äußere Domain, doch das CDN-Konto und die Edge-Logs werden zu Attributionspunkten. TLS-Fingerprints, Zertifikatshistorien, charakteristische Pfade/Header-Reihenfolgen, Antwortgrößen, Redirect-Verhalten und Origin-Allowlisten können vermeintlich unabhängige Fronts miteinander in Verbindung bringen.

Zur Erkennung sollten Reverse-Proxy-Felder vor der Normalisierung aufgezeichnet, SNI/Host/Authority verglichen, seltene Header-Kombinationen untersucht, Antwortinhalte und TLS-Fingerprints gruppiert sowie Cloud-/CDN-Audit-Logs auf Konfigurationsüberschneidungen geprüft werden. Autorisierte Red Teams sollten keine reale Marke kopieren und keine Erfassung von Zugangsdaten hinter einem unbeteiligten Dritten platzieren.

## Domain fronting und domainless fronting

Beim klassischen **domain fronting (T1090.004)** gibt die TLS-Verbindung in SNI eine erlaubte Front-Domain an, während der verschlüsselte HTTP-`Host`- oder HTTP/2-`:authority`-Header eine andere Backend-Domain anfordert. Ein kooperierendes CDN leitet anhand des inneren Werts weiter. Ein Netzwerkbeobachter ohne TLS-Entschlüsselung sieht die Front; das CDN sieht beide Werte und den Origin. Bei domainless-Varianten ist SNI möglicherweise leer, während ein anderes Routing-Feld das Ziel auswählt.<sup>[[4]](#references)</sup>

Das ist keine magische Identitätsvortäuschung: Es funktioniert nur, wenn der Intermediär die Abweichung absichtlich oder versehentlich zulässt und weiß, wie er den inneren Namen weiterleitet. Große Anbieter haben accountübergreifendes Fronting eingeschränkt. Encrypted ClientHello (ECH) verändert, was ein Beobachter auf dem Übertragungsweg sehen kann, beseitigt aber nicht die Aufzeichnungen beim CDN, Endpunkt oder in der Anwendung.

Erkennungspunkte sind unter anderem:

- Prozessherkunft auf dem Endpunkt und ein für diese Anwendung unerwartetes Ziel;
- Abweichungen zwischen SNI und HTTP-Authority, sofern TLS-Inspektion rechtmäßig und verfügbar ist;
- CDN-Logs, die zeigen, dass ein Tenant/eine Front zu einer anderen Authority/einem anderen Origin weiterleitet;
- ungewöhnlich lange oder periodische Sitzungen zu einem normalerweise interaktiven Dienst;
- stabile verschlüsselte Flow-Größen und Taktungen über wechselnde Front-Domains hinweg.

Das sichere Labor simuliert die Routing-Abweichung auf einem eigenen Reverse Proxy; es missbraucht kein öffentliches CDN.

## Dynamische Auflösung: DDNS, DGA und fast flux

Dynamische Auflösung entkoppelt einen logischen Dienst von fester Infrastruktur:

- **DDNS:** Ein authentifizierter Client aktualisiert einen stabilen Namen, nachdem sich seine Adresse geändert hat.
- **DGA:** Der Endpunkt leitet Domainnamen aus einem Seed ab, häufig aus Zeit oder einem Schlüssel, manchmal aber auch aus veränderlichen öffentlichen Inhalten; der Operator richtet DNS für den aktiven Namen ein.<sup>[[17]](#references)</sup>
- **Fast flux:** Ein Name liefert eine schnell wechselnde Gruppe kompromittierter/Proxy-Adressen zurück, oft mit niedrigen TTLs.
- **Double flux:** Sowohl Dienstadressen als auch Adressen autoritativer Nameserver rotieren, wodurch auch die Steuerungsebene verborgen wird.

Fast flux ist ein adversariales Muster zur Lastverteilung und nicht einfach „viele DNS-Antworten“. Aussagekräftigere Hinweise ergeben sich aus der Kombination niedriger TTLs, einer hohen Anzahl eindeutiger Adressen, großer ASN-/Geografie-Streuung, kurzer Lebensdauer der Knoten, wiederholtem Anwendungsverhalten und verdächtiger Registrierungshistorie. CDNs weisen legitimerweise mehrere dieser Merkmale auf. MITRE empfiehlt, DNS-Verhalten mit dem Prozess und nachfolgenden Verbindungen zu korrelieren.<sup>[[5]](#references)</sup>

Eine DGA lässt sich anhand lexikalischer Entropie, Konsonanten-/Ziffernmustern, NXDOMAIN-Spitzen, synchron auftretenden erstmals gesehenen Domains und Prozesskontext erkennen. Wortlisten-DGAs und generative Modelle umgehen einfache Entropieregeln; dadurch werden fleetweite zeitliche Gruppierung und die Herkunft am Endpunkt wichtiger.

### Veränderlicher Bild-Seed für eine Wortlisten-DGA

Eine DGA muss nicht von der Zeit abhängen. Ein Loader ruft eine öffentliche Telegram-Kanalseite ab, liest das `src`-Attribut des Elements `tgme_page_photo_image`, lädt das Profilbild herunter und hasht dessen **letzte 50 Dateibytes**, statt die dekodierten Pixel zu hashen. Vier Hash-Seeds wählen ein Adjektiv, ein Substantiv, ein Verb und eine Zahl aus. Durch Ändern des Bildes ändert sich der abgeleitete DNS-Name, ohne dass ein neuer Client ausgeliefert werden muss. Auf beiden Seiten müssen exakt dieselben heruntergeladenen Bildbytes und dieselbe Reihenfolge der Wortlisten verwendet werden; eine erneute Kodierung des Bildes oder eine andere Reihenfolge einer Liste ergibt andere Namen.<sup>[[17]](#references)</sup>

Mit den aus dem Client wiederhergestellten Wortlisten lässt sich dieser Schritt der Namensauswahl reproduzieren. Der byteweise Hash der Quelle verwendet einen 64-Bit-Akkumulator, den Multiplikator `0x1000193` und separate Seeds für jede Komponente:<sup>[[17]](#references)</sup>

<details>
<summary>Die bildbasierte Auswahl eines Wortlistennamens reproduzieren</summary>

```python
def wordlist_domain(image: bytes, adjectives: list[str], nouns: list[str], verbs: list[str], suffix: str) -> str:
    if len(image) < 50:
        raise ValueError("Image must contain at least 50 bytes")
    tail = image[-50:]
    def hashed(seed: int) -> int:
        value = seed
        for byte in tail:
            value = ((value ^ byte) * 0x1000193) & 0xFFFFFFFFFFFFFFFF
        return value
    a = adjectives[hashed(0x811C9DC5) % len(adjectives)]
    n = nouns[hashed(0xAF0154A5) % len(nouns)]
    v = verbs[hashed(0xFE5439E4) % len(verbs)]
    digit = hashed(0xFFA7471A) % 1000
    return f"{a}-{n}-{v}-{digit}.{suffix}"
```

</details>

Im Gegensatz zu einem [dead-drop resolver](#web-services-and-dead-drop-resolvers), der den Endpunkt selbst veröffentlicht, stellt das öffentliche Objekt hier nur einen veränderbaren Seed bereit; der Client leitet den Endpunkt lokal ab.

Der generierte Name wird dann über `https://dns.google/resolve?name=<domain>&type=TXT` auf einen DNS-TXT-Record abgefragt. Der Client dekodiert das Feld `data` der JSON-Antwort mit Base64, überprüft eine Ed25519-Signatur mit seinem eingebetteten öffentlichen Schlüssel und entschlüsselt erst dann den Befehl mit AES-ECB. Der beobachtete Klartext beginnt mit einem Methodenselektor und einer URL für eine verschlüsselte Payload. Durch die Signaturprüfung kann ein auflösbarer TXT-Record allein keine akzeptierte Tasking-Information liefern.<sup>[[17]](#references)</sup>

## Kompromittierte Domains und Domain shadowing

Ein Angreifer kann ein Registrar-/DNS-Konto kapern, eine verwaiste Subdomain übernehmen oder Records unter einer ansonsten seriösen Domain hinzufügen. **Domain shadowing** lässt die legitime Apex-Domain bestehen, während eine große Zahl von Angreifer-kontrollierten Subdomains auf wechselnde Delivery- oder C2-Hosts verweist. Dadurch kann die Infrastruktur von Alter und Reputation profitieren und einer domainsweiten Blockierung entgehen.<sup>[[6]](#references)</sup>

Verteidiger benötigen Audit-Logs von Registraren und autoritativen DNS-Servern, MFA, Registry-/Registrar-Locks, Alarme für neue Delegationen/API-Tokens/Name-Server, Certificate-Transparency-Monitoring sowie eine Bestandsaufnahme der in DNS referenzierten Cloud-Ressourcen. Untersucht Auflösung und Zertifikatshistorie einer Subdomain unabhängig von der Reputation der Apex-Domain.

## Webdienste und dead-drop resolvers

Ein **dead-drop resolver (T1102.001)** speichert einen kodierten Verweis auf das aktuelle C2 in einem legitimen Beitrag, Profil, Dokument, Repository, Cloud-Objekt oder Blockchain-Feld. Malware ruft das öffentliche Objekt ab, dekodiert eine Domain/IP-Adresse und kontaktiert die nächste Stufe. Bidirektionale Varianten tauschen Befehle oder Dateien über Service-APIs aus.<sup>[[7]](#references)</sup>

Eine GitHub-spezifische Variante dieses Resolvers verwendet die Issues Search API nur dann, wenn ein authentifizierter Repository-Kanal fehlschlägt. Der Client sucht nach Issues, die zum aktuellen Datum, Repository und Issue-Typ passen, folgt der Comments-URL jedes Issues und extrahiert Ciphertext zwischen den Markern `<!--` und `-->`. Nach einer host-spezifischen, datumsbasierten Entschlüsselung ersetzen Felder wie `Owner`, `LicRepo` und `LicToken` den primären Repository-Owner, Pfad und Token. So kann der Operator Zugangsdaten und Endpunkte wechseln, ohne den Client zu ersetzen; der Issue-Kommentar dient als Resolver, während die Repository-Dateien der Tasking-Kanal bleiben.<sup>[[15]](#references)</sup>

Eine Android-Variante wählt beim Start eine von zwei öffentlichen Telegram-Seiten aus und extrahiert Ciphertext zwischen zwei Vorkommen eines in der APK eingebetteten Markers. Sie dekodiert den Wert mit Base64URL und entschlüsselt ihn mit AES-128-CBC: Die ersten 16 Bytes von `SHA-256(marker)` bilden den Schlüssel und die verbleibenden 16 Bytes den IV. Der Klartext ist die tatsächliche C2-Basis-URL, nicht die URL der Telegram-Seite. Bei der Reproduktion der Auflösung müssen Seiteninhalt und exakter Marker erhalten bleiben; durch Ändern der öffentlichen Seite lässt sich der Endpunkt wechseln, ohne die APK neu zu erstellen.<sup>[[16]](#references)</sup>

Das erhöht die Resilienz und verbirgt das Back-End-C2 vor statischer Binäranalyse. Zugleich entstehen stabile Kennungen für Objekte, Mandanten, Repositories, APIs und Zugriffsmuster. Verteidiger sollten folgende Daten zusammenführen:

1. den Prozess, der den Dienst kontaktiert hat;
2. den exakten API-Pfad/das Objekt und den Antwort-Hash;
3. Dekodierungs- oder Zeichenkettenverarbeitungsaktivitäten;
4. die kurz darauf aufgebaute neue ausgehende Verbindung; und
5. identisches Verhalten an anderer Stelle in der Flotte.

GitHub, Cloud-Speicher oder soziale Medien vollständig zu blockieren, ist selten praktikabel. Dienstbasierte Egress-Richtlinien und Korrelation auf Prozessebene sind einer reinen Domain-Blockierung überlegen.

## Personas, Konten und Beschaffungskompartimente

Die Anonymität der Infrastruktur scheitert, wenn eine Persona, Wiederherstellungs-E-Mail-Adresse, Telefonnummer, Zahlung, ein Browser oder eine Admin-IP Kompartimente miteinander verbindet. Staatlich unterstützte Operationen haben soziale Profile, E-Mail-Identitäten und Cloud-Konten lange vor ihrer Nutzung aufgebaut; ATT&CK erfasst dies als Establish Accounts (T1585), einschließlich Untertechniken für soziale Medien, E-Mail und Cloud.<sup>[[8]](#references)</sup>

Verteidiger oder Ermittler erstellen einen Graphen aus:

- Erstellungs- und Erstlogin-Zeitpunkt, Locale, Zeitzone und Arbeitszeiten;
- Wiederherstellungsdaten, MFA-Geräten, Identitätsnachweisen und Zahlungsmitteln;
- Browser-/TLS-Fingerprints und Verlauf der Quellnetzwerke;
- wiederverwendeten Avataren, Bildherkunft, Schreibstil und Wachstum des sozialen Graphen;
- gemeinsam genutzten Domain-Registranten, Name-Servern, Zertifikaten, Analytics-IDs oder Repository-Commits;
- Aktionen auf der Management-Ebene, die die öffentliche Relay-Architektur umgehen.

Bei einem autorisierten Red Team sollten synthetische Personas für den Übungsleiter dokumentiert werden, organisationsinterne Wiederherstellungs- und Zahlungskanäle verwenden, keine echten unbeteiligten Personen imitieren und einen geplanten Rückzug haben. Das SOC kann weiterhin im Unklaren bleiben; die Operation darf jedoch nicht ohne Verantwortlichkeit bleiben.

## Aufkommende zusammengesetzte Muster für Threat Modeling

Die folgenden Beispiele sind **von Verteidigern entwickelte Kombinationen** und keine Behauptungen, dass ein bestimmter Akteur genau diese Designs eingesetzt hat. Sie kombinieren bereits beobachtete Primitive und eignen sich als Purple-Team-Hypothesen.

### Asymmetrisches One-way-Tasking

Befehle treffen über eine öffentliche, Broadcast- oder Append-only-Quelle ein, während Ergebnisse nach einer Verzögerung über einen unabhängigen Kanal abfließen. Zu den Beispielen für diese Primitive zählen One-way-Kommunikation über Webdienste und dead drops. Die Trennung verhindert, dass ein einzelner Datenfluss bidirektional erscheint, und erschwert einfache Request-/Response-Korrelation.<sup>[[9]](#references)</sup>

**Erkennung:** Bewahrt objektbezogene Lesezugriffe auf und korreliert anschließend Prozesszustandsänderungen und spätere ausgehende Übertragungen über ein größeres Zeitfenster. Sucht nach seltenen Prozessen, die dasselbe öffentliche Objekt lesen, auch wenn keine unmittelbare Antwort folgt.

### Mehrstufige Kanalaufwertung

Eine unauffällige erste Stufe führt eine Bestandsaufnahme durch und leitet nur ausgewählte Systeme auf einen unabhängigen Kanal der zweiten Stufe weiter. Der zweite Endpunkt, das Protokoll und der Prozess müssen keine Infrastruktur mit der ersten Stufe gemeinsam haben. Dadurch wird die hochentwickelte Infrastruktur weniger exponiert; das Muster ist in ATT&CK ausdrücklich als T1104 modelliert.<sup>[[10]](#references)</sup>

**Erkennung:** Verknüpft `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`; schließt den Vorfall nicht ab, nachdem die erste Domain blockiert wurde.

### Relay-Übersetzung zwischen Protokollen

Verschiedene Hops übersetzen HTTPS, QUIC, WebSocket, DNS, SSH oder eine Message-Queue-API, anstatt Pakete transparent weiterzuleiten. Die Übersetzung beseitigt einen einzelnen End-to-End-Protokoll-Fingerprint, schafft aber Gateways mit charakteristischen Zeitmustern, Pufferungen und semantischen Konvertierungen. Protocol Tunneling (T1572) lässt sich mit Proxys und Service-Impersonation kombinieren.<sup>[[11]](#references)</sup>

**Erkennung:** Sucht nach Gateway-Hosts, die ein Protokoll empfangen und ein anderes initiieren, wobei Byte- und Zeitverhalten eng gekoppelt sind; vergleicht die Absicht des Endpunkts mit dem tatsächlich übertragenen Protokoll.

### Passive Aktivierung auf Edge-Geräten

Statt Beaconing überwacht ein Implantat den bereits an einen Router/VPN gerichteten Datenverkehr und wird nur bei einem Magic Value, einem Quellportmuster oder einem authentifizierten Token aktiv. Normaler Datenverkehr wird weiterhin an den echten Dienst weitergeleitet. ATT&CK bezeichnet dies als Traffic Signaling (T1205) und führt dokumentierte Beispiele für Netzwerkgeräte und APTs auf.<sup>[[12]](#references)</sup>

**Erkennung:** Firmware-/Dateiintegrität, Raw-Packet-Capture bei einer autorisierten Untersuchung, unerwartete Socket-Filter und abweichendes Dienstverhalten. Das Fehlen eines periodischen Beacons beweist nicht, dass ein Edge-Gerät sauber ist.

### Rotation von Serverless- und kurzlebigen Ursprüngen

Ein Front behält eine stabile logische Identität bei, während kurzlebige Funktionen/Container einzelne Stufen in mehreren Regionen/Konten abwickeln. Dadurch verkürzt sich die Lebensdauer auf der Festplatte und feste Origin-IPs werden vermieden; Telemetriedaten zu Control-Plane-Erstellung, Image/Layer, Rolle, Secret, Request-ID und Abrechnung werden jedoch zum dauerhaften Graphen.

**Erkennung:** Cloud-Audit- und Invocation-Logs außerhalb der Workload aufbewahren; Deployment-Templates, Rollen, Environment-Keys und Front-to-Origin-Beziehungen gruppieren.

### Vielfalt der Privacy-Layer

Eine Operation kann bewusst auf eine einheitliche Kette verzichten: Ein Kanal nutzt beispielsweise ein gemietetes Relay, das Tasking ein öffentliches Objekt, ein Exit eine eigene Mobilfunkverbindung aus einem Labor und die Administration ein separates Organisationsnetzwerk. Das verringert den Nutzen, einen einzelnen Provider zu kompromittieren, erhöht jedoch das Risiko zeitlicher Korrelationen und operativer Fehler über mehrere Ebenen hinweg.

**Erkennung:** Kampagnen-Zeitachsen über Identity-, DNS-, SaaS-, Netzwerk- und Cloud-Sensoren erstellen. Nach synchronisierten Zustandsübergängen statt nach identischen Indikatoren suchen.

### Dezentrale dead drops oder Transparency-Log-dead drops

Ein Akteur kann einen kleinen verschlüsselten Verweis in einem dauerhaften öffentlichen Append-only-System, einem inhaltsadressierten Speicher oder einem Transparency-ähnlichen Feed platzieren. Das öffentliche Objekt ist resilient, aber sein genauer Index/Inhaltshash und das Polling-Verhalten des Clients werden zu stabilen Kennungen.

**Erkennung:** Vollständige API-/Objektkennungen und Antwort-Hashes protokollieren; bei ungewöhnlichen Prozessen alarmieren, die unveränderliche Objekte abfragen und anschließend dekodieren oder neue Verbindungen aufbauen.

### Verzögerte Store-and-Forward-Operationen

Interaktives C2 erzeugt starke zeitliche Korrelationen. Ein Store-and-Forward-Design bündelt verschlüsselte Jobs und gibt Ergebnisse Minuten oder Stunden später über eine andere Queue oder eine physische Übertragung zurück. Es opfert Reaktionsgeschwindigkeit zugunsten einer schwächeren End-to-End-Zeitkorrelation.

**Erkennung:** Korrelationsfenster verlängern, regelmäßige Queue-Zugriffe modellieren und Endpoint-Staging untersuchen. Durch Batching verlagert sich das Signal vom Paket-Timing auf geplante Prozess-/Dateiaktivitäten; es verschwindet nicht.

## Design-Review: In Beobachtern denken

Füllt diese Tabelle für jeden Pfad vor dem Einsatz und nach der Datenerfassung aus:

| Ebene | Sieht die Quelle? | Sieht das Ziel? | Sieht den Inhalt? | Stabile Kennungen | Aufbewahrung/verantwortliche Stelle |
|---|---:|---:|---:|---|---|
| lokales Netzwerk/Carrier | | | | | |
| Entry-/Access-Dienst | | | | | |
| Traversal-Betreiber | | | | | |
| Exit/Redirector/CDN | | | | | |
| autoritatives DNS/Registrar | | | | | |
| Ziel | | | | | |
| Konto-/Zahlungsanbieter | | | | | |

Wenn ein gewöhnlicher Provider jede Spalte ausfüllen kann, bietet die Architektur dem Ziel gegenüber Verschleierung, aber keine robuste Trennung. Wenn kein interner Verantwortlicher Aktivitäten einem Engagement zuordnen kann, ist die Architektur für professionelles Red Teaming ungeeignet.

## References

- [1] [MITRE ATT&CK — Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), and Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — China-nexus espionage actors use ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Compromise Infrastructure: Domains (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Establish Accounts (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Disrupting the World's Largest Residential Proxy Network](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — The Shadow Campaigns: Uncovering Global Espionage](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Blinder Tunnel Campaign Targets Iraqi Infrastructure](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [16] [RemControl: AI Built the Overlays. Victims Lose their PINs](https://www.group-ib.com/blog/remcontrol-android-banking-trojan/)
- [17] [Check Point Research — Tricks from the Past Deployed via Signed ChatGPT and Claude Binaries](https://research.checkpoint.com/2026/tricks-from-the-past-deployed-via-signed-chatgpt-and-claude-binaries/)
{{#include ../banners/hacktricks-training.md}}
