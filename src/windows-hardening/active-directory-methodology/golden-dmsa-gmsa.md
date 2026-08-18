# Golden gMSA/dMSA Attack (Uhesabuji wa Nenosiri za Managed Service Account Nje ya Mtandao)

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari

Windows Managed Service Accounts ni principals za domain zilizokusudiwa kuendesha services bila administrator kushughulikia password inayodumu kwa muda mrefu:

1. **gMSA** (group Managed Service Account) inaweza kutumiwa na computers zilizoidhinishwa kupitia `msDS-GroupMSAMembership` / `PrincipalsAllowedToRetrieveManagedPassword`.
2. **dMSA** (delegated Managed Service Account) ilianzishwa katika **Windows Server 2025**. Hufunga authentication ya kawaida kwenye machine identities zilizoidhinishwa na inaweza kuchukua nafasi ya legacy service account kupitia migration workflow.

Usichanganye **Golden dMSA** na **BadSuccessor**. Golden dMSA inahitaji ku-compromise KDS root-key material na ku-derive managed-account keys; [BadSuccessor](badsuccessor-dmsa-migration-abuse.md) badala yake hutumia vibaya control ya dMSA object na migration attributes zake.

DC haihifadhi password ya clear-text iliyotengenezwa kwa kujitegemea kwa kila gMSA. Hu-derive account password kutoka kwa **KDS root key**, Group Key Distribution Protocol (GKDI) key yenye time index, na account SID. Root-key objects ni `msKds-ProvRootKey` objects chini ya `CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,...`; value nyeti ni `msKds-RootKeyData`. `msDS-ManagedPasswordId` **si GUID**: ni binary key identifier iliyo na KDS root-key GUID, indexes za GKDI `L0`/`L1`/`L2`, na metadata ya domain/forest. DC hutumia KDF yenye label `GMSA PASSWORD` na binary SID kama context, kisha hufichua `MSDS-MANAGEDPASSWORD_BLOB` kwa principals pekee zilizoidhinishwa kuretrieve gMSA password.<sup>[[2]](#references)</sup>

dMSA kwa kawaida hutofautiana kiutendaji: secret yake imekusudiwa kubaki kwenye DC na KDC hutoa credentials kwa machine iliyoidhinishwa. Hata hivyo, dMSA hutumia tena password derivation ya msingi ya KDS/GKDI. Golden dMSA hujenga upya secret hiyo moja kwa moja na hivyo hupita intended machine-bound flow pamoja na Credential Guard kwenye service host.<sup>[[1]](#references)</sup>

## Golden gMSA / Golden dMSA Attack

Baada ya kutoa KDS root key, attacker anaweza ku-derive passwords za accounts zilizofungamanishwa na key hiyo bila kusoma `msDS-ManagedPassword`. Hii hupita per-account password-retrieval ACL na hudumu licha ya managed-password rotations za kawaida mradi root key iliyo-compromise bado inatumika. Kwa gMSAs, `msDS-ManagedPasswordId` inayoweza kusomeka kwa kawaida hutoa key identifier sahihi. Kwa dMSAs zilizo na ACL restrictions, Golden dMSA hupunguza identifier inayokosekana hadi **candidates 1,024** pekee.<sup>[[1]](#references)[[2]](#references)</sup>

### Mahitaji ya Awali

* KDS root-key object husika, ambayo kwa kawaida hupatikana kwa Enterprise Admin / forest-root Domain Admin rights, `SYSTEM` kwenye DC, au kutoka kwenye DC database au backup iliyo wazi.<sup>[[1]](#references)[[2]](#references)</sup>
* SID ya target account, DNS domain, forest name, na `sAMAccountName`.<sup>[[1]](#references)[[2]](#references)</sup>
* Kwa direct gMSA computation, `msDS-ManagedPasswordId` yake iliyosimbwa kwa base64; kwa Golden dMSA hii inaweza badala yake kukisiwa.<sup>[[1]](#references)[[2]](#references)</sup>
* Windows host ya x64 yenye .NET Framework 4.7.2 kwa [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA).<sup>[[3]](#references)</sup>

### Phase 1 - Toa KDS root key

`GoldenDMSA` na [`GoldenGMSA`](https://github.com/Semperis/GoldenGMSA) hu-export fields za root-key object kama base64 blob. Bila domain argument, tools hu-query forest root na huhitaji directory access yenye privileges zinazofaa. Kwa domain/forest argument, `SYSTEM` kwenye DC inaweza ku-query local Configuration naming-context replica ya DC hiyo.<sup>[[1]](#references)[[2]](#references)</sup>
```cmd
:: GoldenDMSA: Enterprise Admin, or SYSTEM on a DC with --domain
GoldendMSA.exe kds
GoldendMSA.exe kds -g KDS_ROOT_KEY_GUID
GoldendMSA.exe kds --domain child.example.local

:: GoldenGMSA equivalents
GoldenGMSA.exe kdsinfo
GoldenGMSA.exe kdsinfo --guid KDS_ROOT_KEY_GUID
```
Rekodi GUID ya root-key na blob ya root-key ya base64. Export ya registry `SECURITY`/`SYSTEM` hive si root key ya KDS yenyewe: material halisi iko kwenye AD Configuration partition.<sup>[[1]](#references)[[2]](#references)</sup>

### Phase 2 - Orodhesha objects za gMSA / dMSA

Kwa gMSA, pata `sAMAccountName`, `objectSid`, na `msDS-ManagedPasswordId` ya binary. Hii ya mwisho kwa kawaida inaweza kusomeka hata wakati caller haruhusiwi kupata `msDS-ManagedPassword`.<sup>[[2]](#references)</sup>
```powershell
Get-ADServiceAccount -Filter * -Properties objectSid,msDS-ManagedPasswordId |
Select-Object sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo --domain example.local
```
ACL chaguomsingi ya dMSA inaweza kuzuia LDAP enumeration kwa watumiaji wenye privileges ndogo. `GoldenDMSA info` inaweza ama ku-query LDAP au ku-enumerate RIDs zinazowezekana na kutatua SIDs kupitia `LsaLookupSids` kwenye `\PIPE\lsarpc`, kisha kutofautisha dMSAs na akaunti za computer pamoja na gMSAs.<sup>[[1]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe info -d example.local -m ldap
GoldendMSA.exe info -d example.local -m brute -u alice -p PASSWORD -o EXAMPLE -r 5000
```
### Awamu ya 3 - Reconstruct or guess `msDS-ManagedPasswordId`

Kitambulisho muhimu kinajumuisha `L0Index`, `L1Index`, na `L2Index`, si timestamp ya kuundwa kwa akaunti ikifuatiwa na bits za random. Semperis iligundua kuwa njia ya kutengeneza password haitumii candidate `L0Index`, huku `L1Index` na `L2Index` kila moja ikiwa na kikomo cha thamani `0..31`. Kwa sababu hiyo, attacker anayejua GUID ya root-key, domain, forest, na SID anaweza kuunda vitambulisho vyote `32 * 32 = 1,024` vya candidate.<sup>[[1]](#references)</sup>
```cmd
:: Write 1,024 base64 ManagedPasswordId candidates to KDS_ROOT_KEY_GUID.txt
GoldendMSA.exe wordlist -s DMSA_SID -d example.local -f example.local -k KDS_ROOT_KEY_GUID

:: Derive and validate candidates; -t caches the successful TGT
GoldendMSA.exe bruteforce -s DMSA_SID -i KDS_ROOT_KEY_GUID -k KDS_ROOT_KEY_BASE64 -d example.local -u svc_dmsa$ -t
```
Derivations hufanyika offline, lakini kutambua candidate aliye live kwa kawaida huhitaji majaribio ya authentication. Hii inaweza kusababisha mlipuko wa failed Kerberos pre-authentication au NTLM validation kabla ya key sahihi kupatikana. Kwa AES Kerberos keys, salt ya managed-account inayotumiwa na tool ni `UPPERCASE.DNS.DOMAIN` + `host` + UPN ya account yenye herufi ndogo bila `$` ya mwisho (kwa mfano, `EXAMPLE.LOCALhostsvc_dmsa.example.local`).<sup>[[1]](#references)</sup>

### Awamu ya 4 - Kokotoa na utumie password

Ikiwa identifier kamili inajulikana, kokotoa password buffer ya baiti 256 na uibadilishe kuwa NTLM/AES material. Thamani ya base64 inayochapishwa na tools hizi ni password buffer iliyowekwa encoding, **si LDAP `MSDS-MANAGEDPASSWORD_BLOB` yenyewe**.<sup>[[2]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe compute -s ACCOUNT_SID -k KDS_ROOT_KEY_BASE64 -d example.local -m MANAGED_PASSWORD_ID_BASE64
GoldendMSA.exe convert -d example.local -u svc_account$ -p BASE64_PASSWORD

GoldenGMSA.exe compute --sid ACCOUNT_SID --kdskey KDS_ROOT_KEY_BASE64 --pwdid MANAGED_PASSWORD_ID_BASE64
```
Matokeo ya NTLM yanaweza kutumika pale ambapo NTLM inakubaliwa; AES key inaweza kutumika kwa overpass-the-hash / TGT requests pale ambapo managed account ni AES-only. Hii inatoa privileges, SPNs, delegation configuration, na resource access za managed service account iliyoathiriwa bila kuongeza mashine ya mshambuliaji kwenye `PrincipalsAllowedToRetrieveManagedPassword`.<sup>[[1]](#references)[[2]](#references)</sup>

### Unyanyasaji wa Configuration-partition wa cross-domain

KDS root-key objects huishi katika forest Configuration naming context, ambayo inasambazwa kwa DCs zilizo kwenye child domains. Kwa sababu hiyo, `SYSTEM` kwenye child-domain DC inaweza kusoma forest-root KDS material kutoka kwenye local replica ya child DC, ingawa child Domain Admins hawawezi kusoma object hiyo moja kwa moja kutoka forest-root DC. Ikiwa mshambuliaji anaweza pia kusoma `msDS-ManagedPasswordId` ya parent-domain gMSA, GoldenGMSA inaweza kukokotoa password ya account hiyo ya parent; SID filtering haizuii shambulio hili la cryptographic.<sup>[[5]](#references)</sup>
```cmd
:: Run as SYSTEM on a child.example.local DC
GoldenGMSA.exe kdsinfo --forest child.example.local

:: Query target metadata in the parent, then combine both inputs
GoldenGMSA.exe gmsainfo --domain example.local
GoldenGMSA.exe compute --sid PARENT_GMSA_SID --domain example.local --forest child.example.local
```
## Utambuzi, Udhibiti na Urejeshaji

* Sanidi SACL kwenye container ya **Master Root Keys**, ikirithiwa na objects za `msKds-ProvRootKey`, kwa ajili ya usomaji uliofanikiwa wa `msKds-RootKeyData`. Directory Service Access auditing ikiwa imewezeshwa, online extraction huzalisha Security event **4662**; chunguza subjects ambao si DCs wanaotarajiwa au waendeshaji wa Tier-0. Pia kagua mabadiliko kwenye SACL hizi na ACLs za root-key objects.<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>
* Shambulio la child-to-parent husoma KDS object kutoka local replica ya DC ya child iliyoathiriwa, kwa hiyo forest-root domain huenda isione usomaji huo. Kwenye parent domain, kagua usomaji uliofanikiwa wa `msDS-ManagedPasswordId` (schema GUID `0e78295a-c6d3-0a40-b491-d62251ffa0a6`) kwenye objects za `msDS-GroupManagedServiceAccount` na chunguza usomaji unaofanywa na principals kutoka domain nyingine.<sup>[[5]](#references)</sup>
* Linganisha ufikiaji wa KDS-object na logons zisizo za kawaida za managed accounts, pamoja na mfululizo wa kushindwa kwa Kerberos/NTLM kwa service accounts zinazoishia na `$`. Offline computation baada ya database/backup theft ya awali haionekani na live DC.<sup>[[1]](#references)[[3]](#references)</sup>
* Password rotation ya kawaida haitoshi baada ya root-key exposure. Utaratibu wa sasa wa Microsoft wa recovery huunda KDS root key mpya, huanzisha upya KDS kwenye DCs zote husika, na huhamisha accounts zilizoathiriwa kwenye key hiyo. Ikiwa scope/time ya exposure haijulikani na kusubiri safe roll hakukubaliki, badilisha kila gMSA iliyotumia key iliyoathiriwa; ikiwa scope inajulikana, Microsoft inaandika authoritative-restore workflow ya kulazimisha safe rolling. Thibitisha GUID ya key mpya kwenye `msDS-ManagedPasswordId` kabla ya kufuta key ya zamani.<sup>[[4]](#references)</sup>
* Chukulia ufikiaji wa DC database na backups, Configuration-partition replication, na usimamizi wa KDS root-key kuwa Tier-0. Kupunguza `ManagedPasswordIntervalInDays` hupunguza baadhi ya recovery windows, lakini hakubatilishi root key ambayo tayari imecompromise.<sup>[[4]](#references)</sup>

## Zana

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) - dMSA/gMSA enumeration, utengenezaji wa identifiers, uthibitishaji wa candidates 1,024, password computation, na ubadilishaji wa NTLM/AES.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) - gMSA/KDS enumeration na password computation ya online, offline, na cross-domain.<sup>[[2]](#references)</sup>
* [`Rubeus`](https://github.com/GhostPack/Rubeus) na [`Impacket`](https://github.com/fortra/impacket) - tumia au thibitisha derived NTLM/AES keys katika authorised testing.



## References

- [1] [Golden dMSA - authentication bypass for Delegated Managed Service Accounts](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [gMSA Active Directory Attacks](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Semperis/GoldenDMSA GitHub repository](https://github.com/Semperis/GoldenDMSA)
- [4] [Microsoft - Jinsi ya kurecover kutoka kwenye Golden gMSA attack](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/recover-from-golden-gmsa-attack)
- [5] [SID filter as security boundary between domains? Part 5 - Golden gMSA trust attack](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
{{#include ../../banners/hacktricks-training.md}}
