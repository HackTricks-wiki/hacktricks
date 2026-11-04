# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

**BadSuccessor** hutumia vibaya mchakato wa uhamishaji wa **delegated Managed Service Account** (**dMSA**) ulioletwa katika **Windows Server 2025**. dMSA inaweza kuunganishwa na akaunti ya zamani kupitia **`msDS-ManagedAccountPrecededByLink`** na kupitishwa katika hali za uhamishaji zilizohifadhiwa kwenye **`msDS-DelegatedMSAState`**. Ikiwa mshambuliaji anaweza kuunda dMSA katika OU inayoweza kuandikwa na kudhibiti sifa hizo, KDC inaweza kutoa tiketi kwa dMSA inayodhibitiwa na mshambuliaji ikiwa na **muktadha wa uidhinishaji wa akaunti iliyounganishwa**.<sup>[[2]](#references)</sup>

Kwa vitendo, hii inamaanisha mtumiaji mwenye marupurupu madogo ambaye ana haki za OU zilizokasimiwa pekee anaweza kuunda dMSA mpya, kuiunganisha na `Administrator`, kukamilisha hali ya uhamishaji, kisha kupata TGT ambayo PAC yake ina vikundi vyenye marupurupu kama **Domain Admins**.<sup>[[2]](#references)</sup>

## Maelezo muhimu kuhusu uhamishaji wa dMSA

- dMSA ni kipengele cha **Windows Server 2025**.
- `Start-ADServiceAccountMigration` huweka uhamishaji katika hali ya **kuanza**.
- `Complete-ADServiceAccountMigration` huweka uhamishaji katika hali ya **kukamilika**.
- `msDS-DelegatedMSAState = 1` inamaanisha uhamishaji umeanza.
- `msDS-DelegatedMSAState = 2` inamaanisha uhamishaji umekamilika.
- Katika uhamishaji halali, dMSA inakusudiwa kuchukua nafasi ya akaunti iliyotangulia bila kuathiri utendaji, kwa hivyo KDC/LSA huhifadhi ufikiaji ambao akaunti ya awali tayari ilikuwa nao.<sup>[[3]](#references)</sup>

Microsoft Learn pia inabainisha kuwa wakati wa uhamishaji akaunti ya awali huunganishwa na dMSA, na dMSA inakusudiwa kufikia vitu ambavyo akaunti ya zamani ingeweza kufikia.<sup>[[3]](#references)</sup> Hili ndilo dhana ya usalama ambayo BadSuccessor hutumia vibaya.<sup>[[2]](#references)</sup>

## Mahitaji

1. Domain ambako **dMSA ipo**, kumaanisha upande wa AD unaauni **Windows Server 2025**.
2. Mshambuliaji anaweza **kuunda** vitu vya `msDS-DelegatedManagedServiceAccount` katika OU fulani, au ana haki pana sawa za kuunda vitu vya child hapo.
3. Mshambuliaji anaweza **kuandika** sifa husika za dMSA au kudhibiti kikamilifu dMSA aliyoiunda.
4. Mshambuliaji anaweza kuomba tiketi za Kerberos kutoka kwenye muktadha uliojiunga na domain au kupitia tunnel inayofikia LDAP/Kerberos.<sup>[[2]](#references)</sup>

### Ukaguzi wa vitendo

Ishara iliyo wazi zaidi kwa operator ni kuthibitisha kiwango cha domain/forest na kuhakikisha mazingira tayari yanatumia stack mpya ya Server 2025:

```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```

Ukiona thamani kama `Windows2025Domain` na `Windows2025Forest`, weka **BadSuccessor / dMSA migration abuse** kama ukaguzi wa kipaumbele.

Unaweza pia kuorodhesha OUs zinazoweza kuandikiwa na zilizokabidhiwa ruhusa za kuunda dMSA kwa kutumia zana za umma:<sup>[[1]](#references)</sup>

```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```

## Mtiririko wa matumizi mabaya

1. Unda dMSA katika OU ambapo una haki zilizokabidhiwa za kuunda child.
2. Weka **`msDS-ManagedAccountPrecededByLink`** kuwa DN ya lengo lenye haki za juu, kama vile `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Weka **`msDS-DelegatedMSAState`** kuwa `2` ili kuashiria kuwa uhamishaji umekamilika.
4. Omba TGT ya dMSA mpya na utumie ticket iliyorejeshwa kufikia huduma zenye haki za juu.<sup>[[2]](#references)</sup>

Mfano wa PowerShell:<sup>[[2]](#references)</sup>

```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
    msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```

Mifano ya maombi ya tiketi / zana za uendeshaji:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```

## Kwa nini hili ni zaidi ya kuongeza mamlaka

Wakati wa uhamishaji halali, Windows pia inahitaji dMSA mpya ishughulikie tiketi zilizotolewa kwa akaunti ya awali kabla ya cutover. Ndiyo maana nyenzo za tiketi zinazohusiana na dMSA zinaweza kujumuisha funguo **za sasa** na **za awali** katika mtiririko wa **`KERB-DMSA-KEY-PACKAGE`**.<sup>[[2]](#references)</sup>

Kwa uhamishaji bandia unaodhibitiwa na mshambuliaji, tabia hiyo inaweza kugeuza BadSuccessor kuwa:<sup>[[2]](#references)</sup>

- **Kuongeza mamlaka** kwa kurithi SID za vikundi vyenye mamlaka katika PAC.
- **Kufichua nyenzo za vitambulisho** kwa sababu ushughulikiaji wa funguo za awali unaweza kufichua nyenzo zinazolingana na hash ya RC4/NT ya mtangulizi katika mtiririko wa kazi ulio hatarini.

Hilo hufanya mbinu hii iwe muhimu kwa kutwaa domain moja kwa moja na kwa shughuli zinazofuata, kama vile pass-the-hash au kuhatarisha vitambulisho kwa upana zaidi.

## BetterSuccessor baada ya kiraka cha KDC

KDC iliyowekewa kiraka huthibitisha pande zote mbili za uhamishaji wa dMSA. Mbali na `msDS-ManagedAccountPrecededByLink` na hali ya uhamishaji ya dMSA, akaunti mtangulizi lazima iunganishe kurudi kwa dMSA kupitia `msDS-SupersededManagedAccountLink` na iwe na `msDS-SupersededServiceAccountState` inayolingana. Kiungo cha upande mmoja sasa hushindwa; akaunti inayoweza tu kuunda dMSA haiwezi kuteua mtangulizi yeyote kiholela. Ikiwa na `CreateChild` ya dMSA katika OU **na** ruhusa halisi za kuandika sifa za uhamishaji za akaunti lengwa iliyochaguliwa, mshambuliaji anaweza kuweka kiungo cha kurudishiana. Tiketi ya dMSA inayotokana na hilo inaweza kubeba muktadha wa idhini wa mtangulizi na kufichua funguo zake katika kifurushi cha funguo cha dMSA. Hii ni njia mahususi ya kupata vitambulisho/kuongeza mamlaka, si uthibitisho kwamba BadSuccessor ya awali ya kulenga akaunti yoyote kiholela bado inaweza kutumiwa kwenye DC zilizowekewa viraka.<sup>[[5]](#references)[[6]](#references)</sup>

Katika maabara ambako uwezo wa kuandika kwenye akaunti lengwa umethibitishwa, `bloodyAD` inaweza kuunda dMSA na kufanya maandishi mawili ya uhamishaji yanayolingana. Omba tiketi ya dMSA ukitumia nyenzo za Kerberos zilizorejeshwa, kisha uhakiki ruhusa halisi za akaunti lengwa kabla ya kudhani kwamba mamlaka au hash yake imepatikana. Jina la subcommand `badSuccessor` ya zana hiyo halimaanishi kuwa inatumia tabia ya upande mmoja ambayo haikuwa imewekewa kiraka.<sup>[[7]](#references)</sup>

```bash
KRB5CCNAME=operator.ccache bloodyAD -d example.local --host dc.example.local -k add badSuccessor test_dmsa --ou 'OU=DMSAHolder,DC=example,DC=local' -t 'CN=Target User,OU=Users,DC=example,DC=local'
```

## Maelezo kuhusu hali ya patch

Tabia ya awali ya BadSuccessor **si suala la kinadharia la toleo la onyesho la 2025 pekee**. Microsoft iliipa **CVE-2025-53779** na kuchapisha security update mnamo **Agosti 2025**.<sup>[[4]](#references)</sup> Endelea kuweka shambulio hili kwenye nyaraka kwa ajili ya:

- **labs / CTFs / mazoezi ya assume-breach**
- **mazingira ya Windows Server 2025 ambayo hayajawekewa patch**
- **uthibitishaji wa delegations za OU na uwezekano wa kufichuliwa kwa dMSA wakati wa tathmini**

Usidhani kuwa domain ya Windows Server 2025 inaweza kushambuliwa kwa sababu tu dMSA ipo; thibitisha kiwango cha patch na ujaribu kwa uangalifu.

## Tools

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [1] [HTB: Eighteen - Matumizi mabaya ya dMSA ya BadSuccessor ili kupata Domain Admin (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor: Kutumia vibaya dMSA ili kuongeza mamlaka katika Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Muhtasari wa Delegated Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
- [5] [Akamai - BadSuccessor Imekufa, Aishi BadSuccessor(?)](https://www.akamai.com/blog/security-research/badsuccessor-is-dead-analyzing-badsuccessor-patch)
- [6] [Altered Security - BetterSuccessor: Bado kutumia vibaya dMSA baada ya patch](https://www.alteredsecurity.com/post/bettersuccessor-still-abusing-dmsa-for-privilege-escalation-badsuccessor-after-patch)
- [7] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../../banners/hacktricks-training.md}}
