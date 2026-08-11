# Viwango vya Integrity

{{#include ../../banners/hacktricks-training.md}}

## Viwango vya Integrity

Katika Windows Vista na matoleo ya baadaye, objects zinazoweza kulindwa zinaweza kuwa na label ya **integrity level**. Objects nyingi huchukuliwa kuwa na medium integrity, huku maeneo maalum yaliyokusudiwa kwa applications zenye low integrity yakiweza kuwekewa lebo ya low. Processes zinazoanzishwa na standard users kwa kawaida huendeshwa kwa medium integrity, applications zilizoinuliwa huendeshwa kwa high integrity, na services nyingi huendeshwa kwa system integrity.<sup>[[1]](#references)</sup>

Kanuni muhimu ni kwamba objects haziwezi kubadilishwa na processes zenye integrity level ya chini kuliko level ya object hiyo. Windows hutumia ukaguzi huu wa Mandatory Integrity Control (MIC) kabla ya kutathmini discretionary access control list (DACL) ya object. Levels zinazopatikana mara nyingi ni:<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: Level ya chini kabisa, inayowakilishwa na `SECURITY_MANDATORY_UNTRUSTED_RID` (`S-1-16-0`). Usichanganye integrity label hii na identity ya **Anonymous Logon** (`S-1-5-7`); authentication identities na MIC labels ni namespaces tofauti za SID. Kwa mfano wa matumizi halisi, Chromium's Windows sandbox huanza kwa kupeana sandboxed targets Low integrity, kisha hushusha renderer targets hadi Untrusted integrity baada ya startup.<sup>[[5]](#references)[[6]](#references)</sup>
- **Low**: Hutumika hasa kwa interactions za internet, hasa katika Internet Explorer's Protected Mode, ikiathiri files na processes zinazohusiana, pamoja na folders fulani kama **Temporary Internet Folder**. Low integrity processes hukabiliwa na restrictions kubwa, zikiwemo kutokuwa na registry write access na user profile write access yenye mipaka.
- **Medium**: Level ya default kwa activities nyingi, inayotolewa kwa standard users na objects zisizo na integrity levels maalum. Hata members wa Administrators group huendesha kwa level hii kwa default.
- **High**: Imetengwa kwa administrators, ikiwawezesha kubadilisha objects zilizo katika integrity levels za chini, pamoja na zile zilizo kwenye high level yenyewe.
- **System**: Level ya juu zaidi ya uendeshaji kwa Windows kernel na core services, ambayo haiwezi kufikiwa hata na administrators, hivyo kuhakikisha ulinzi wa system functions muhimu.

Windows pia hufafanua protected-process integrity value iliyo juu ya System. Hata hivyo, **TrustedInstaller** ni Windows service identity badala ya MIC level tofauti; uwezo wake wa kubadilisha protected operating-system resources unatokana na permissions zilizopewa identity hiyo.

Usidhani kwamba location kama root ya system drive huwa na High integrity label isiyobadilika. Kagua effective DACL na mandatory label yoyote iliyo wazi kwa kutumia `icacls`; object isiyo na label huchukuliwa kuwa Medium kwa MIC, huku DACL na ownership yake zikiendelea kuzuia access kwa kujitegemea.<sup>[[1]](#references)[[4]](#references)</sup>

Unaweza kupata integrity level ya process ukitumia **Process Explorer** kutoka **Sysinternals** kwa kufungua process properties na kuangalia **Security** tab:<sup>[[3]](#references)</sup>

![Integrity Levels - Integrity Levels: Unaweza kupata integrity level ya process ukitumia Process Explorer kutoka Sysinternals, kwa kufikia properties za process na kuangalia "...](<../../images/image (824).png>)

Unaweza pia kupata **current integrity level** yako kwa kutumia `whoami /groups`:

![Integrity Levels - Integrity Levels: Unaweza pia kupata current integrity level yako ukitumia whoami /groups](<../../images/image (325).png>)

### Integrity Levels katika File System

Object katika file system inaweza kuwa na **minimum integrity-level requirement**. Process iliyo chini ya level hiyo inakabiliwa na mandatory policy ya object hata wakati DACL yake ingeipa access vinginevyo. Kwa mfano, tengeneza regular file kutoka standard-user console na ukague permissions zake:<sup>[[1]](#references)[[4]](#references)</sup>
```
echo asd >asd.txt
icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
```
Sasa, weka kiwango cha chini cha integrity cha **High** kwenye faili. Hili **lazima lifanywe kutoka kwenye console** inayoendeshwa kama **administrator**, kwa sababu console ya kawaida huendeshwa katika integrity ya Medium na **haitaruhusiwa** kuweka integrity ya High kwenye object:
```
icacls asd.txt /setintegritylevel(oi)(ci) High
processed file: asd.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
Mandatory Label\High Mandatory Level:(NW)
```
Mtumiaji `DESKTOP-IDJHTKP\user` ana **ruhusa KAMILI** juu ya faili kwa sababu mtumiaji huyo ndiye aliyeiunda. Hata hivyo, mandatory label inamzuia mtumiaji kurekebisha faili isipokuwa mchakato unaendesha katika kiwango cha High integrity. Mtumiaji bado anaweza kuisoma kwa sababu sera ya mandatory iliyoonyeshwa ni `(NW)`, au no-write-up:
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **Kwa hivyo, faili inapokuwa na minimum integrity level, ili kuirekebisha unahitaji kuwa unaendesha angalau katika integrity level hiyo.**

### Integrity Levels katika Binaries

Mfano ufuatao unatumia nakala ya `cmd.exe` katika `C:\Windows\System32\cmd-low.exe` na kuipa **Low integrity level kutoka kwenye administrator console**:
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Sasa, ninapoendesha `cmd-low.exe`, itaendeshwa **chini ya kiwango cha uadilifu cha chini** badala ya cha wastani:

![Viwango vya Uadilifu katika Mfumo wa Faili - Viwango vya Uadilifu katika Binaries: Sasa, ninapoendesha cmd-low.exe, itaendeshwa chini ya kiwango cha uadilifu cha chini badala ya cha wastani](<../../images/image (313).png>)

Kuweka lebo ya uadilifu wa Juu kwenye binary (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) hakufanyi binary hiyo iendeshwe kiotomatiki kwa uadilifu wa Juu. Ikiitwa kutoka kwa process yenye uadilifu wa Wastani, itaendeshwa kwa uadilifu wa Wastani kwa sababu process mpya hupokea kiwango cha chini zaidi kati ya kiwango cha uadilifu cha faili inayotekelezwa na cha mwitaji.<sup>[[1]](#references)</sup>

### Viwango vya Uadilifu katika Processes

Si faili na folda zote zilizo na lebo ya wazi ya kiwango cha chini cha uadilifu, **lakini kila process huendeshwa kwa kiwango fulani cha uadilifu**. Kama ilivyo kwa objects za mfumo wa faili, **process inayotaka kupata ruhusa ya kuandika kwenye process nyingine lazima iwe na angalau kiwango sawa cha uadilifu**. Kwa hivyo, process yenye uadilifu wa Chini haiwezi kufungua process yenye uadilifu wa Wastani ikiwa na ufikiaji kamili.<sup>[[1]](#references)</sup>

Kwa sababu ya vikwazo hivi, njia salama zaidi ni **kuendesha kila process kwa kiwango cha chini zaidi cha uadilifu kinachoiruhusu kutekeleza kazi iliyokusudiwa**.

## References

- [1] [Microsoft Learn – Udhibiti wa Lazima wa Uadilifu](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – Orodha ya MANDATORY_LEVEL](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [5] [Chromium source – Sera ya kawaida ya sandbox ya Windows ya uadilifu](https://github.com/chromium/chromium/blob/main/sandbox/policy/win/sandbox_win.cc#L212-L216)
- [6] [Microsoft Learn – SIDs zinazojulikana](https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids)
{{#include ../../banners/hacktricks-training.md}}
