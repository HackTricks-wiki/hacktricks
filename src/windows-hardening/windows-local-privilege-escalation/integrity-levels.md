# Viwango vya Uadilifu

{{#include ../../banners/hacktricks-training.md}}

## Viwango vya Uadilifu

Katika Windows Vista na matoleo ya baadaye, objects zinazoweza kulindwa zinaweza kuwa na lebo ya **integrity level**. Objects nyingi huchukuliwa kuwa na medium integrity, huku maeneo maalum yaliyokusudiwa kwa applications zenye low integrity yakiweza kuwekewa lebo ya low. Processes zinazoanzishwa na standard users kwa kawaida huendesha kwa medium integrity, applications zilizoinuliwa huendesha kwa high integrity, na services nyingi huendesha kwa system integrity.<sup>[[1]](#references)</sup>

Kanuni muhimu ni kwamba objects haziwezi kurekebishwa na processes zilizo na integrity level ya chini kuliko level ya object hiyo. Windows hutumia ukaguzi huu wa Mandatory Integrity Control (MIC) kabla ya kutathmini discretionary access control list (DACL) ya object. Viwango vinavyokumbana navyo mara nyingi ni:<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: Kiwango cha chini kabisa, kinachowakilishwa na `SECURITY_MANDATORY_UNTRUSTED_RID`. Kwa mfano wa matumizi halisi, Windows sandbox ya Chromium huanza kwa kuzipa targets zilizowekwa sandbox Low integrity, kisha hushusha renderer targets hadi Untrusted integrity baada ya startup.<sup>[[5]](#references)</sup>
- **Low**: Hutumika hasa kwa mwingiliano wa internet, haswa katika Protected Mode ya Internet Explorer, ikiathiri files na processes zinazohusiana, pamoja na folders fulani kama **Temporary Internet Folder**. Processes zenye low integrity hukabiliwa na vizuizi vikubwa, ikiwa ni pamoja na kutokuwa na uwezo wa kuandika kwenye registry na kuwa na uwezo mdogo wa kuandika kwenye user profile.
- **Medium**: Kiwango chaguo-msingi kwa shughuli nyingi, kinachopewa standard users na objects zisizo na integrity levels maalum. Hata members wa Administrators group huendesha katika kiwango hiki kwa default.
- **High**: Kimehifadhiwa kwa administrators, kikiwawezesha kurekebisha objects zilizo katika integrity levels za chini, ikiwa ni pamoja na objects zilizo katika high level yenyewe.
- **System**: Kiwango cha juu zaidi cha uendeshaji kwa Windows kernel na core services, ambacho hata administrators hawawezi kufikia, kikihakikisha ulinzi wa system functions muhimu.

Windows pia hufafanua protected-process integrity value iliyo juu ya System. Hata hivyo, **TrustedInstaller** ni Windows service identity badala ya kuwa MIC level tofauti; uwezo wake wa kurekebisha protected operating-system resources unatokana na permissions zilizopewa identity hiyo.

Unaweza kupata integrity level ya process kwa kutumia **Process Explorer** kutoka **Sysinternals** kwa kufungua process properties na kutazama **Security** tab:<sup>[[3]](#references)</sup>

![Integrity Levels - Integrity Levels: Unaweza kupata integrity level ya process kwa kutumia Process Explorer kutoka Sysinternals, kwa kufikia properties za process na kutazama "...](<../../images/image (824).png>)

Pia unaweza kupata **current integrity level** yako kwa kutumia `whoami /groups`:

![Integrity Levels - Integrity Levels: Pia unaweza kupata current integrity level yako kwa kutumia whoami /groups](<../../images/image (325).png>)

### Integrity Levels katika File System

Object katika file system inaweza kuwa na **minimum integrity-level requirement**. Process iliyo chini ya level hiyo iko chini ya mandatory policy ya object hata wakati DACL yake ingeiruhusu access. Kwa mfano, tengeneza file ya kawaida kutoka kwenye standard-user console na ukague permissions zake:<sup>[[1]](#references)[[4]](#references)</sup>
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
Sasa, weka kiwango cha chini cha integrity cha **High** kwa faili. Hili **lazima lifanywe kutoka kwenye console** inayoendeshwa kama **administrator**, kwa sababu console ya kawaida huendeshwa kwenye integrity ya Medium na **haitaruhusiwa** kugawa integrity ya High kwa object:
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
Mtumiaji `DESKTOP-IDJHTKP\user` ana **ruhusa za FULL** juu ya faili kwa sababu ndiye aliyeiunda. Hata hivyo, lebo ya lazima inamzuia mtumiaji kurekebisha faili isipokuwa mchakato unaendeshwa katika kiwango cha High integrity. Mtumiaji bado anaweza kuisoma kwa sababu sera ya lazima iliyoonyeshwa ni `(NW)`, yaani no-write-up:
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **Kwa hivyo, faili inapokuwa na kiwango cha chini cha uadilifu, ili kuirekebisha unahitaji kuwa unaendesha angalau katika kiwango hicho cha uadilifu.**

### Viwango vya Uadilifu katika Binaries

Mfano ufuatao unatumia nakala ya `cmd.exe` katika `C:\Windows\System32\cmd-low.exe` na kuikabidhi **kiwango cha Low cha uadilifu kutoka kwenye console ya administrator**:
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Sasa, ninapoendesha `cmd-low.exe` itaendeshwa **ikiwa na kiwango cha uadilifu cha chini** badala ya cha wastani:

![Viwango vya Uadilifu katika Mfumo wa Faili - Viwango vya Uadilifu katika Binaries: Sasa, ninapoendesha cmd-low.exe itaendeshwa ikiwa na kiwango cha uadilifu cha chini badala ya cha wastani](<../../images/image (313).png>)

Kuweka lebo ya uadilifu wa Juu kwenye binary (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) hakufanyi iendeshwe ikiwa na uadilifu wa Juu kiotomatiki. Ikiitwa kutoka kwa mchakato wenye uadilifu wa Wastani, itaendeshwa ikiwa na uadilifu wa Wastani kwa sababu mchakato mpya hupokea kiwango cha chini kati ya viwango vya uadilifu vya faili inayotekelezwa na cha mwitaji.<sup>[[1]](#references)</sup>

### Viwango vya Uadilifu katika Michakato

Si faili na folda zote zilizo na lebo ya chini ya uadilifu iliyo wazi, **lakini kila mchakato huendeshwa katika kiwango fulani cha uadilifu**. Kama ilivyo kwa vipengee vya mfumo wa faili, **mchakato unaotaka kupata ufikiaji wa kuandika kwa mchakato mwingine lazima uwe na angalau kiwango sawa cha uadilifu**. Kwa hiyo, mchakato wenye uadilifu wa Chini hauwezi kufungua mchakato wenye uadilifu wa Wastani ukiwa na ufikiaji kamili.<sup>[[1]](#references)</sup>

Kwa sababu ya vizuizi hivi, njia salama zaidi ni **kuendesha kila mchakato katika kiwango cha chini zaidi cha uadilifu ambacho bado kinauwezesha kutekeleza kazi yake iliyokusudiwa**.

## References

- [1] [Microsoft Learn – Udhibiti wa Uadilifu wa Lazima](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – Hesabu ya MANDATORY_LEVEL](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [5] [Chanzo cha Chromium – Sera chaguomsingi ya uadilifu ya sandbox ya Windows](https://github.com/chromium/chromium/blob/main/sandbox/policy/win/sandbox_win.cc#L212-L216)
{{#include ../../banners/hacktricks-training.md}}
