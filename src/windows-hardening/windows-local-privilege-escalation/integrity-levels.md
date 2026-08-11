# Viwango vya Uadilifu

{{#include ../../banners/hacktricks-training.md}}

## Viwango vya Uadilifu

Katika Windows Vista na matoleo ya baadaye, vitu vinavyoweza kulindwa vinaweza kuwa na lebo ya **kiwango cha uadilifu**. Vitu vingi huchukuliwa kuwa na uadilifu wa kati, huku maeneo mahususi yaliyokusudiwa kwa applications zenye uadilifu wa chini yakiweza kuwekwa lebo ya chini. Processes zinazoanzishwa na watumiaji wa kawaida kwa kawaida huendeshwa kwa uadilifu wa kati, applications zilizoinuliwa huendeshwa kwa uadilifu wa juu, na services nyingi huendeshwa kwa uadilifu wa mfumo.<sup>[[1]](#references)</sup>

Kanuni muhimu ni kwamba vitu haviwezi kurekebishwa na processes zilizo na kiwango cha uadilifu cha chini kuliko kiwango cha kitu hicho. Windows hutumia ukaguzi huu wa Mandatory Integrity Control (MIC) kabla ya kutathmini discretionary access control list (DACL) ya kitu. Viwango vinavyokutana mara nyingi ni:<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: Kiwango cha chini kabisa, kinachowakilishwa na `SECURITY_MANDATORY_UNTRUSTED_RID`.
- **Low**: Hutumika hasa kwa interactions za mtandao, hususan katika Internet Explorer's Protected Mode, ikiathiri files na processes zinazohusiana, pamoja na folders fulani kama **Temporary Internet Folder**. Processes zenye uadilifu wa chini hukabiliwa na vizuizi vikubwa, ikiwemo kutokuwa na uwezo wa kuandika kwenye registry na uwezo mdogo wa kuandika kwenye user profile.
- **Medium**: Kiwango chaguo-msingi kwa shughuli nyingi, kinachotolewa kwa watumiaji wa kawaida na vitu visivyo na viwango mahususi vya uadilifu. Hata washiriki wa Administrators group huendesha kwa kiwango hiki kwa chaguo-msingi.
- **High**: Hutengwa kwa administrators, na kuwawezesha kurekebisha vitu vilivyo katika viwango vya chini vya uadilifu, ikiwemo vile vilivyo katika kiwango cha juu chenyewe.
- **System**: Kiwango cha juu zaidi cha uendeshaji kwa Windows kernel na core services, kisichofikiwa hata na administrators, na hivyo kuhakikisha ulinzi wa system functions muhimu.

Windows pia hufafanua thamani ya uadilifu ya protected-process iliyo juu ya System. Hata hivyo, **TrustedInstaller** ni utambulisho wa Windows service badala ya kuwa kiwango tofauti cha MIC; uwezo wake wa kurekebisha protected operating-system resources unatokana na permissions alizopewa utambulisho huo.

Unaweza kupata kiwango cha uadilifu cha process kwa kutumia **Process Explorer** kutoka **Sysinternals** kwa kufungua process properties na kuangalia kichupo cha **Security**:<sup>[[3]](#references)</sup>

![Viwango vya Uadilifu - Viwango vya Uadilifu: Unaweza kupata kiwango cha uadilifu cha process kwa kutumia Process Explorer kutoka Sysinternals, kwa kufikia properties za process na kuangalia "...](<../../images/image (824).png>)

Unaweza pia kupata **kiwango chako cha sasa cha uadilifu** kwa kutumia `whoami /groups`:

![Viwango vya Uadilifu - Viwango vya Uadilifu: Unaweza pia kupata kiwango chako cha sasa cha uadilifu kwa kutumia whoami /groups](<../../images/image (325).png>)

### Viwango vya Uadilifu katika File System

Kitu katika file system kinaweza kuwa na **sharti la chini la kiwango cha uadilifu**. Process iliyo chini ya kiwango hicho inakabiliwa na mandatory policy ya kitu hicho hata wakati DACL yake ingeidhinisha access. Kwa mfano, tengeneza file la kawaida kutoka kwenye console ya standard-user na ukague permissions zake:<sup>[[1]](#references)[[4]](#references)</sup>
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
Sasa, weka kiwango cha chini cha integrity cha **High** kwenye faili. Hili **lazima lifanywe kutoka kwenye console** inayoendeshwa kama **administrator**, kwa sababu console ya kawaida huendeshwa katika integrity ya Medium na **haitaruhusiwa** kukabidhi integrity ya High kwa object:
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
Mtumiaji `DESKTOP-IDJHTKP\user` ana **FULL privileges** juu ya faili kwa sababu ndiye aliyeiunda. Hata hivyo, mandatory label inamzuia mtumiaji kurekebisha faili isipokuwa mchakato unaendeshwa katika High integrity. Mtumiaji bado anaweza kuisoma kwa sababu mandatory policy iliyoonyeshwa ni `(NW)`, au no-write-up:
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **Kwa hiyo, faili inapokuwa na minimum integrity level, ili kuirekebisha lazima uwe unaendesha angalau katika integrity level hiyo.**

### Integrity Levels katika Binaries

Mfano ufuatao unatumia nakala ya `cmd.exe` katika `C:\Windows\System32\cmd-low.exe` na kuikabidhi **Low integrity level kutoka kwa administrator console**:
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Sasa, ninapoendesha `cmd-low.exe` itaendeshwa **chini ya kiwango cha uadilifu cha chini** badala ya cha kati:

![Viwango vya Uadilifu katika Mfumo wa Faili - Viwango vya Uadilifu katika Binaries: Sasa, ninapoendesha cmd-low.exe itaendeshwa chini ya kiwango cha uadilifu cha chini badala ya cha kati](<../../images/image (313).png>)

Kuweka lebo ya uadilifu ya High kwenye binary (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) hakufanyi iendeshwe katika uadilifu wa High kiotomatiki. Ikiitwa kutoka kwa mchakato wenye uadilifu wa Medium, itaendeshwa kwa uadilifu wa Medium kwa sababu mchakato mpya hupokea kiwango cha chini kati ya viwango vya uadilifu vya faili inayotekelezwa na cha mchakato anayeiita.<sup>[[1]](#references)</sup>

### Viwango vya Uadilifu katika Michakato

Si faili na folda zote zilizo na lebo ya chini ya uadilifu iliyo wazi, **lakini kila mchakato huendeshwa katika kiwango fulani cha uadilifu**. Kama ilivyo kwa vitu vya mfumo wa faili, **mchakato unaotaka kupata ruhusa ya kuandika kwenye mchakato mwingine lazima uwe na angalau kiwango sawa cha uadilifu**. Kwa hiyo, mchakato wenye uadilifu wa Low hauwezi kufungua mchakato wenye uadilifu wa Medium kwa ufikiaji kamili.<sup>[[1]](#references)</sup>

Kwa sababu ya vizuizi hivi, njia salama zaidi ni **kuendesha kila mchakato katika kiwango cha chini kabisa cha uadilifu kinachouwezesha kutekeleza kazi iliyokusudiwa**.

## References

- [1] [Microsoft Learn – Udhibiti wa Uadilifu wa Lazima](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – Uorodheshaji wa MANDATORY_LEVEL](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
{{#include ../../banners/hacktricks-training.md}}
