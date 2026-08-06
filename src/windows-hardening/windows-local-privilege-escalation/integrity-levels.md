# Viwango vya Uadilifu

{{#include ../../banners/hacktricks-training.md}}

## Viwango vya Uadilifu

Katika Windows Vista na matoleo ya baadaye, vipengee vyote vilivyolindwa huja na tag ya **kiwango cha uadilifu**. Mpangilio huu kwa kawaida huweka kiwango cha uadilifu cha "medium" kwa files na registry keys, isipokuwa folders na files fulani ambazo Internet Explorer 7 inaweza kuandikia katika kiwango cha low cha uadilifu. Tabia chaguomsingi ni kwamba processes zinazoanzishwa na standard users ziwe na kiwango cha medium cha uadilifu, huku services kwa kawaida zikiendesha katika kiwango cha system cha uadilifu. Label ya high-integrity hulinda root directory.

Kanuni muhimu ni kwamba objects haziwezi kurekebishwa na processes zilizo na kiwango cha chini cha uadilifu kuliko kiwango cha object hiyo. Viwango vya uadilifu ni:

- **Untrusted**: Kiwango hiki ni cha processes zilizo na anonymous logins. Mfano: Chrome
- **Low**: Hutumika hasa kwa maingiliano ya internet, haswa katika Protected Mode ya Internet Explorer, na huathiri files na processes zinazohusiana, pamoja na folders fulani kama **Temporary Internet Folder**. Low integrity processes hukabiliwa na vizuizi vikubwa, ikiwemo kutokuwa na uwezo wa kuandika kwenye registry na kuwa na uwezo mdogo wa kuandika kwenye user profile.
- **Medium**: Kiwango chaguomsingi kwa shughuli nyingi, hupewa standard users na objects zisizo na viwango maalum vya uadilifu. Hata members wa Administrators group huendesha katika kiwango hiki kwa chaguomsingi.
- **High**: Kimehifadhiwa kwa administrators, na kuwawezesha kurekebisha objects zilizo katika viwango vya chini vya uadilifu, pamoja na zile zilizo katika kiwango cha high chenyewe.
- **System**: Kiwango cha juu zaidi cha uendeshaji kwa Windows kernel na core services, ambacho hata administrators hawawezi kufikia, hivyo kuhakikisha ulinzi wa system functions muhimu.
- **Installer**: Kiwango cha kipekee kinachozidi viwango vingine vyote, na kuwezesha objects zilizo katika kiwango hiki ku-uninstall object nyingine yoyote.

Unaweza kupata kiwango cha uadilifu cha process kwa kutumia **Process Explorer** kutoka **Sysinternals**, kwa kufungua **properties** za process na kuangalia tab ya "**Security**":

![Viwango vya Uadilifu - Viwango vya Uadilifu: Unaweza kupata kiwango cha uadilifu cha process kwa kutumia Process Explorer kutoka Sysinternals, kwa kufungua properties za process na kuangalia tab ya "...](<../../images/image (824).png>)

Pia unaweza kupata **kiwango chako cha sasa cha uadilifu** kwa kutumia `whoami /groups`

![Viwango vya Uadilifu - Viwango vya Uadilifu: Pia unaweza kupata kiwango chako cha sasa cha uadilifu kwa kutumia whoami /groups](<../../images/image (325).png>)

### Viwango vya Uadilifu katika File-system

Object iliyo ndani ya file-system inaweza kuhitaji **minimum integrity level requirement**, na ikiwa process haina kiwango hiki cha uadilifu, haitaweza kuingiliana nayo.\
Kwa mfano, **create regular file from a regular user console and check the permissions**:
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
Sasa, hebu tuteue kiwango cha chini cha integrity cha **High** kwa file. Hili **lazima lifanywe kutoka kwenye console** inayotumika kama **administrator**, kwa sababu **console ya kawaida** itakuwa ikitumia kiwango cha Medium Integrity na **haitaruhusiwa** kuteua kiwango cha High Integrity kwa object:
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
Hapa ndipo mambo yanapovutia. Unaweza kuona kwamba mtumiaji `DESKTOP-IDJHTKP\user` ana **FULL privileges** juu ya faili (kwa hakika, huyu ndiye mtumiaji aliyeunda faili), hata hivyo, kutokana na minimum integrity level iliyotekelezwa, hataweza tena kurekebisha faili isipokuwa anaendesha ndani ya High Integrity Level (kumbuka kwamba ataweza kuisoma):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **Kwa hivyo, faili inapokuwa na kiwango cha chini kabisa cha integrity, ili kuirekebisha unahitaji kuwa unaendesha angalau katika kiwango hicho cha integrity.**

### Integrity Levels in Binaries

Nilitengeneza nakala ya `cmd.exe` katika `C:\Windows\System32\cmd-low.exe` na nikaiwekea **kiwango cha integrity cha low kutoka kwenye administrator console:**
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

Kwa watu wenye udadisi, ukiweka kiwango cha uadilifu cha juu kwenye binary (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) haitaendeshwa kiotomatiki kwa kiwango cha uadilifu cha juu (ukiianzisha kutoka kwenye kiwango cha uadilifu cha kati --kwa chaguo-msingi-- itaendeshwa chini ya kiwango cha uadilifu cha kati).

### Viwango vya Uadilifu katika Processes

Si faili na folda zote zilizo na kiwango cha chini cha uadilifu, **lakini processes zote zinaendeshwa chini ya kiwango fulani cha uadilifu**. Na kama ilivyotokea kwenye mfumo wa faili, **ikiwa process inataka kuandika ndani ya process nyingine, lazima iwe na angalau kiwango sawa cha uadilifu**. Hii inamaanisha kuwa process yenye kiwango cha chini cha uadilifu haiwezi kufungua handle yenye ufikiaji kamili kwa process yenye kiwango cha kati cha uadilifu.

Kwa sababu ya vikwazo vilivyoelezwa katika sehemu hii na iliyotangulia, kwa mtazamo wa usalama, daima **inapendekezwa kuendesha process katika kiwango cha chini kabisa cha uadilifu kinachowezekana**.

{{#include ../../banners/hacktricks-training.md}}
