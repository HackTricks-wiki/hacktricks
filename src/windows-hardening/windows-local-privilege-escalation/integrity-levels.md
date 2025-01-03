# Integrity Levels

{{#include ../../banners/hacktricks-training.md}}

## Integrity Levels

Katika Windows Vista na toleo la baadaye, vitu vyote vilivyolindwa vinakuja na lebo ya **kiwango cha uaminifu**. Mpangilio huu kwa kawaida unatoa kiwango cha "kati" cha uaminifu kwa faili na funguo za rejista, isipokuwa kwa folda na faili fulani ambazo Internet Explorer 7 inaweza kuandika kwa kiwango cha chini cha uaminifu. Tabia ya kawaida ni kwamba michakato inayozinduliwa na watumiaji wa kawaida ina kiwango cha kati cha uaminifu, wakati huduma kwa kawaida hufanya kazi kwa kiwango cha uaminifu wa mfumo. Lebo ya uaminifu wa juu inalinda saraka ya mzizi.

Kanuni muhimu ni kwamba vitu haviwezi kubadilishwa na michakato yenye kiwango cha chini cha uaminifu kuliko kiwango cha kitu. Viwango vya uaminifu ni:

- **Untrusted**: Kiwango hiki ni kwa michakato yenye kuingia kwa siri. %%%Mfano: Chrome%%%
- **Low**: Kimsingi kwa mwingiliano wa mtandao, hasa katika Modu ya Kulinda ya Internet Explorer, ikihusisha faili na michakato zinazohusiana, na folda fulani kama **Folda ya Mtandao ya Muda**. Michakato ya uaminifu wa chini inakabiliwa na vizuizi vikubwa, ikiwa ni pamoja na kukosa ufikiaji wa kuandika rejista na ufikiaji mdogo wa kuandika wasifu wa mtumiaji.
- **Medium**: Kiwango cha kawaida kwa shughuli nyingi, kinachotolewa kwa watumiaji wa kawaida na vitu bila viwango maalum vya uaminifu. Hata wanachama wa kundi la Wasimamizi hufanya kazi kwa kiwango hiki kwa kawaida.
- **High**: Imehifadhiwa kwa wasimamizi, ikiwaruhusu kubadilisha vitu kwa viwango vya chini vya uaminifu, ikiwa ni pamoja na vile vya kiwango cha juu mwenyewe.
- **System**: Kiwango cha juu zaidi cha uendeshaji kwa kernel ya Windows na huduma za msingi, ambacho hakiwezi kufikiwa hata na wasimamizi, kuhakikisha ulinzi wa kazi muhimu za mfumo.
- **Installer**: Kiwango cha kipekee ambacho kiko juu ya vingine vyote, kikiruhusu vitu vilivyo katika kiwango hiki kuondoa kitu kingine chochote.

Unaweza kupata kiwango cha uaminifu cha mchakato kwa kutumia **Process Explorer** kutoka **Sysinternals**, ukifikia **mali** ya mchakato na kuangalia kichupo cha "**Usalama**":

![](<../../images/image (824).png>)

Unaweza pia kupata **kiwango chako cha uaminifu cha sasa** kwa kutumia `whoami /groups`

![](<../../images/image (325).png>)

### Integrity Levels in File-system

Kitu ndani ya mfumo wa faili kinaweza kuhitaji **mahitaji ya kiwango cha chini cha uaminifu** na ikiwa mchakato huna mchakato huu wa uaminifu hautaweza kuingiliana nacho.\
Kwa mfano, hebu **tufanye faili ya kawaida kutoka kwa konsole ya mtumiaji wa kawaida na kuangalia ruhusa**:
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
Sasa, hebu tuweke kiwango cha chini cha uaminifu cha **Juu** kwa faili. Hii **lazima ifanywe kutoka kwenye konso** inayotembea kama **meneja** kwani **konso ya kawaida** itakuwa ikitembea katika kiwango cha Uaminifu wa Kati na **haitaruhusiwa** kuweka kiwango cha Juu cha Uaminifu kwa kitu:
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
Hapa ndipo mambo yanakuwa ya kuvutia. Unaweza kuona kwamba mtumiaji `DESKTOP-IDJHTKP\user` ana **haki kamili** juu ya faili (kweli huyu ndiye mtumiaji aliyeunda faili), hata hivyo, kutokana na kiwango cha chini cha uaminifu kilichotekelezwa hatoweza kubadilisha faili tena isipokuwa anapokuwa akifanya kazi ndani ya Kiwango cha Juu cha Uaminifu (zingatia kwamba ataweza kuisoma):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!NOTE]
> **Hivyo, wakati faili ina kiwango cha chini cha uaminifu, ili kuibadilisha unahitaji kuwa unafanya kazi angalau katika kiwango hicho cha uaminifu.**

### Viwango vya Uaminifu katika Binaries

Nimefanya nakala ya `cmd.exe` katika `C:\Windows\System32\cmd-low.exe` na kuweka kiwango chake cha **uaminifu kuwa wa chini kutoka kwa konsoli ya msimamizi:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Sasa, ninapokimbia `cmd-low.exe` itafanya **kazi chini ya kiwango cha chini cha uaminifu** badala ya kiwango cha kati:

![](<../../images/image (313).png>)

Kwa watu wenye hamu, ikiwa utaweka kiwango cha juu cha uaminifu kwa binary (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) haitafanya kazi kwa kiwango cha juu cha uaminifu kiotomatiki (ikiwa unakiita kutoka kiwango cha kati cha uaminifu --kwa default-- itafanya kazi chini ya kiwango cha kati cha uaminifu).

### Viwango vya Uaminifu katika Mchakato

Sio faili na folda zote zina kiwango cha chini cha uaminifu, **lakini mchakato wote unafanya kazi chini ya kiwango cha uaminifu**. Na sawa na kile kilichotokea na mfumo wa faili, **ikiwa mchakato unataka kuandika ndani ya mchakato mwingine lazima uwe na angalau kiwango sawa cha uaminifu**. Hii inamaanisha kwamba mchakato wenye kiwango cha chini cha uaminifu hauwezi kufungua kushughulikia kwa ufikiaji kamili kwa mchakato wenye kiwango cha kati cha uaminifu.

Kwa sababu ya vizuizi vilivyotajwa katika sehemu hii na sehemu iliyopita, kutoka kwa mtazamo wa usalama, kila wakati **inapendekezwa kufanya kazi katika kiwango cha chini cha uaminifu iwezekanavyo**.

{{#include ../../banners/hacktricks-training.md}}
