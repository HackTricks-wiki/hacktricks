# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

Ikiwa umeona kwamba unaweza **kuandika katika folda ya System Path** (kumbuka kwamba hii haitafanya kazi ikiwa unaweza kuandika katika folda ya User Path) inawezekana kwamba unaweza **kuinua mamlaka** katika mfumo.

Ili kufanya hivyo unaweza kutumia **Dll Hijacking** ambapo uta **hijack maktaba inayopakuliwa** na huduma au mchakato wenye **mamlaka zaidi** kuliko yako, na kwa sababu huduma hiyo inapakua Dll ambayo labda hata haipo katika mfumo mzima, itajaribu kuipakua kutoka System Path ambapo unaweza kuandika.

Kwa maelezo zaidi kuhusu **nini Dll Hijacking** angalia:

{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### Finding a missing Dll

Jambo la kwanza unahitaji ni **kubaini mchakato** unaotembea na **mamlaka zaidi** kuliko yako ambao unajaribu **kupakua Dll kutoka System Path** unayoweza kuandika.

Shida katika kesi hizi ni kwamba labda michakato hiyo tayari inatembea. Ili kupata ni Dll zipi zinakosekana huduma hizo unahitaji kuzindua procmon haraka iwezekanavyo (kabla ya michakato kupakuliwa). Hivyo, ili kupata .dll zinazokosekana fanya:

- **Unda** folda `C:\privesc_hijacking` na ongeza njia `C:\privesc_hijacking` kwenye **System Path env variable**. Unaweza kufanya hivi **kwa mikono** au kwa **PS**:
```powershell
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
- Anzisha **`procmon`** na nenda kwenye **`Options`** --> **`Enable boot logging`** na bonyeza **`OK`** kwenye ujumbe.
- Kisha, **reboot**. Wakati kompyuta inapoanzishwa upya **`procmon`** itaanza **kurekodi** matukio mara moja.
- Mara **Windows** inapokuwa **imeanzishwa, tekeleza `procmon`** tena, itakuambia kwamba imekuwa ikifanya kazi na itaku **uliza kama unataka kuhifadhi** matukio kwenye faili. Sema **ndiyo** na **hifadhi matukio kwenye faili**.
- **Baada** ya **faili** kutengenezwa, **funga** dirisha lililo wazi la **`procmon`** na **fungua faili la matukio**.
- Ongeza hizi **filters** na utaona Dll zote ambazo baadhi ya **proccess zilijaribu kupakia** kutoka kwenye folda ya Writable System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

### Dll Zilizokosekana

Nilipokimbia hii kwenye **mashine ya bure ya virtual (vmware) Windows 11** nilipata matokeo haya:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Katika kesi hii .exe hazina maana hivyo zipuuzie, Dll zilizokosekana zilikuwa kutoka:

| Huduma                          | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Baada ya kupata hii, nilipata chapisho la blog linalovutia ambalo pia linaelezea jinsi ya [**kudhulumu WptsExtensions.dll kwa privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Ambayo ndiyo tunayo **enda kufanya sasa**.

### Ukatili

Hivyo, ili **kuinua mamlaka** tunakwenda kudhulumu maktaba **WptsExtensions.dll**. Tukiwa na **path** na **jina** tunahitaji tu **kutengeneza dll mbaya**.

Unaweza [**jaribu kutumia mfano wowote wa haya**](./#creating-and-compiling-dlls). Unaweza kukimbia payloads kama: pata rev shell, ongeza mtumiaji, tekeleza beacon...

> [!WARNING]
> Kumbuka kwamba **sio huduma zote zinaendeshwa** na **`NT AUTHORITY\SYSTEM`** baadhi pia zinaendeshwa na **`NT AUTHORITY\LOCAL SERVICE`** ambayo ina **mamlaka kidogo** na hu **wezi kuunda mtumiaji mpya** kudhulumu ruhusa zake.\
> Hata hivyo, mtumiaji huyo ana **`seImpersonate`** ruhusa, hivyo unaweza kutumia [**potato suite ili kuinua mamlaka**](../roguepotato-and-printspoofer.md). Hivyo, katika kesi hii rev shell ni chaguo bora kuliko kujaribu kuunda mtumiaji.

Wakati wa kuandika huduma ya **Task Scheduler** inaendeshwa na **Nt AUTHORITY\SYSTEM**.

Baada ya **kutengeneza Dll mbaya** (_katika kesi yangu nilitumia x64 rev shell na nilipata shell lakini defender iliuua kwa sababu ilikuwa kutoka msfvenom_), ihifadhi kwenye Writable System Path kwa jina **WptsExtensions.dll** na **anzisha upya** kompyuta (au anzisha upya huduma au fanya chochote kinachohitajika ili kuanzisha tena huduma/programu iliyoathiriwa).

Wakati huduma inapoanzishwa tena, **dll inapaswa kupakiwa na kutekelezwa** (unaweza **kurudia** hila ya **procmon** ili kuangalia kama **maktaba ilipakiwa kama inavyotarajiwa**).

{{#include ../../../banners/hacktricks-training.md}}
