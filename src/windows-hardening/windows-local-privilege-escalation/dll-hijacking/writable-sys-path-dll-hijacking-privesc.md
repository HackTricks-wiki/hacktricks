# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Utangulizi

Ikiwa umegundua kwamba unaweza **kuandika katika folda ya System Path** (kumbuka kwamba hii haitafanya kazi ikiwa unaweza kuandika katika folda ya User Path) inawezekana kwamba unaweza **kupandisha ruhusa** kwenye mfumo.

Ili kufanya hivyo unaweza kunyanyasa **Dll Hijacking** ambapo utafanya **hijack ya maktaba inayopakiwa** na service au mchakato wenye **ruhusa zaidi** kuliko zako, na kwa sababu service hiyo inapakia Dll ambayo labda haipo hata kwenye mfumo mzima, itajaribu kuipakia kutoka System Path ambapo unaweza kuandika.

Kwa maelezo zaidi kuhusu **ni nini Dll Hijackig** angalia:


{{#ref}}
./
{{#endref}}

## Privesc na Dll Hijacking

### Kupata Dll iliyokosekana

Kitu cha kwanza unachohitaji ni **kutambua mchakato** unaokimbia na **ruhusa zaidi** kuliko zako ambao unajaribu **kupakia Dll kutoka System Path** ambayo unaweza kuandika ndani yake.

Shida katika kesi hizi ni kwamba uwezekano mchakato hizo tayari zinakimbia. Ili kupata Dll ambazo zinakosekana kwa services unahitaji kuanzisha procmon haraka iwezekanavyo (kabla mchakato haujapakiwa). Kwa hivyo, ili kutafuta .dll zilizokosekana fanya:

- **Unda** folda `C:\privesc_hijacking` na ongeza path `C:\privesc_hijacking` kwenye **System Path env variable**. Unaweza kufanya hivi **kwa mkono** au kwa **PS**:
```bash
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
- Zindua **`procmon`** na nenda kwenye **`Options`** --> **`Enable boot logging`** kisha bonyeza **`OK`** kwenye mwito.
- Kisha, **anzisha upya**. Kompyuta itakapowashwa tena **`procmon`** itaanza **kurekodi** matukio mara moja iwezekanavyo.
- Mara **Windows** itakapowashwa, **endesha `procmon`** tena, itakuambia kuwa imekuwa ikikimbia na itauliza ikiwa ungependa **kuhifadhi** matukio katika faili. Sema **ndio** na **hifadhi matukio katika faili**.
- **Baada** faili ikizalishwa, **funika** dirisha la **`procmon`** lililofunguliwa na **fungua faili la matukio**.
- Ongeza hizi **filters** na utapata DLL zote ambazo baadhi ya **process** zilijaribu kuzileta kutoka kwenye folda ya writable System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

### Dlls zilizokosewa

Nilipokimbia hii kwenye mashine ya virtual (vmware) ya Windows 11 bila malipo nilipata matokeo haya:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Katika kesi hii .exe hazina matumizi, zahirika, DLL zilizokosewa zilitoka kwa:

| Huduma                          | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Baada ya kugundua hili, nilipata chapisho la blogu lenye kuvutia ambalo pia linaelezea jinsi ya [**abuse WptsExtensions.dll for privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Hilo ndilo **tutakalofanya sasa**.

### Exploitation

Kwa hivyo, ili **escalate privileges** tutahijack maktaba **WptsExtensions.dll**. Tukiwa na **path** na **name** tunahitaji tu **generate the malicious dll**.

Unaweza [**jaribu kutumia mifano yoyote ya hizi**](#creating-and-compiling-dlls). Unaweza kuendesha payloads kama: kupata rev shell, kuongeza user, kuendesha beacon...

> [!WARNING]
> Kumbuka kwamba **si huduma zote zinaendeshwa** kwa **`NT AUTHORITY\SYSTEM`** — baadhi zinaendeshwa pia kwa **`NT AUTHORITY\LOCAL SERVICE`** ambayo ina **privileges chache** na **hutaweza kuunda user mpya** kwa kutumia ruhusa zake.\
> Hata hivyo, user huyo ana ruhusa ya **`seImpersonate`**, hivyo unaweza kutumia [ **potato suite to escalate privileges**](../roguepotato-and-printspoofer.md). Kwa hivyo, katika kesi hii rev shell ni chaguo zuri zaidi kuliko kujaribu kuunda user.

Kwa wakati wa kuandika hii huduma ya **Task Scheduler** inaendeshwa kwa **Nt AUTHORITY\SYSTEM**.

Mara baada ya **kutengeneza Dll hasidi** (_kwangu nilitumia x64 rev shell na nilipata shell lakini defender iliiua kwa sababu ilitokana na msfvenom_), ichiweke kwenye writable System Path kwa jina **WptsExtensions.dll** na **anzisha upya** kompyuta (au anzisha upya service au fanya chochote kinachohitajika ili kuendesha tena service/programu iliyohusishwa).

Wakati service itakapowashwa tena, **dll inapaswa kuzipakiwa na kutekelezwa** (unaweza **tumia tena** trick ya **procmon** ili kukagua ikiwa **library ilizimwa kama ilivyotarajiwa**).

{{#include ../../../banners/hacktricks-training.md}}
