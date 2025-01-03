{{#include ../../banners/hacktricks-training.md}}

**The original post is** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Summary

Mfunguo mbili za rejista zilipatikana kuwa zinaweza kuandikwa na mtumiaji wa sasa:

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

Ilipendekezwa kuangalia ruhusa za huduma ya **RpcEptMapper** kwa kutumia **regedit GUI**, hasa kwenye kichupo cha **Ruhusa za Ufanisi** katika dirisha la **Advanced Security Settings**. Njia hii inaruhusu tathmini ya ruhusa zilizotolewa kwa watumiaji au vikundi maalum bila kuhitaji kuchunguza kila Kuingilia Udhibiti wa Ufikiaji (ACE) moja kwa moja.

Picha ilionyesha ruhusa zilizotolewa kwa mtumiaji mwenye mamlaka ya chini, ambapo ruhusa ya **Create Subkey** ilikuwa ya kutajwa. Ruhusa hii, pia inajulikana kama **AppendData/AddSubdirectory**, inalingana na matokeo ya script.

Kutokuweza kubadilisha baadhi ya thamani moja kwa moja, lakini uwezo wa kuunda funguo mpya za chini, ulionekana. Mfano ulioangaziwa ulikuwa ni jaribio la kubadilisha thamani ya **ImagePath**, ambayo ilipelekea ujumbe wa kukataliwa kwa ufikiaji.

Licha ya vikwazo hivi, uwezekano wa kupandisha mamlaka ulitambuliwa kupitia uwezekano wa kutumia funguo ya **Performance** ndani ya muundo wa rejista wa huduma ya **RpcEptMapper**, funguo ambayo haipo kwa kawaida. Hii inaweza kuruhusu usajili wa DLL na ufuatiliaji wa utendaji.

Hati kuhusu funguo ya **Performance** na matumizi yake kwa ufuatiliaji wa utendaji ilikaguliwa, ikisababisha maendeleo ya DLL ya uthibitisho wa dhana. DLL hii, ikionyesha utekelezaji wa kazi za **OpenPerfData**, **CollectPerfData**, na **ClosePerfData**, ilijaribiwa kupitia **rundll32**, ikithibitisha mafanikio yake ya uendeshaji.

Lengo lilikuwa kulazimisha huduma ya **RPC Endpoint Mapper** kupakia DLL ya Performance iliyoundwa. Uangalizi ulionyesha kuwa kutekeleza maswali ya darasa la WMI yanayohusiana na Data ya Utendaji kupitia PowerShell kulisababisha kuundwa kwa faili ya kumbukumbu, ikiruhusu utekelezaji wa msimbo wa kiholela chini ya muktadha wa **LOCAL SYSTEM**, hivyo kutoa mamlaka ya juu.

Uthibitisho wa kudumu na athari zinazoweza kutokea za udhaifu huu zilisisitizwa, zikionyesha umuhimu wake kwa mikakati ya baada ya unyakuzi, harakati za pembeni, na kuepuka mifumo ya antivirus/EDR.

Ingawa udhaifu huu ulifunuliwa kwa bahati mbaya kupitia script, ilisisitizwa kuwa unyakuzi wake unakabiliwa na toleo la zamani la Windows (mfano, **Windows 7 / Server 2008 R2**) na unahitaji ufikiaji wa ndani.

{{#include ../../banners/hacktricks-training.md}}
