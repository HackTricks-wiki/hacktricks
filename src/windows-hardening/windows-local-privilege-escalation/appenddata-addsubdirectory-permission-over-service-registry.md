{{#include ../../banners/hacktricks-training.md}}

**Die oorspronklike pos is** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Samevatting

Twee register sleutels is gevind wat skryfbaar is deur die huidige gebruiker:

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

Daar is voorgestel om die toestemmings van die **RpcEptMapper** diens te kontroleer met behulp van die **regedit GUI**, spesifiek die **Geavanceerde Sekuriteitsinstellings** venster se **Effektiewe Toestemmings** tab. Hierdie benadering stel die beoordeling van toegepaste toestemmings aan spesifieke gebruikers of groepe in staat sonder die behoefte om elke Toegang Beheer Inskrywing (ACE) individueel te ondersoek.

'n Skermskoot het die toestemmings gewys wat aan 'n laag-geprivilegieerde gebruiker toegeken is, waaronder die **Skep Subsleutel** toestemming opvallend was. Hierdie toestemming, ook bekend as **AppendData/AddSubdirectory**, stem ooreen met die script se bevindings.

Die onvermoë om sekere waardes direk te wysig, terwyl die vermoë om nuwe subsleutels te skep, opgemerk is. 'n Voorbeeld wat uitgelig is, was 'n poging om die **ImagePath** waarde te verander, wat 'n toegang geweier boodskap tot gevolg gehad het.

Ten spyte van hierdie beperkings, is 'n potensiaal vir privilige-eskalasie geïdentifiseer deur die moontlikheid om die **Performance** subsleutel binne die **RpcEptMapper** diens se registerstruktuur te benut, 'n subsleutel wat nie standaard teenwoordig is nie. Dit kan DLL registrasie en prestasie monitering moontlik maak.

Dokumentasie oor die **Performance** subsleutel en sy gebruik vir prestasie monitering is geraadpleeg, wat gelei het tot die ontwikkeling van 'n bewys-van-konsep DLL. Hierdie DLL, wat die implementering van **OpenPerfData**, **CollectPerfData**, en **ClosePerfData** funksies demonstreer, is getoets via **rundll32**, wat sy operasionele sukses bevestig het.

Die doel was om die **RPC Endpoint Mapper diens** te dwing om die vervaardigde Performance DLL te laai. Waarnemings het getoon dat die uitvoering van WMI klas navrae rakende Prestasie Data via PowerShell gelei het tot die skepping van 'n loglêer, wat die uitvoering van arbitrêre kode onder die **LOCAL SYSTEM** konteks moontlik gemaak het, en sodoende verhoogde privilige gegee het.

Die volharding en potensiële implikasies van hierdie kwesbaarheid is beklemtoon, wat die relevansie daarvan vir post-exploitasiestategieë, laterale beweging, en ontduiking van antivirus/EDR stelsels uitlig.

Alhoewel die kwesbaarheid aanvanklik onbedoeld deur die script bekend gemaak is, is dit beklemtoon dat die uitbuiting beperk is tot verouderde Windows weergawes (bv. **Windows 7 / Server 2008 R2**) en plaaslike toegang vereis.

{{#include ../../banners/hacktricks-training.md}}
