# Office-lêerontleding

{{#include ../../../banners/hacktricks-training.md}}

Vir verdere inligting, kyk na [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Dit is net ’n opsomming:<sup>[[2]](#references)</sup>

Microsoft Office-dokumente verskyn dikwels in verouderde formate soos RTF en OLE/CFBF-gebaseerde DOC, XLS en PPT, of in nuwer **Office Open XML (OOXML)**-formate soos DOCX, XLSX en PPTX. Office-dokumente kan aktiewe inhoud soos makro’s bevat, wat hulle algemene draers van phishing en malware maak. OOXML-lêers is ZIP-houers waarvan die lêerhiërargie en XML-inhoud ondersoek kan word deur hulle uit te pak.<sup>[[1]](#references)[[2]](#references)</sup>

Die opdrag om ’n dokument uit te pak en die resulterende struktuur word gegee om OOXML-lêerstrukture te verken. Tegnieke om data in hierdie lêers te versteek, is gedokumenteer, wat op voortgesette innovasie in die verberging van data binne CTF-uitdagings dui.<sup>[[2]](#references)</sup>

Vir ontleding bied **oletools** en **OfficeDissector** omvattende gereedskapstelle om beide OLE- en OOXML-dokumente te ondersoek. Hierdie gereedskap help om ingebedde makro’s te identifiseer en te ontleed, wat dikwels as vektore vir die aflewering van malware dien deur tipies verdere kwaadwillige loonvragte af te laai en uit te voer. VBA-makro’s kan sonder Microsoft Office ontleed word deur Libre Office te gebruik, wat ontfouting met breekpunte en veranderlikes in die dophouvenster moontlik maak.<sup>[[2]](#references)</sup>

Die installering en gebruik van **oletools** is eenvoudig; opdragte vir installering via pip en die onttrekking van makro’s uit dokumente word verskaf. In Word sluit outomatiese makro’s `AutoExec` en `AutoOpen` in, terwyl `Document_Open` ’n oopgebeurtenisprosedure is.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

## VBA-makro-analise: rommelkode en UserForms

## Rommelkode

Makros kan **onbereikbare of irrelevante kode** bevat wat bedoel is om analise te vertraag. Identifiseer konstante voorwaardes en spoor bereikbare gedrag na voordat jy tyd daaraan bestee om ’n vertakking te reverse-engineer. Die voorbeeld hieronder gebruik ’n `If`-voorwaarde wat nooit waar kan wees nie om rommelkode te verberg.

![A Word macro containing an unreachable conditional branch with junk code](<../../../images/image (369).png>)

## Makrovorms

VBA UserForms kan data in kontroles soos tekskassies stoor. Omdat vorms, rame en bladsye elk ’n `Controls`-versameling kan blootstel, moet ontleders die hele beheerhiërargie deurloop eerder as om net staat te maak op wat die vorm vertoon. Die voorbeeld hieronder stoor versteekte data in oorvleuelende tekskassies.<sup>[[6]](#references)</sup>

Tydens dinamiese analise kan VBA se `GetObject`-funksie ’n Automation-objek uit ’n lêer ophaal of aan ’n reeds lopende Automation-bediener koppel. Makros kan dié objektoegang gebruik om data te bereik wat nie in die sigbare dokument duidelik is nie; ondersoek sowel die teruggekeerde objek as die UserForm-beheerboom.<sup>[[7]](#references)</sup>

![A macro UserForm with data concealed in overlapping text boxes](<../../../images/image (344).png>)

Vir Office-dokumente wat met ’n wagwoord geënkripteer is, sien die [grammatikagedrewe vanlyn-herstelwerkvloei](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

Vir Revit RFA-lêers wat OLE/CFBF gebruik, sien [ECC-herberekening, beheerde gzip en deserializer-uitbuiting](../../../binary-exploitation/revit-rfa-ole-compound-file-exploitation.md); dié parser-uitbuitingswerkvloei is apart van Office-dokumenttriage.

## References

- [1] [Dokumentasie oor OLE Compound File (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [2] [Veldgids vir Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [3] [Dokumentasie oor olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [4] [Outomatiese makros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [5] [Document.Open-gebeurtenis (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
- [6] [Microsoft Learn - Versamelings, kontroles en objekte (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [7] [Microsoft Learn - `GetObject`-funksie](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../../../banners/hacktricks-training.md}}
