# Word-makro's

{{#include ../banners/hacktricks-training.md}}

## Junk Code

Makro's kan **onbereikbare of irrelevante kode** bevat wat bedoel is om analise te vertraag. Identifiseer konstante voorwaardes en volg bereikbare gedrag voordat jy tyd aan die reverse engineering van 'n vertakking bestee. Die voorbeeld hieronder gebruik 'n `If`-voorwaarde wat nooit waar kan wees nie om junk code te verberg.

![A Word-makro wat 'n onbereikbare voorwaardelike vertakking met junk code bevat](<../images/image (369).png>)

## Makrovorms

VBA UserForms kan data in kontroles soos tekskassies stoor. Omdat vorms, rame en bladsye elk 'n `Controls`-versameling kan blootstel, moet ontleders die volledige kontrolehiërargie opsom eerder as om slegs te vertrou op wat die vorm vertoon. Die voorbeeld hieronder stoor verborge data in oorvleuelende tekskassies.<sup>[[1]](#references)</sup>

Tydens dinamiese analise kan VBA se `GetObject`-funksie 'n Automation-objek uit 'n lêer ophaal of aan 'n reeds lopende Automation-bediener koppel. Makro's kan daardie objektoegang gebruik om data te bereik wat nie in die sigbare dokument duidelik is nie; inspekteer beide die teruggekeerde objek en die UserForm-kontroleboom.<sup>[[2]](#references)</sup>

![A makro UserForm met data wat in oorvleuelende tekskassies verberg is](<../images/image (344).png>)

## References

- [1] [Microsoft Learn - Versamelings, kontroles en objekte (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [2] [Microsoft Learn - `GetObject`-funksie](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../banners/hacktricks-training.md}}
