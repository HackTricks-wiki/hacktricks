# Word-makro's

{{#include ../banners/hacktricks-training.md}}

## Junk Code

Makro's kan **onbereikbare of irrelevante kode** bevat wat bedoel is om analise te vertraag. Identifiseer konstante voorwaardes en volg bereikbare gedrag voordat jy tyd spandeer aan die reversing van 'n vertakking. Die voorbeeld hieronder gebruik 'n `If`-voorwaarde wat nooit waar kan wees nie om junk code te verberg.

!['n Word-makro wat 'n onbereikbare voorwaardelike vertakking met junk code bevat](<../images/image (369).png>)

## Makro-vorms

VBA UserForms kan data in kontroles soos tekskassies stoor. Omdat vorms, rame en bladsye elk 'n `Controls`-versameling kan blootstel, moet analysts die volledige beheerhiërargie opsom eerder as om slegs te vertrou op wat die vorm vertoon. Die voorbeeld hieronder stoor verborge data in oorvleuelende tekskassies.<sup>[[1]](#references)</sup>

!['n Makro UserForm met data wat in oorvleuelende tekskassies versteek is](<../images/image (344).png>)

## References

- [1] [Microsoft Learn - Versamelings, kontroles en objekte (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
{{#include ../banners/hacktricks-training.md}}
