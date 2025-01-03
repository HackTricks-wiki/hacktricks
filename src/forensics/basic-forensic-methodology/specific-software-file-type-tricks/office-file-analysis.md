# Office-lêeranalyse

{{#include ../../../banners/hacktricks-training.md}}

Vir verdere inligting, kyk na [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Dit is net 'n opsomming:

Microsoft het baie kantoor dokumentformate geskep, met twee hoof tipes wat **OLE-formate** (soos RTF, DOC, XLS, PPT) en **Office Open XML (OOXML)-formate** (soos DOCX, XLSX, PPTX) is. Hierdie formate kan makros insluit, wat hulle teikens vir phishing en malware maak. OOXML-lêers is gestruktureer as zip-kontainers, wat inspeksie deur ontrafel moontlik maak, wat die lêer- en vouerhiërargie en XML-lêerinhoud onthul.

Om OOXML-lêerstrukture te verken, word die opdrag om 'n dokument te ontrafel en die uitvoerstruktuur gegee. Tegnieke om data in hierdie lêers te verberg, is gedokumenteer, wat daarop dui dat daar voortgesette innovasie in dataverborge binne CTF-uitdagings is.

Vir analise bied **oletools** en **OfficeDissector** omvattende hulpmiddels vir die ondersoek van beide OLE- en OOXML-dokumente. Hierdie hulpmiddels help om ingebedde makros te identifiseer en te analiseer, wat dikwels as vektore vir malware-aflewering dien, wat tipies addisionele kwaadwillige payloads aflaai en uitvoer. Analise van VBA-makros kan sonder Microsoft Office gedoen word deur Libre Office te gebruik, wat debuggings met breekpunte en kykveranderlikes toelaat.

Installasie en gebruik van **oletools** is eenvoudig, met opdragte wat gegee word vir installasie via pip en die onttrekking van makros uit dokumente. Outomatiese uitvoering van makros word geaktiveer deur funksies soos `AutoOpen`, `AutoExec`, of `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
{{#include ../../../banners/hacktricks-training.md}}
