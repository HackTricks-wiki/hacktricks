# Uchambuzi wa faili za Ofisi

{{#include ../../../banners/hacktricks-training.md}}

Kwa maelezo zaidi angalia [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Hii ni muhtasari tu:

Microsoft imeunda aina nyingi za fomati za hati za ofisi, ambapo aina mbili kuu ni **OLE formats** (kama RTF, DOC, XLS, PPT) na **Office Open XML (OOXML) formats** (kama DOCX, XLSX, PPTX). Fomati hizi zinaweza kujumuisha macros, na kuifanya kuwa malengo ya phishing na malware. Faili za OOXML zimeundwa kama vyombo vya zip, kuruhusu ukaguzi kupitia unzipping, ikifunua muundo wa faili na folda na maudhui ya faili ya XML.

Ili kuchunguza muundo wa faili za OOXML, amri ya kufungua hati na muundo wa matokeo zimepewa. Mbinu za kuficha data katika faili hizi zimeandikwa, zikionyesha uvumbuzi unaoendelea katika kuficha data ndani ya changamoto za CTF.

Kwa uchambuzi, **oletools** na **OfficeDissector** hutoa seti kamili za zana za kuchunguza hati za OLE na OOXML. Zana hizi husaidia katika kubaini na kuchambua macros zilizojumuishwa, ambazo mara nyingi hutumikia kama njia za usambazaji wa malware, kwa kawaida zinapakua na kutekeleza mzigo mbaya wa ziada. Uchambuzi wa macros za VBA unaweza kufanywa bila Microsoft Office kwa kutumia Libre Office, ambayo inaruhusu urekebishaji kwa kutumia breakpoints na watch variables.

Usanidi na matumizi ya **oletools** ni rahisi, huku amri zikipewa kwa ajili ya kusanidi kupitia pip na kutoa macros kutoka kwa hati. Utekelezaji wa moja kwa moja wa macros unasababishwa na kazi kama `AutoOpen`, `AutoExec`, au `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
{{#include ../../../banners/hacktricks-training.md}}
