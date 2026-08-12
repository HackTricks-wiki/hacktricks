# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Aina za payload za Intruder

Burp Intruder inajumuisha payload generators na transformations zilizojengwa ndani zifuatazo:<sup>[[1]](#references)</sup>

- **Simple list:** Tumia orodha iliyosanidiwa ya strings kama payloads.
- **Runtime file:** Soma payload moja kwa kila mstari wakati wa runtime. Hii ni muhimu kwa orodha kubwa kwa sababu Burp haipakii file nzima kwenye memory.
- **Case modification:** Tengeneza value isiyobadilishwa, katika herufi ndogo na herufi kubwa, `Propername` (herufi ya kwanza ikiwa kubwa na zilizobaki zikiwa ndogo), au `ProperName` (herufi ya kwanza ikiwa kubwa huku herufi zinazobaki zikibaki bila kubadilishwa). Burp huondoa matokeo yanayojirudia.
- **Numbers:** Tengeneza nambari zinazofuatana au za random ndani ya range iliyosanidiwa.
- **Brute forcer:** Tengeneza kila permutation kwa character set iliyochaguliwa na urefu wa chini/wa juu.

## Extensions na zana za ziada

- **Collabfiltrator** hutengeneza payloads zinazotekeleza commands na ku-exfiltrate output yake kupitia DNS queries kwenda Burp Collaborator.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** hu-export findings za Burp ili zitumike katika workflows nyingine za reporting.<sup>[[3]](#references)</sup>
- **HTTP Script Generator** hubadilisha HTTP requests kuwa scripts katika languages kadhaa.<sup>[[4]](#references)</sup>

## References

- [1] [PortSwigger documentation - Aina za payload za Burp Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
{{#include ../banners/hacktricks-training.md}}
