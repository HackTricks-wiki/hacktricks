# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Aina za payload za Intruder

- **Simple list:** Tumia orodha iliyosanidiwa ya strings kama payloads.
- **Runtime file:** Soma payload moja kwa kila mstari wakati wa runtime. Hii ni muhimu kwa orodha kubwa kwa sababu Burp haipakii faili lote kwenye memory.
- **Case modification:** Badilisha herufi kubwa na ndogo za input string, kwa mfano kuwa lowercase, uppercase, sentence case, au title case.
- **Numbers:** Zalisha nambari zinazofuatana au za random ndani ya range iliyosanidiwa.
- **Brute forcer:** Zalisha kila permutation kwa character set iliyochaguliwa na urefu wa chini/wa juu.<sup>[[1]](#references)</sup>

## Extensions na zana shirikishi

- **Collabfiltrator** huzalisha payloads zinazotekeleza commands na ku-exfiltrate output yake kupitia DNS queries kwenda Burp Collaborator.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** hu-export findings za Burp kwa matumizi katika workflows nyingine za reporting.<sup>[[3]](#references)</sup>
- **HTTP Script Generator** hubadilisha HTTP requests kuwa scripts katika lugha kadhaa.<sup>[[4]](#references)</sup>

## References

- [1] [PortSwigger documentation - Aina za payload za Burp Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
{{#include ../banners/hacktricks-training.md}}
