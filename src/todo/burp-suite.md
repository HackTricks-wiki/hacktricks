# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Intruder payload types

- **Jednostavna lista:** Koristi konfigurisanu listu stringova kao payloads.
- **Runtime file:** Čita jedan payload po liniji tokom runtime-a. Ovo je korisno za velike liste jer Burp ne učitava celu datoteku u memoriju.
- **Case modification:** Menja velika i mala slova ulaznog stringa, na primer u mala slova, velika slova, oblik rečenice ili oblik naslova.
- **Numbers:** Generiše sekvencijalne ili nasumične brojeve unutar konfigurisanog opsega.
- **Brute forcer:** Generiše svaku permutaciju za izabrani skup karaktera i minimalnu/maksimalnu dužinu.<sup>[[1]](#references)</sup>

## Extensions and companion tools

- **Collabfiltrator** generiše payloads koji izvršavaju komande i exfiltriraju njihov izlaz kroz DNS upite ka Burp Collaborator-u.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** izvozi Burp nalaze za upotrebu u drugim reporting workflow-ima.<sup>[[3]](#references)</sup>
- **HTTP Script Generator** pretvara HTTP zahteve u skripte na nekoliko jezika.<sup>[[4]](#references)</sup>

## References

- [1] [PortSwigger dokumentacija - Burp Intruder tipovi payload-a](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
{{#include ../banners/hacktricks-training.md}}
