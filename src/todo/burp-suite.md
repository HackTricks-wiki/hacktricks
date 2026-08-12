# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Tipovi payload-a za Intruder

Burp Intruder uključuje sledeće ugrađene generatore i transformacije payload-a:<sup>[[1]](#references)</sup>

- **Simple list:** Koristi konfigurisanu listu stringova kao payload-e.
- **Runtime file:** Čita po jedan payload iz svakog reda tokom izvršavanja. Ovo je korisno za velike liste jer Burp ne učitava celu datoteku u memoriju.
- **Case modification:** Generiše neizmenjenu vrednost, oblike sa malim i velikim slovima, `Propername` (prvo slovo veliko, a ostala mala) ili `ProperName` (prvo slovo veliko, dok preostali karakteri ostaju neizmenjeni). Burp odbacuje duplikate.
- **Numbers:** Generiše sekvencijalne ili nasumične brojeve unutar konfigurisane granice.
- **Brute forcer:** Generiše svaku permutaciju za izabrani skup karaktera i minimalnu/maksimalnu dužinu.

## Ekstenzije i prateći alati

- **Collabfiltrator** generiše payload-e koji izvršavaju komande i eksfiltriraju njihov izlaz kroz DNS upite ka Burp Collaborator-u.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** izvozi Burp nalaze za upotrebu u drugim workflows za izveštavanje.<sup>[[3]](#references)</sup>
- **HTTP Script Generator** pretvara HTTP zahteve u skripte na nekoliko jezika.<sup>[[4]](#references)</sup>

## References

- [1] [PortSwigger dokumentacija - Tipovi payload-a za Burp Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
{{#include ../banners/hacktricks-training.md}}
