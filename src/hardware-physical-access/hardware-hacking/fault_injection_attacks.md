# Attacchi di fault injection

{{#include ../../banners/hacktricks-training.md}}

La fault injection, spesso chiamata **glitching** nell’ambito della sicurezza hardware, consiste nel disturbare deliberatamente un dispositivo mentre è in funzione, inducendolo a eseguire un calcolo errato. Un fault utile può saltare un’istruzione, corrompere dati, aggirare un controllo di sicurezza o produrre un output crittografico errato da cui è possibile ricavare informazioni segrete.<sup>[[1]](#references)</sup>

Le tecniche comuni manipolano la tensione di alimentazione o il clock, iniettano interferenze elettromagnetiche oppure ricorrono a stimoli ottici o laser.<sup>[[1]](#references)</sup> La loro precisione e invasività variano, ma per eseguire test efficaci in genere servono un trigger ripetibile e scansioni sistematiche di timing, durata e intensità degli impulsi. Iniziate da una baseline stabile, registrate separatamente i reset e gli output malformati e modificate un solo parametro alla volta.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - Metodo di fault injection non invasivo e senza trigger basato su interferenza elettromagnetica intenzionale](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [Documentazione ChipWhisperer - Panoramica e confronto dell’hardware di acquisizione](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
