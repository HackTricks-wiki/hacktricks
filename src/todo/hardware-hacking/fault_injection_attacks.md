# Attacchi di Fault Injection

{{#include ../../banners/hacktricks-training.md}}

La fault injection, spesso chiamata **glitching** nel campo della sicurezza hardware, disturba deliberatamente un dispositivo mentre è in funzione, inducendolo a eseguire un calcolo errato. Un fault utile può saltare un'istruzione, corrompere dati, bypassare un controllo di sicurezza o produrre un output crittografico errato dal quale è possibile ricavare informazioni segrete.<sup>[[1]](#references)</sup>

Le tecniche comuni manipolano la tensione di alimentazione o il clock, iniettano interferenze elettromagnetiche oppure utilizzano stimolazioni ottiche o laser.<sup>[[1]](#references)</sup> La loro precisione e invasività variano, ma i test riusciti richiedono generalmente un trigger ripetibile e scansioni sistematiche di temporizzazione, durata dell'impulso e intensità. Inizia con una baseline stabile, registra separatamente i reset e gli output malformati e modifica un parametro alla volta.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - Metodo di Fault Injection non invasivo e senza trigger basato su interferenze elettromagnetiche intenzionali](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [Documentazione di ChipWhisperer - Panoramica e confronto dell'hardware di acquisizione](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
