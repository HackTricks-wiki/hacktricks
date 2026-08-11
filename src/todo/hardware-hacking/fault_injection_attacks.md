# Attacchi di Fault Injection

{{#include ../../banners/hacktricks-training.md}}

La fault injection disturba deliberatamente un dispositivo mentre è in funzione, inducendolo a eseguire un calcolo errato. Un fault utile può saltare un'istruzione, corrompere dati, bypassare un controllo di sicurezza o produrre un output crittografico errato dal quale è possibile ricavare informazioni segrete.<sup>[[1]](#references)</sup>

Le tecniche comuni manipolano la tensione di alimentazione o il clock, iniettano interferenze elettromagnetiche o utilizzano stimolazioni ottiche o laser.<sup>[[1]](#references)</sup> La loro precisione e invasività variano, ma i test efficaci richiedono generalmente un trigger ripetibile e sweep sistematici di temporizzazione, durata dell'impulso e intensità. Iniziare con una baseline stabile, registrare separatamente reset e output malformati e modificare un parametro alla volta.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - Metodo di Fault Injection non invasivo e senza trigger basato sull'interferenza elettromagnetica intenzionale](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [Documentazione di ChipWhisperer - Panoramica e confronto dell'hardware di acquisizione](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
