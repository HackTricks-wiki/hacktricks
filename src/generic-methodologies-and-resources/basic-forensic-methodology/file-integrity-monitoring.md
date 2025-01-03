{{#include ../../banners/hacktricks-training.md}}

# Baseline

Una baseline consiste nel prendere uno snapshot di alcune parti di un sistema per **confrontarlo con uno stato futuro per evidenziare le modifiche**.

Ad esempio, puoi calcolare e memorizzare l'hash di ciascun file del filesystem per poter scoprire quali file sono stati modificati.\
Questo può essere fatto anche con gli account utente creati, i processi in esecuzione, i servizi in esecuzione e qualsiasi altra cosa che non dovrebbe cambiare molto, o affatto.

## File Integrity Monitoring

Il File Integrity Monitoring (FIM) è una tecnica di sicurezza critica che protegge gli ambienti IT e i dati tracciando le modifiche ai file. Comporta due passaggi chiave:

1. **Baseline Comparison:** Stabilire una baseline utilizzando attributi dei file o checksum crittografici (come MD5 o SHA-2) per confronti futuri per rilevare modifiche.
2. **Real-Time Change Notification:** Ricevere avvisi istantanei quando i file vengono accessi o modificati, tipicamente attraverso estensioni del kernel del sistema operativo.

## Tools

- [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
- [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

## References

- [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)

{{#include ../../banners/hacktricks-training.md}}
