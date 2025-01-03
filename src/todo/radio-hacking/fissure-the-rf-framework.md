# FISSURE - Il Framework RF

**Comprensione e Ingegneria Inversa dei Segnali SDR Indipendenti dalla Frequenza**

FISSURE è un framework open-source RF e di ingegneria inversa progettato per tutti i livelli di abilità, con hook per la rilevazione e classificazione dei segnali, scoperta dei protocolli, esecuzione degli attacchi, manipolazione IQ, analisi delle vulnerabilità, automazione e AI/ML. Il framework è stato costruito per promuovere l'integrazione rapida di moduli software, radio, protocolli, dati di segnale, script, grafici di flusso, materiale di riferimento e strumenti di terze parti. FISSURE è un abilitante del flusso di lavoro che mantiene il software in un'unica posizione e consente ai team di mettersi rapidamente al passo mentre condividono la stessa configurazione di base collaudata per specifiche distribuzioni Linux.

Il framework e gli strumenti inclusi in FISSURE sono progettati per rilevare la presenza di energia RF, comprendere le caratteristiche di un segnale, raccogliere e analizzare campioni, sviluppare tecniche di trasmissione e/o iniezione e creare payload o messaggi personalizzati. FISSURE contiene una libreria in crescita di informazioni su protocolli e segnali per assistere nell'identificazione, creazione di pacchetti e fuzzing. Esistono capacità di archiviazione online per scaricare file di segnale e costruire playlist per simulare il traffico e testare i sistemi.

Il codice Python amichevole e l'interfaccia utente consentono ai principianti di apprendere rapidamente strumenti e tecniche popolari riguardanti RF e ingegneria inversa. Gli educatori in cybersecurity e ingegneria possono sfruttare il materiale integrato o utilizzare il framework per dimostrare le proprie applicazioni nel mondo reale. Sviluppatori e ricercatori possono utilizzare FISSURE per le loro attività quotidiane o per esporre le loro soluzioni all'avanguardia a un pubblico più ampio. Man mano che la consapevolezza e l'uso di FISSURE crescono nella comunità, così farà l'estensione delle sue capacità e l'ampiezza della tecnologia che comprende.

**Informazioni Aggiuntive**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Iniziare

**Supportato**

Ci sono tre rami all'interno di FISSURE per rendere più facile la navigazione nei file e ridurre la ridondanza del codice. Il ramo Python2\_maint-3.7 contiene una base di codice costruita attorno a Python2, PyQt4 e GNU Radio 3.7; il ramo Python3\_maint-3.8 è costruito attorno a Python3, PyQt5 e GNU Radio 3.8; e il ramo Python3\_maint-3.10 è costruito attorno a Python3, PyQt5 e GNU Radio 3.10.

|   Sistema Operativo   |   Ramo FISSURE   |
| :------------------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**In Corso (beta)**

Questi sistemi operativi sono ancora in stato beta. Sono in fase di sviluppo e diverse funzionalità sono note per essere mancanti. Gli elementi nell'installer potrebbero entrare in conflitto con programmi esistenti o non installarsi fino a quando lo stato non viene rimosso.

|     Sistema Operativo     |    Ramo FISSURE   |
| :----------------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

Nota: Alcuni strumenti software non funzionano per ogni OS. Fare riferimento a [Software And Conflicts](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Installazione**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Questo installerà le dipendenze software di PyQt necessarie per avviare le interfacce di installazione se non vengono trovate.

Successivamente, seleziona l'opzione che meglio corrisponde al tuo sistema operativo (dovrebbe essere rilevato automaticamente se il tuo OS corrisponde a un'opzione).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Si consiglia di installare FISSURE su un sistema operativo pulito per evitare conflitti esistenti. Seleziona tutte le caselle di controllo consigliate (pulsante predefinito) per evitare errori durante l'operazione dei vari strumenti all'interno di FISSURE. Ci saranno più richieste durante l'installazione, principalmente per autorizzazioni elevate e nomi utente. Se un elemento contiene una sezione "Verifica" alla fine, l'installer eseguirà il comando che segue e evidenzierà l'elemento della casella di controllo in verde o rosso a seconda che vengano prodotti errori dal comando. Gli elementi selezionati senza una sezione "Verifica" rimarranno neri dopo l'installazione.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Uso**

Apri un terminale e inserisci:
```
fissure
```
Riferirsi al menu di aiuto di FISSURE per ulteriori dettagli sull'uso.

## Dettagli

**Componenti**

* Dashboard
* Central Hub (HIPRFISR)
* Target Signal Identification (TSI)
* Protocol Discovery (PD)
* Flow Graph & Script Executor (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Capacità**

| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Rilevatore di Segnale**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Manipolazione IQ**_      | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Ricerca Segnale**_          | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Riconoscimento Modelli**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attacchi**_           | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Playlist di Segnale**_       | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Galleria Immagini**_  |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Creazione Pacchetti**_   | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Integrazione Scapy**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Calcolatore CRC**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Registrazione**_            |

**Hardware**

Di seguito è riportato un elenco di hardware "supportato" con vari livelli di integrazione:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* Adattatori 802.11
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Lezioni

FISSURE viene fornito con diverse guide utili per familiarizzare con diverse tecnologie e tecniche. Molte includono passaggi per utilizzare vari strumenti integrati in FISSURE.

* [Lezione1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lezione2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lezione3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lezione4: Schede ESP](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lezione5: Tracciamento Radiosonde](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lezione6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lezione7: Tipi di Dati](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lezione8: Blocchi GNU Radio Personalizzati](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lezione9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lezione10: Esami Radioamatoriali](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lezione11: Strumenti Wi-Fi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## Roadmap

* [ ] Aggiungere più tipi di hardware, protocolli RF, parametri di segnale, strumenti di analisi
* [ ] Supportare più sistemi operativi
* [ ] Sviluppare materiale didattico attorno a FISSURE (Attacchi RF, Wi-Fi, GNU Radio, PyQt, ecc.)
* [ ] Creare un condizionatore di segnale, estrattore di caratteristiche e classificatore di segnale con tecniche AI/ML selezionabili
* [ ] Implementare meccanismi di demodulazione ricorsiva per produrre un bitstream da segnali sconosciuti
* [ ] Trasferire i principali componenti di FISSURE a uno schema di distribuzione di nodi sensori generici

## Contribuire

Suggerimenti per migliorare FISSURE sono fortemente incoraggiati. Lascia un commento nella pagina [Discussioni](https://github.com/ainfosec/FISSURE/discussions) o nel server Discord se hai pensieri riguardo ai seguenti argomenti:

* Suggerimenti per nuove funzionalità e modifiche di design
* Strumenti software con passaggi di installazione
* Nuove lezioni o materiale aggiuntivo per lezioni esistenti
* Protocolli RF di interesse
* Maggiore hardware e tipi di SDR per integrazione
* Script di analisi IQ in Python
* Correzioni e miglioramenti di installazione

Le contribuzioni per migliorare FISSURE sono cruciali per accelerare il suo sviluppo. Qualsiasi contributo che fai è molto apprezzato. Se desideri contribuire attraverso lo sviluppo di codice, per favore fork il repo e crea una pull request:

1. Fork il progetto
2. Crea il tuo branch di funzionalità (`git checkout -b feature/AmazingFeature`)
3. Commetti le tue modifiche (`git commit -m 'Aggiungi qualche AmazingFeature'`)
4. Push al branch (`git push origin feature/AmazingFeature`)
5. Apri una pull request

Creare [Issues](https://github.com/ainfosec/FISSURE/issues) per portare attenzione a bug è anche benvenuto.

## Collaborare

Contatta Assured Information Security, Inc. (AIS) Business Development per proporre e formalizzare eventuali opportunità di collaborazione su FISSURE, sia dedicando tempo all'integrazione del tuo software, sia facendo sviluppare soluzioni per le tue sfide tecniche dalle persone talentuose di AIS, o integrando FISSURE in altre piattaforme/applicazioni.

## Licenza

GPL-3.0

Per i dettagli sulla licenza, vedere il file LICENSE.

## Contatto

Unisciti al server Discord: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Segui su Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Crediti

Riconosciamo e siamo grati a questi sviluppatori:

[Crediti](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Riconoscimenti

Un ringraziamento speciale a Dr. Samuel Mantravadi e Joseph Reith per i loro contributi a questo progetto.
