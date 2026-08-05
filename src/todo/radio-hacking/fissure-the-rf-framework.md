# FISSURE - Il framework RF

{{#include ../../banners/hacktricks-training.md}}

**Frequency Independent SDR-based Signal Understanding and Reverse Engineering**

FISSURE è un framework open-source per RF e reverse engineering, progettato per tutti i livelli di competenza, con supporto per il rilevamento e la classificazione dei segnali, la scoperta dei protocolli, l'esecuzione di attacchi, la manipolazione IQ, l'analisi delle vulnerabilità, l'automazione e l'AI/ML. Il framework è stato creato per promuovere la rapida integrazione di moduli software, radio, protocolli, dati sui segnali, script, flow graph, materiale di riferimento e strumenti di terze parti. FISSURE facilita i workflow mantenendo il software in un'unica posizione e consentendo ai team di acquisire rapidamente le competenze necessarie, condividendo la stessa configurazione di base collaudata per specifiche distribuzioni Linux.<sup>[[1]](#references)[[2]](#references)</sup>

Il framework e gli strumenti inclusi in FISSURE sono progettati per rilevare la presenza di energia RF, comprendere le caratteristiche di un segnale, raccogliere e analizzare campioni, sviluppare tecniche di trasmissione e/o injection e creare payload o messaggi personalizzati. FISSURE contiene una libreria in continua espansione di informazioni su protocolli e segnali, per facilitare l'identificazione, la creazione di pacchetti e il fuzzing. Sono disponibili funzionalità di archiviazione online per scaricare file di segnali e creare playlist con cui simulare il traffico e testare i sistemi.

La codebase Python e l'interfaccia utente intuitive consentono ai principianti di apprendere rapidamente strumenti e tecniche comuni relativi a RF e reverse engineering. Gli educatori nel campo della cybersecurity e dell'ingegneria possono sfruttare il materiale integrato o utilizzare il framework per dimostrare le proprie applicazioni del mondo reale. Sviluppatori e ricercatori possono usare FISSURE per le attività quotidiane o per presentare le proprie soluzioni all'avanguardia a un pubblico più ampio. Con la crescita della consapevolezza e dell'utilizzo di FISSURE nella community, aumenteranno anche l'estensione delle sue funzionalità e l'ampiezza della tecnologia che comprende.

**Informazioni aggiuntive**

* [Pagina AIS](https://www.ainfosec.com/technologies/fissure/)
* [Slide GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [Paper GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [Video GRCon22](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Trascrizione dell'Hack Chat](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Per iniziare

**Supportati**

All'interno di FISSURE sono presenti tre branch per semplificare la navigazione dei file e ridurre la ridondanza del codice. Il branch Python2\_maint-3.7 contiene una codebase basata su Python2, PyQt4 e GNU Radio 3.7; il branch Python3\_maint-3.8 è basato su Python3, PyQt5 e GNU Radio 3.8; il branch Python3\_maint-3.10 è basato su Python3, PyQt5 e GNU Radio 3.10.

|   Sistema operativo   |   Branch FISSURE   |
| :------------------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**In corso (beta)**

Questi sistemi operativi sono ancora in stato beta. Sono in fase di sviluppo e diverse funzionalità risultano ancora mancanti. Gli elementi inclusi nell'installer potrebbero entrare in conflitto con programmi esistenti o non riuscire a installarsi fino alla rimozione dello stato beta.

|     Sistema operativo     |    Branch FISSURE   |
| :----------------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

Nota: alcuni strumenti software non funzionano su tutti i sistemi operativi. Consulta [Software And Conflicts](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Installazione**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Questo installerà le dipendenze software PyQt necessarie per avviare le GUI di installazione, se non vengono trovate.

Successivamente, seleziona l'opzione che corrisponde meglio al tuo sistema operativo (dovrebbe essere rilevata automaticamente se il tuo sistema operativo corrisponde a una delle opzioni).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

È consigliato installare FISSURE su un sistema operativo pulito per evitare conflitti esistenti. Seleziona tutte le caselle consigliate (pulsante Default) per evitare errori durante l'utilizzo dei vari strumenti all'interno di FISSURE. Durante l'installazione verranno visualizzati diversi prompt, che richiederanno principalmente autorizzazioni elevate e nomi utente. Se un elemento contiene una sezione "Verify" alla fine, l'installer eseguirà il comando successivo ed evidenzierà in verde o rosso la casella dell'elemento, a seconda che il comando produca errori. Gli elementi selezionati senza una sezione "Verify" resteranno neri al termine dell'installazione.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Utilizzo**

Apri un terminale e inserisci:
```
fissure
```
Consulta il menu Help di FISSURE per maggiori dettagli sull'utilizzo.

## Dettagli

**Componenti**

* Dashboard
* Central Hub (HIPRFISR)
* Target Signal Identification (TSI)
* Protocol Discovery (PD)
* Flow Graph & Script Executor (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Funzionalità**

| ![Signal Detector icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Signal Detector**_ | ![IQ Manipulation icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ Manipulation**_      | ![Signal Lookup icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Signal Lookup**_          | ![Pattern Recognition icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Pattern Recognition**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attacks**_           | ![Fuzzing icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Signal Playlists**_       | ![Image Gallery icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Image Gallery**_  |
| ![Packet Crafting icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Packet Crafting**_   | ![Scapy Integration icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy Integration**_ | ![CRC Calculator icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC Calculator**_ | ![Logging icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logging**_            |

**Hardware**

Di seguito è riportato un elenco dell'hardware "supportato", con diversi livelli di integrazione:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* Adattatori 802.11
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Lezioni

FISSURE include diverse guide utili per acquisire familiarità con differenti tecnologie e tecniche. Molte di esse includono istruzioni per l'utilizzo di vari strumenti integrati in FISSURE.

* [Lesson1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lesson2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lesson3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lesson4: ESP Boards](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lesson5: Radiosonde Tracking](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lesson6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lesson7: Data Types](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lesson8: Custom GNU Radio Blocks](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lesson9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lesson10: Ham Radio Exams](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lesson11: Wi-Fi Tools](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## Roadmap

* [ ] Aggiungere altri tipi di hardware, protocolli RF, parametri dei segnali e strumenti di analisi
* [ ] Supportare più sistemi operativi
* [ ] Sviluppare materiale didattico su FISSURE (RF Attacks, Wi-Fi, GNU Radio, PyQt, ecc.)
* [ ] Creare un signal conditioner, un feature extractor e un signal classifier con tecniche AI/ML selezionabili
* [ ] Implementare meccanismi di demodulazione ricorsiva per produrre un bitstream da segnali sconosciuti
* [ ] Trasferire i componenti principali di FISSURE a uno schema di distribuzione basato su nodi sensore generici

## Contributi

I suggerimenti per migliorare FISSURE sono fortemente incoraggiati. Lascia un commento nella pagina [Discussions](https://github.com/ainfosec/FISSURE/discussions) o nel Discord Server se hai osservazioni riguardo a quanto segue:

* Suggerimenti per nuove funzionalità e modifiche al design
* Strumenti software con istruzioni di installazione
* Nuove lezioni o materiale aggiuntivo per le lezioni esistenti
* Protocolli RF di interesse
* Più hardware e tipi di SDR da integrare
* Script di analisi IQ in Python
* Correzioni e miglioramenti dell'installazione

I contributi per migliorare FISSURE sono fondamentali per accelerarne lo sviluppo. Ogni contributo è molto apprezzato. Se desideri contribuire allo sviluppo del codice, esegui il fork del repo e crea una pull request:

1. Esegui il fork del progetto
2. Crea il tuo feature branch (`git checkout -b feature/AmazingFeature`)
3. Esegui il commit delle modifiche (`git commit -m 'Add some AmazingFeature'`)
4. Esegui il push sul branch (`git push origin feature/AmazingFeature`)
5. Apri una pull request

È inoltre benvenuta la creazione di [Issues](https://github.com/ainfosec/FISSURE/issues) per segnalare i bug.

## Collaborazione

Contatta il reparto Business Development di Assured Information Security, Inc. (AIS) per proporre e formalizzare eventuali opportunità di collaborazione con FISSURE, ad esempio dedicando tempo all'integrazione del tuo software, incaricando il talentuoso team di AIS di sviluppare soluzioni per le tue sfide tecniche o integrando FISSURE in altre piattaforme/applicazioni.

## Licenza

GPL-3.0

Per i dettagli sulla licenza, consulta il file LICENSE.

## Contatti

Unisciti al Discord Server: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Segui su Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Riconoscimenti

Riconosciamo e ringraziamo questi sviluppatori:

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Ringraziamenti

Un ringraziamento speciale al Dr. Samuel Mantravadi e a Joseph Reith per i loro contributi a questo progetto.

## Riferimenti

- [1] [FISSURE - The RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE Paper (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)

{{#include ../../banners/hacktricks-training.md}}
