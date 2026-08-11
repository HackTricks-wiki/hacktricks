# FISSURE - Il framework RF

{{#include ../../banners/hacktricks-training.md}}

**Comprensione e reverse engineering dei segnali basati su SDR e indipendenti dalla frequenza**

FISSURE è un framework open-source per RF e reverse engineering, progettato per tutti i livelli di competenza, con hook per il rilevamento e la classificazione dei segnali, la scoperta dei protocolli, l'esecuzione di attacchi, la manipolazione IQ, l'analisi delle vulnerabilità, l'automazione e l'AI/ML. Il framework è stato creato per promuovere la rapida integrazione di moduli software, radio, protocolli, dati dei segnali, script, flow graph, materiale di riferimento e strumenti di terze parti. FISSURE è un abilitatore dei workflow che mantiene il software in un'unica posizione e permette ai team di acquisire rapidamente le competenze necessarie, condividendo la stessa configurazione di base collaudata per specifiche distribuzioni Linux.<sup>[[1]](#references)[[2]](#references)</sup>

Il framework e gli strumenti inclusi in FISSURE sono progettati per rilevare l'energia RF, caratterizzare i segnali, raccogliere e analizzare i campioni, sviluppare tecniche di trasmissione o injection e creare payload o messaggi personalizzati. FISSURE fornisce inoltre informazioni sui protocolli e sui segnali per l'identificazione, la creazione di pacchetti e il fuzzing, oltre ad archivi e playlist per la simulazione e il testing del traffico.<sup>[[1]](#references)[[2]](#references)</sup>

La codebase Python e l'interfaccia grafica aiutano i principianti a imparare a usare gli strumenti RF e di reverse engineering. Gli educatori possono utilizzare le lezioni integrate, mentre sviluppatori e ricercatori possono integrare i propri moduli e workflow. Le versioni attuali supportano anche nodi sensore distribuiti, l'integrazione con TAK, workflow di geolocalizzazione e deployment Apptainer specifici per ruolo.<sup>[[1]](#references)[[3]](#references)</sup>

**Informazioni aggiuntive**

* [Pagina AIS](https://www.ainfosec.com/technologies/fissure/)
* [Slide GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [Paper GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [Video GRCon22](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Trascrizione dell'Hack Chat](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Per iniziare

**Supportato**

L'attuale FISSURE utilizza il branch **`Python3`** per lo sviluppo attivo con PyQt5 e GNU Radio 3.8 o 3.10. Il branch deprecato **`Python2_maint-3.7`** rimane disponibile per i sistemi operativi meno recenti e gli strumenti di terze parti che richiedono GNU Radio 3.7. I precedenti nomi dei branch `Python3_maint-3.8` e `Python3_maint-3.10` sono storici; la selezione della versione di GNU Radio è ora gestita dal branch `Python3`.<sup>[[1]](#references)[[3]](#references)</sup>

| Sistema operativo | Branch FISSURE | Branch GNU Radio predefinito |
| :--: | :--: | :--: |
| DragonOS Noble (24.04) | Python3 | maint-3.10 |
| Kali | Python3 | maint-3.10 |
| Raspberry Pi OS | Python3 | maint-3.10 |
| Ubuntu 18.04 | Python2\_maint-3.7 | maint-3.7 |
| Ubuntu 20.04 | Python3 | maint-3.8 |
| Ubuntu 22.04 | Python3 | maint-3.10 |
| Ubuntu 24.04 / Ubuntu ARM | Python3 | maint-3.10 |
| Windows 11 WSL2 | usa una versione Linux supportata | usa la versione corrispondente |

**In corso (beta)**

Questi sistemi operativi sono ancora in stato beta. Sono in fase di sviluppo e diverse funzionalità risultano ancora mancanti. Gli elementi dell'installer potrebbero entrare in conflitto con programmi esistenti o non riuscire a installarsi finché lo stato beta non verrà rimosso.

| Sistema operativo | Branch FISSURE | Branch GNU Radio predefinito |
| :--: | :--: | :--: |
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

Alcuni strumenti di terze parti non funzionano su tutti i sistemi operativi. Prima dell'installazione, consulta la documentazione aggiornata relativa a [Conflitti noti e software di terze parti](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts).<sup>[[3]](#references)</sup>

**Installazione**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout Python3  # optional; use Python2_maint-3.7 only for legacy requirements
git submodule update --init
./install
```
Il passaggio del submodule scarica i moduli GNU Radio out-of-tree utilizzati da FISSURE ed è necessario quando si installano tali moduli. L'installer installerà anche le dipendenze PyQt mancanti necessarie per avviare le relative GUI di installazione.<sup>[[3]](#references)</sup>

Successivamente, seleziona l'opzione più adatta al tuo sistema operativo (dovrebbe essere rilevata automaticamente se il tuo sistema operativo corrisponde a una delle opzioni).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

È consigliabile installare FISSURE su un sistema operativo pulito per evitare conflitti preesistenti. Seleziona tutte le caselle consigliate (pulsante Default) per evitare errori durante l'utilizzo dei vari strumenti all'interno di FISSURE. Durante l'installazione verranno visualizzate diverse richieste, principalmente relative a permessi elevati e nomi utente. Se un elemento contiene una sezione "Verify" alla fine, l'installer eseguirà il comando indicato e evidenzierà in verde o rosso la casella dell'elemento, a seconda che il comando produca errori. Gli elementi selezionati senza una sezione "Verify" rimarranno neri al termine dell'installazione.

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
* Identificazione dei segnali target (TSI)
* Individuazione dei protocolli (PD)
* Flow Graph & Script Executor (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Funzionalità**

| ![Signal Detector icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Rilevatore di segnali**_ | ![IQ Manipulation icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Manipolazione IQ**_      | ![Signal Lookup icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Ricerca dei segnali**_          | ![Pattern Recognition icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Riconoscimento dei pattern**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attacchi**_           | ![Fuzzing icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Playlist di segnali**_       | ![Image Gallery icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Galleria di immagini**_  |
| ![Packet Crafting icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Creazione di pacchetti**_   | ![Scapy Integration icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Integrazione con Scapy**_ | ![CRC Calculator icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Calcolatore CRC**_ | ![Logging icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logging**_            |

**Hardware**

Il seguente hardware presenta diversi livelli di integrazione in FISSURE:<sup>[[1]](#references)[[3]](#references)</sup>

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx, X410
* HackRF
* RTL2832U
* Adattatori 802.11
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR
* SDRplay: RSPduo, RSPdx, RSPdx R2

## Lezioni

FISSURE include diverse guide utili per acquisire familiarità con tecnologie e tecniche differenti. Molte includono passaggi per utilizzare vari strumenti integrati in FISSURE.

* [Lezione 1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lezione 2: Dissectors Lua](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lezione 3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lezione 4: Schede ESP](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lezione 5: Tracciamento dei radiosonde](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lezione 6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lezione 7: Tipi di dati](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lezione 8: Blocchi GNU Radio personalizzati](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lezione 9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lezione 10: Esami di radioamatore](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lezione 11: Strumenti Wi-Fi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)
* [Lezione 12: Creazione di USB avviabili](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson12_Creating_Bootable_USBs.md)
* [Lezione 13: Z-Wave](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson13_Z-Wave.md)
* [Lezione 14: Ventilatori da soffitto](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson14_Ceiling_Fans.md)

## Roadmap

* [ ] Aggiungere altri tipi di hardware, protocolli RF, parametri dei segnali e strumenti di analisi
* [ ] Supportare più sistemi operativi
* [ ] Sviluppare materiale didattico su FISSURE (attacchi RF, Wi-Fi, GNU Radio, PyQt, ecc.)
* [ ] Creare un signal conditioner, un feature extractor e un signal classifier con tecniche AI/ML selezionabili
* [ ] Implementare meccanismi di demodulazione ricorsiva per produrre un bitstream da segnali sconosciuti
* [ ] Trasferire i componenti principali di FISSURE a uno schema generico di distribuzione di nodi sensore

## Contribuire

I suggerimenti per migliorare FISSURE sono fortemente incoraggiati. Lascia un commento nella pagina [Discussions](https://github.com/ainfosec/FISSURE/discussions) o nel Discord Server se hai idee riguardo a quanto segue:

* Suggerimenti per nuove funzionalità e modifiche al design
* Strumenti software con istruzioni per l'installazione
* Nuove lezioni o materiale aggiuntivo per le lezioni esistenti
* Protocolli RF di interesse
* Altri tipi di hardware e SDR da integrare
* Script di analisi IQ in Python
* Correzioni e miglioramenti dell'installazione

I contributi per migliorare FISSURE sono fondamentali per accelerarne lo sviluppo. Ogni contributo è molto apprezzato. Se desideri contribuire allo sviluppo del codice, esegui il fork del repo e crea una pull request:

1. Esegui il fork del progetto
2. Crea il tuo feature branch (`git checkout -b feature/AmazingFeature`)
3. Esegui il commit delle modifiche (`git commit -m 'Add some AmazingFeature'`)
4. Esegui il push del branch (`git push origin feature/AmazingFeature`)
5. Apri una pull request

Anche la creazione di [Issues](https://github.com/ainfosec/FISSURE/issues) per segnalare i bug è benvenuta.

## Collaborare

Contatta il Business Development di Assured Information Security, Inc. (AIS) per proporre e formalizzare eventuali opportunità di collaborazione con FISSURE, sia dedicando tempo all'integrazione del tuo software, sia affidando alle persone esperte di AIS lo sviluppo di soluzioni per le tue sfide tecniche, sia integrando FISSURE in altre piattaforme/applicazioni.

## Licenza

GPL-3.0

Per i dettagli sulla licenza, consulta il file LICENSE.

## Contatti

Unisciti al Discord Server: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Segui su Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Crediti

Riconosciamo e ringraziamo questi sviluppatori:

[Crediti](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Ringraziamenti

Un ringraziamento speciale al Dr. Samuel Mantravadi e a Joseph Reith per i loro contributi a questo progetto.

## References

- [1] [FISSURE - The RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE Paper (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [3] [FISSURE documentation - Installation](https://fissure.readthedocs.io/en/latest/pages/installation.html)
{{#include ../../banners/hacktricks-training.md}}
