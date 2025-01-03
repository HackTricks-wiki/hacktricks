{{#include ../../../banners/hacktricks-training.md}}

**La manipolazione di file audio e video** è un elemento fondamentale nelle **sfide forensi CTF**, sfruttando **steganografia** e analisi dei metadati per nascondere o rivelare messaggi segreti. Strumenti come **[mediainfo](https://mediaarea.net/en/MediaInfo)** e **`exiftool`** sono essenziali per ispezionare i metadati dei file e identificare i tipi di contenuto.

Per le sfide audio, **[Audacity](http://www.audacityteam.org/)** si distingue come uno strumento principale per visualizzare forme d'onda e analizzare spettrogrammi, essenziali per scoprire testi codificati nell'audio. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** è altamente raccomandato per un'analisi dettagliata degli spettrogrammi. **Audacity** consente la manipolazione audio come rallentare o invertire tracce per rilevare messaggi nascosti. **[Sox](http://sox.sourceforge.net/)**, un'utilità da riga di comando, eccelle nella conversione e modifica di file audio.

La manipolazione dei **Bit meno significativi (LSB)** è una tecnica comune nella steganografia audio e video, sfruttando i chunk di dimensioni fisse dei file multimediali per incorporare dati in modo discreto. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** è utile per decodificare messaggi nascosti come **toni DTMF** o **codice Morse**.

Le sfide video spesso coinvolgono formati contenitore che raggruppano flussi audio e video. **[FFmpeg](http://ffmpeg.org/)** è il punto di riferimento per analizzare e manipolare questi formati, capace di demultiplexare e riprodurre contenuti. Per gli sviluppatori, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** integra le capacità di FFmpeg in Python per interazioni avanzate scriptabili.

Questa gamma di strumenti sottolinea la versatilità richiesta nelle sfide CTF, dove i partecipanti devono impiegare un ampio spettro di tecniche di analisi e manipolazione per scoprire dati nascosti all'interno di file audio e video.

## Riferimenti

- [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
