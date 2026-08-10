# Analisi di file video e audio

La **manipolazione dei file audio e video** è un elemento fondamentale nelle **CTF forensics challenges**, poiché sfrutta la **steganography** e l'analisi dei metadati per nascondere o rivelare messaggi segreti. Strumenti come **[mediainfo](https://mediaarea.net/en/MediaInfo)** ed **`exiftool`** sono essenziali per esaminare i metadati dei file e identificare i tipi di contenuto.<sup>[[1]](#references)</sup>

Per le challenge audio, **[Audacity](http://www.audacityteam.org/)** si distingue come strumento di riferimento per visualizzare le forme d'onda e analizzare gli spettrogrammi, attività essenziali per scoprire testo codificato nell'audio. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** è altamente consigliato per un'analisi dettagliata degli spettrogrammi. **Audacity** consente di manipolare l'audio, ad esempio rallentando o invertendo le tracce per rilevare messaggi nascosti. **[Sox](http://sox.sourceforge.net/)**, un'utility da riga di comando, è eccellente per convertire e modificare file audio.<sup>[[1]](#references)</sup>

La manipolazione dei **Least Significant Bits (LSB)** è una tecnica comune nella steganography audio e video, che sfrutta i chunk di dimensione fissa dei file multimediali per incorporare dati in modo discreto. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** è utile per decodificare messaggi nascosti come **toni DTMF** o **codice Morse**.<sup>[[1]](#references)</sup>

Le challenge video spesso coinvolgono formati contenitore che raggruppano flussi audio e video. **[FFmpeg](http://ffmpeg.org/)** è lo strumento di riferimento per analizzare e manipolare questi formati, in grado di demultiplexare e riprodurre i contenuti. Per gli sviluppatori, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** integra le funzionalità di FFmpeg in Python per interazioni avanzate tramite script.<sup>[[1]](#references)</sup>

Questo insieme di strumenti sottolinea la versatilità richiesta nelle challenge CTF, in cui i partecipanti devono utilizzare un'ampia gamma di tecniche di analisi e manipolazione per scoprire dati nascosti nei file audio e video.

## References

- [1] [Analisi dei file video e audio – Trail of Bits CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
{{#include ../../../banners/hacktricks-training.md}}
