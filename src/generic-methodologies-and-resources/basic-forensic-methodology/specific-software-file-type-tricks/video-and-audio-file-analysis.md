# Analisi dei file video e audio

{{#include ../../../banners/hacktricks-training.md}}

La **manipolazione dei file audio e video** è una tecnica fondamentale nelle **sfide di digital forensics dei CTF**, che sfrutta la **steganography** e l'analisi dei metadata per nascondere o rivelare messaggi segreti. Strumenti come **[mediainfo](https://mediaarea.net/en/MediaInfo)** ed **`exiftool`** sono essenziali per esaminare i metadata dei file e identificare i tipi di contenuto.<sup>[[1]](#references)</sup>

Per le sfide audio, **[Audacity](http://www.audacityteam.org/)** si distingue come strumento di riferimento per visualizzare le forme d'onda e analizzare gli spettrogrammi, operazioni essenziali per scoprire testo codificato nell'audio. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** è altamente consigliato per un'analisi dettagliata degli spettrogrammi. **Audacity** consente di manipolare l'audio, ad esempio rallentando o invertendo le tracce, per rilevare messaggi nascosti. **[Sox](http://sox.sourceforge.net/)**, un'utilità a riga di comando, è eccellente per convertire e modificare file audio.<sup>[[1]](#references)</sup>

La manipolazione dei **Least Significant Bits (LSB)** è una tecnica comune nella steganography audio e video, che sfrutta i blocchi di dimensione fissa dei file multimediali per incorporare dati in modo discreto. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** è utile per decodificare messaggi nascosti come **toni DTMF** o **codice Morse**.<sup>[[1]](#references)</sup>

Le sfide video spesso coinvolgono formati container che raggruppano stream audio e video. **[FFmpeg](http://ffmpeg.org/)** è lo strumento di riferimento per analizzare e manipolare questi formati, poiché è in grado di effettuare il de-multiplexing e riprodurre i contenuti. Per gli sviluppatori, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** integra le funzionalità di FFmpeg in Python per interazioni avanzate tramite script.<sup>[[1]](#references)</sup>

Questo insieme di strumenti sottolinea la versatilità richiesta nelle sfide CTF, in cui i partecipanti devono impiegare un ampio spettro di tecniche di analisi e manipolazione per scoprire dati nascosti all'interno di file audio e video.

## References

- [1] [Analisi dei file video e audio – Trail of Bits CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
{{#include ../../../banners/hacktricks-training.md}}
