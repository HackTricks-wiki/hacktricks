{{#include ../../../banners/hacktricks-training.md}}

**Audio- en video-lêermanipulasie** is 'n noodsaaklike deel van **CTF forensiese uitdagings**, wat **steganografie** en metadata-analise benut om geheime boodskappe te verberg of te onthul. Gereedskap soos **[mediainfo](https://mediaarea.net/en/MediaInfo)** en **`exiftool`** is noodsaaklik om lêermetadata te ondersoek en inhoudstipes te identifiseer.

Vir audio-uitdagings, **[Audacity](http://www.audacityteam.org/)** is 'n uitstaande hulpmiddel om golfforme te sien en spektrogramme te analiseer, wat noodsaaklik is om teks wat in audio gekodeer is, te ontdek. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** word sterk aanbeveel vir gedetailleerde spektrogramanalise. **Audacity** maak dit moontlik om audio te manipuleer, soos om snitte te vertraag of om te keer om versteekte boodskappe te ontdek. **[Sox](http://sox.sourceforge.net/)**, 'n opdraglyn-hulpmiddel, presteer uitstekend in die omskakeling en redigering van audiolêers.

**Least Significant Bits (LSB)** manipulasie is 'n algemene tegniek in audio- en video-steganografie, wat die vaste-grootte stukke van media-lêers benut om data diskreet in te sluit. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** is nuttig om boodskappe wat as **DTMF toon** of **Morse kode** versteek is, te dekodeer.

Video-uitdagings behels dikwels houerformate wat audio- en video-strome saamvoeg. **[FFmpeg](http://ffmpeg.org/)** is die voorkeur vir die analise en manipulasie van hierdie formate, wat in staat is om te demultiplex en inhoud af te speel. Vir ontwikkelaars integreer **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** die vermoëns van FFmpeg in Python vir gevorderde skripbare interaksies.

Hierdie verskeidenheid gereedskap beklemtoon die veelsydigheid wat benodig word in CTF-uitdagings, waar deelnemers 'n breë spektrum van analise- en manipulasietegnieke moet gebruik om versteekte data binne audio- en video-lêers te ontdek.

## References

- [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
