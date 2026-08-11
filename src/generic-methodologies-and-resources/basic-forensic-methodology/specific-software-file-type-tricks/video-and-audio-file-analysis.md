# Аналіз відео- та аудіофайлів

{{#include ../../../banners/hacktricks-training.md}}

**Маніпуляції з аудіо- та відеофайлами** є стандартною практикою у **CTF forensics challenges**, де для приховування або виявлення секретних повідомлень використовуються **steganography** та аналіз metadata. Інструменти на кшталт **[mediainfo](https://mediaarea.net/en/MediaInfo)** і **`exiftool`** необхідні для перевірки metadata файлів та визначення типів вмісту.<sup>[[1]](#references)</sup>

Для аудіочеленджів **[Audacity](http://www.audacityteam.org/)** є одним із найкращих інструментів для перегляду waveforms і аналізу spectrograms, що необхідно для виявлення тексту, закодованого в аудіо. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** рекомендується для детального аналізу spectrograms. **Audacity** дає змогу маніпулювати аудіо, наприклад сповільнювати або відтворювати треки у зворотному напрямку, щоб виявити приховані повідомлення. **[Sox](http://sox.sourceforge.net/)**, утиліта командного рядка, чудово підходить для конвертування та редагування аудіофайлів.<sup>[[1]](#references)</sup>

Маніпуляція **Least Significant Bits (LSB)** є поширеною технікою в аудіо- та відеостеганографії, яка використовує фрагменти медіафайлів фіксованого розміру для непомітного вбудовування даних. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** корисний для декодування повідомлень, прихованих у вигляді **DTMF tones** або **Morse code**.<sup>[[1]](#references)</sup>

Відеочеленджі часто передбачають роботу з container formats, які об'єднують аудіо- та відеопотоки. **[FFmpeg](http://ffmpeg.org/)** є основним інструментом для аналізу та маніпуляцій із цими форматами; він підтримує de-multiplexing і відтворення вмісту. Для розробників **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** інтегрує можливості FFmpeg у Python для розширеної взаємодії за допомогою скриптів.<sup>[[1]](#references)</sup>

Цей набір інструментів підкреслює універсальність, необхідну в CTF challenges, де учасники мають застосовувати широкий спектр технік аналізу та маніпуляцій для виявлення прихованих даних в аудіо- та відеофайлах.

## References

- [1] [Аналіз відео- та аудіофайлів – CTF Field Guide від Trail of Bits](https://trailofbits.github.io/ctf/forensics/)
{{#include ../../../banners/hacktricks-training.md}}
