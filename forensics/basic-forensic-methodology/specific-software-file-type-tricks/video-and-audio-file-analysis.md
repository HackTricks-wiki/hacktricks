

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


From: [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

Like image file formats, audio and video file trickery is a common theme in CTF forensics challenges not because hacking or data hiding ever happens this way in the real world, but just because audio and video are fun. As with image file formats, steganography might be used to embed a secret message in the content data, and again you should know to check the file metadata areas for clues. Your first step should be to take a look with the [mediainfo](https://mediaarea.net/en/MediaInfo) tool \(or `exiftool`\) and identify the content type and look at its metadata.

[Audacity](http://www.audacityteam.org/) is the premier open-source audio file and waveform-viewing tool. CTF challenge authors love to encode text into audio waveforms, which you can see using the spectrogram view \(although a specialized tool called [Sonic Visualiser](http://www.sonicvisualiser.org/) is better for this task in particular\). Audacity can also enable you to slow down, reverse, and do other manipulations that might reveal a hidden message if you suspect there is one \(if you can hear garbled audio, interference, or static\). [Sox](http://sox.sourceforge.net/) is another useful command-line tool for converting and manipulating audio files.

It's also common to check Least Significant Bits (LSB) for a secret message. Most audio and video media formats use discrete (fixed-size) "chunks" so that they can be streamed; the LSBs of those chunks are a common place to smuggle some data without visibly affecting the file.

Other times, a message might be encoded into the audio as [DTMF tones](http://dialabc.com/sound/detect/index.html) or morse code. For these, try working with [multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng) to decode them.

Video file formats are container formats, that contain separate streams of both audio and video that are multiplexed together for playback. For analyzing and manipulating video file formats, [FFmpeg](http://ffmpeg.org/) is recommended. `ffmpeg -i` gives an initial analysis of the file content. It can also de-multiplex or playback the content streams. The power of FFmpeg is exposed to Python using [ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html).



<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


