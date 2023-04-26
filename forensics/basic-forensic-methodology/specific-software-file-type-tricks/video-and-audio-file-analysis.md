

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


From: [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

Like image file formats, audio and video file trickery is a common theme in CTF forensics challenges not because hacking or data hiding ever happens this way in the real world, but just because audio and video are fun. As with image file formats, steganography might be used to embed a secret message in the content data, and again you should know to check the file metadata areas for clues. Your first step should be to take a look with the [mediainfo](https://mediaarea.net/en/MediaInfo) tool \(or `exiftool`\) and identify the content type and look at its metadata.

[Audacity](http://www.audacityteam.org/) is the premier open-source audio file and waveform-viewing tool. CTF challenge authors love to encode text into audio waveforms, which you can see using the spectrogram view \(although a specialized tool called [Sonic Visualiser](http://www.sonicvisualiser.org/) is better for this task in particular\). Audacity can also enable you to slow down, reverse, and do other manipulations that might reveal a hidden message if you suspect there is one \(if you can hear garbled audio, interference, or static\). [Sox](http://sox.sourceforge.net/) is another useful command-line tool for converting and manipulating audio files.

It's also common to check Least Significant Bits (LSB) for a secret message. Most audio and video media formats use discrete (fixed-size) "chunks" so that they can be streamed; the LSBs of those chunks are a common place to smuggle some data without visibly affecting the file.

Other times, a message might be encoded into the audio as [DTMF tones](http://dialabc.com/sound/detect/index.html) or morse code. For these, try working with [multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng) to decode them.

Video file formats are container formats, that contain separate streams of both audio and video that are multiplexed together for playback. For analyzing and manipulating video file formats, [FFmpeg](http://ffmpeg.org/) is recommended. `ffmpeg -i` gives an initial analysis of the file content. It can also de-multiplex or playback the content streams. The power of FFmpeg is exposed to Python using [ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html).



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


