

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**Audio and video file manipulation** is a staple in **CTF forensics challenges**, leveraging **steganography** and metadata analysis to hide or reveal secret messages. Tools such as **[mediainfo](https://mediaarea.net/en/MediaInfo)** and **`exiftool`** are essential for inspecting file metadata and identifying content types.

For audio challenges, **[Audacity](http://www.audacityteam.org/)** stands out as a premier tool for viewing waveforms and analyzing spectrograms, essential for uncovering text encoded in audio. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** is highly recommended for detailed spectrogram analysis. **Audacity** allows for audio manipulation like slowing down or reversing tracks to detect hidden messages. **[Sox](http://sox.sourceforge.net/)**, a command-line utility, excels in converting and editing audio files.

**Least Significant Bits (LSB)** manipulation is a common technique in audio and video steganography, exploiting the fixed-size chunks of media files to embed data discreetly. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** is useful for decoding messages hidden as **DTMF tones** or **Morse code**.

Video challenges often involve container formats that bundle audio and video streams. **[FFmpeg](http://ffmpeg.org/)** is the go-to for analyzing and manipulating these formats, capable of de-multiplexing and playing back content. For developers, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** integrates FFmpeg's capabilities into Python for advanced scriptable interactions.

This array of tools underscores the versatility required in CTF challenges, where participants must employ a broad spectrum of analysis and manipulation techniques to uncover hidden data within audio and video files.

## References
* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)


<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


