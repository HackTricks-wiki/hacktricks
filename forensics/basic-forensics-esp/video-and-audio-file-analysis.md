# Video and Audio file analysis

From: [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

Like image file formats, audio and video file trickery is a common theme in CTF forensics challenges not because hacking or data hiding ever happens this way in the real world, but just because audio and video is fun. As with image file formats, stegonagraphy might be used to embed a secret message in the content data, and again you should know to check the file metadata areas for clues. Your first step should be to take a look with the [mediainfo](https://mediaarea.net/en/MediaInfo) tool \(or `exiftool`\) and identify the content type and look at its metadata.

[Audacity](http://www.audacityteam.org/) is the premiere open-source audio file and waveform-viewing tool, and CTF challenge authors love to encode text into audio waveforms, which you can see using the spectogram view \(although a specialized tool called [Sonic Visualiser](http://www.sonicvisualiser.org/) is better for this task in particular\). Audacity can also enable you to slow down, reverse, and do other manipulations that might reveal a hidden message if you suspect there is one \(if you can hear garbled audio, interference, or static\). [Sox](http://sox.sourceforge.net/) is another useful command-line tool for converting and manipulating audio files.

It's also common to check least-significant-bits \(LSB\) for a secret message. Most audio and video media formats use discrete \(fixed-size\) "chunks" so that they can be streamed; the LSBs of those chunks are a common place to smuggle some data without visibly affecting the file.

Other times, a message might be encoded into the audio as [DTMF tones](http://dialabc.com/sound/detect/index.html) or morse code. For these, try working with [multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng) to decode them.

Video file formats are really container formats, that contain separate streams of both audio and video that are multiplexed together for playback. For analyzing and manipulating video file formats, [ffmpeg](http://ffmpeg.org/) is recommended. `ffmpeg -i` gives initial analysis of the file content. It can also de-multiplex or playback the content streams. The power of ffmpeg is exposed to Python using [ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html).

