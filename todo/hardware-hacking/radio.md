# Radio

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)is a free digital signal analyzer for GNU/Linux and macOS, designed to extract information of unknown radio signals. It supports a variety of SDR devices through SoapySDR, and allows adjustable demodulation of FSK, PSK and ASK signals, decode analog video, analyze bursty signals and listen to analog voice channels (all in real time).

### Basic Config

After installing there are a few things that you could consider configuring.\
In settings (the second tab button) you can select the **SDR device** or **select a file** to read and which frequency to syntonise and the Sample rate (recommended to up to 2.56Msps if your PC support it)\\

![](<../../.gitbook/assets/image (655) (1).png>)

In the GUI behaviour it's recommended to enable a few things if your PC support it:

![](<../../.gitbook/assets/image (465) (2).png>)

{% hint style="info" %}
If you realise that your PC is not capturing things try to disable OpenGL and lowering the sample rate.
{% endhint %}

### Uses

* Just to **capture some time of a signal and analyze it** just maintain the button "Push to capture" as long as you need.

![](<../../.gitbook/assets/image (631).png>)

* The **Tuner** of SigDigger helps to **capture better signals** (but it can also degrade them). Ideally start with 0 and keep **making it bigger until** you find the **noise** introduce is **bigger** than the **improvement of the signal** you need).

![](<../../.gitbook/assets/image (658).png>)

### Synchronize with radio channel

With [**SigDigger** ](https://github.com/BatchDrake/SigDigger)synchronize with the channel you want to hear, configure "Baseband audio preview" option, configure the bandwith to get all the info being sent and then set the Tuner to the level before the noise is really starting to increase:

![](<../../.gitbook/assets/image (389).png>)

## Interesting tricks

* When a device is sending bursts of information, usually the **first part is going to be a preamble** so you **don't** need to **worry** if you **don't find information** in there **or if there are some errors** there.
* In frames of information you usually should **find different frames well aligned between them**:

![](<../../.gitbook/assets/image (660) (1).png>)

![](<../../.gitbook/assets/image (652) (1) (1).png>)

* **After recovering the bits you might need to process them someway**. For example, in Manchester codification a up+down will be a 1 or 0 and a down+up will be the other one. So pairs of 1s and 0s (ups and downs) will be a real 1 or a real 0.
* Even if a signal is using Manchester codification (it's impossible to find more than two 0s or 1s in a row), you might **find several 1s or 0s together in the preamble**!

### Uncovering modulation type with IQ

There are 3 ways to store information in signals: Modulating the **amplitude**, **frequency** or **phase**.\
If you are checking a signal there are different ways to try to figure out what is being used to store information (fin more ways below) but a good one is to check the IQ graph.

![](<../../.gitbook/assets/image (630).png>)

* **Detecting AM**: If in the IQ graph appears for example **2 circles** (probably one in 0 and other in a different amplitude), it could means that this is an AM signal. This is because in the IQ graph the distance between the 0 and the circle is the amplitude of the signal, so it's easy to visualize different amplitudes being used.
* **Detecting PM**: Like in the previous image, if you find small circles not related between them it probably means that a phase modulation is used. This is because in the IQ graph, the angle between the point and the 0,0 is the phase of the signal, so that means that 4 different phases are used.
  * Note that if the information is hidden in the fact that a phase is changed and not in the phase itself, you won't see different phases clearly differentiated.
* **Detecting FM**: IQ doesn't have a field to identify frequencies (distance to centre is amplitude and angle is phase).\
  Therefore, to identify FM, you should **only see basically a circle** in this graph.\
  Moreover, a different frequency is "represented" by the IQ graph by a **speed acceleration across the circle** (so in SysDigger selecting the signal the IQ graph is populated, if you find an acceleration or change of direction in the created circle it could mean that this is FM):

## AM Example

{% file src="../../.gitbook/assets/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### Uncovering AM

#### Checking the envelope

Checking AM info with [**SigDigger** ](https://github.com/BatchDrake/SigDigger)and just looking at the **envelop** you can see different clear amplitude levels. The used signal is sending pulses with information in AM, this is how one pulse looks like:

![](<../../.gitbook/assets/image (636).png>)

And this is how part of the symbol looks like with the waveform:

![](<../../.gitbook/assets/image (650) (1).png>)

#### Checking the Histogram

You can **select the whole signal** where information is located, select **Amplitude** mode and **Selection** and click on **Histogram.** You can observer that 2 clear levels are only found

![](<../../.gitbook/assets/image (647) (1) (1).png>)

For example, if you select Frequency instead of Amplitude in this AM signal you find just 1 frequency (no way information modulated in frequency is just using 1 freq).

![](<../../.gitbook/assets/image (637) (1) (1).png>)

If you find a lot of frequencies potentially this won't be a FM, probably the signal frequency was just modified because of the channel.

#### With IQ

In this example you can see how there is a **big circle** but also **a lot of points in the centre.**

![](<../../.gitbook/assets/image (640).png>)

### Get Symbol Rate

#### With one symbol

Select the smallest symbol you can find (so you are sure it's just 1) and check the "Selection freq". I this case it would be 1.013kHz (so 1kHz).

![](<../../.gitbook/assets/image (638) (1).png>)

#### With a group of symbols

You can also indicate the number of symbols you are going to select and SigDigger will calculate the frequency of 1 symbol (the more symbols selected the better probably). In this scenario I selected 10 symbols and the "Selection freq" is 1.004 Khz:

![](<../../.gitbook/assets/image (635).png>)

### Get Bits

Having found this is an **AM modulated** signal and the **symbol rate** (and knowing that in this case something up means 1 and something down means 0), it's very easy to **obtain the bits** encoded in the signal. So, select the signal with info and configure the sampling and decision and press sample (check that **Amplitude** is selected, the discovered **Symbol rate** is configured and the **Gadner clock recovery** is selected):

![](<../../.gitbook/assets/image (642) (1).png>)

* **Sync to selection intervals** means that if you previously selected intervals to find the symbol rate, that symbol rate will be used.
* **Manual** means that the indicated symbol rate is going to be used
* In **Fixed interval selection** you indicate the number of intervals that should be selected and it calculates the symbol rate from it
* **Gadner clock recovery** is usually the best option, but you still need to indicate some approximate symbol rate.

Pressing sample this appears:

![](<../../.gitbook/assets/image (659).png>)

Now, to make SigDigger understand **where is the range** of the level carrying information you need to click on the **lower level** and maintain clicked until the biggest level:

![](<../../.gitbook/assets/image (662) (1) (1) (1).png>)

If there would have been for example **4 different levels of amplitude**, you should have need to configure the **Bits per symbol to 2** and select from the smallest to the biggest.

Finally **increasing** the **Zoom** and **changing the Row size** you can see the bits (and you can select all and copy to get all the bits):

![](<../../.gitbook/assets/image (649) (1).png>)

If the signal has more than 1 bit per symbol (for example 2), SigDigger has **no way to know which symbol is** 00, 01, 10, 11, so it will use different **grey scales** the represent each (and if you copy the bits it will use **numbers from 0 to 3**, you will need to treat them).

Also, use **codifications** such as **Manchester**, and **up+down** can be **1 or 0** and an down+up can be a 1 or 0. In those cases you need to **treat the obtained ups (1) and downs (0)** to substitute the pairs of 01 or 10 as 0s or 1s.

## FM Example

{% file src="../../.gitbook/assets/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### Uncovering FM

#### Checking the frequencies and waveform

Signal example sending information modulated in FM:

![](<../../.gitbook/assets/image (661) (1).png>)

In the previous image you can observe pretty good that **2 frequencies are used** but if you **observe** the **waveform** you might n**ot be able to identify correctly the 2 different frequencies**:

![](<../../.gitbook/assets/image (653).png>)

This is because I capture the signal in booth frequencies, therefore one is approximately the other in negative:

![](<../../.gitbook/assets/image (656).png>)

If the synchronized frequency is **closer to one frequency than to the other** you can easily see the 2 different frequencies:

![](<../../.gitbook/assets/image (648) (1) (1) (1).png>)

![](<../../.gitbook/assets/image (634).png>)

#### Checking the histogram

Checking the frequency histogram of the signal with information you can easily see 2 different signals:

![](<../../.gitbook/assets/image (657).png>)

In this case if you check the **Amplitude histogram** you will find **only one amplitude**, so it **cannot be AM** (if you find a lot of amplitudes it might be because the signal has been losing power along the channel):

![](<../../.gitbook/assets/image (646).png>)

And this is would be phase histogram (which makes very clear the signal is not modulated in phase):

![](<../../.gitbook/assets/image (201) (2).png>)

#### With IQ

IQ doesn't have a field to identify frequencies (distance to centre is amplitude and angle is phase).\
Therefore, to identify FM, you should **only see basically a circle** in this graph.\
Moreover, a different frequency is "represented" by the IQ graph by a **speed acceleration across the circle** (so in SysDigger selecting the signal the IQ graph is populated, if you find an acceleration or change of direction in the created circle it could mean that this is FM):

![](<../../.gitbook/assets/image (643) (1).png>)

### Get Symbol Rate

You can use the **same technique as the one used in the AM example** to get the symbol rate once you have found the frequencies carrying symbols.

### Get Bits

You can use the **same technique as the one used in the AM example** to get the bits once you have **found the signal is modulated in frequency** and the **symbol rate**.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
