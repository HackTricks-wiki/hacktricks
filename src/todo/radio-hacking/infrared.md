# Infrared

{#include ../../../../../../home/runner/work/HackTricks-Feed/HackTricks-Feed/src/banners/hacktricks-training.md}

## How the Infrared Works <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Infrared light is invisible to humans**. IR wavelength is from **0.7 to 1000 microns**. Household remotes use an IR signal for data transmission and operate in the wavelength range of 0.75..1.4 microns. A microcontroller in the remote makes an infrared LED blink with a specific frequency, turning the digital signal into an IR signal.

To receive IR signals a **photoreceiver** is used. It **converts IR light into voltage pulses**, which are already **digital signals**. Usually, there is a **dark light filter inside the receiver**, which lets **only the desired wavelength through** and cuts out noise.

### Variety of IR Protocols <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR protocols differ in 3 factors:

- bit encoding
- data structure
- carrier frequency — often in range 36..38 kHz

#### Bit encoding ways <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

Bits are encoded by modulating the duration of the space between pulses. The width of the pulse itself is constant.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

Bits are encoded by modulation of the pulse width. The width of space after pulse burst is constant.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

It is also known as Manchester encoding. The logical value is defined by the polarity of the transition between pulse burst and space. "Space to pulse burst" denotes logic "0", "pulse burst to space" denotes logic "1".

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Combination of previous ones and other exotics**

> [!TIP]
> There are IR protocols that are **trying to become universal** for several types of devices. The most famous ones are RC5 and NEC. Unfortunately, the most famous **does not mean the most common**. In my environment, I met just two NEC remotes and no RC5 ones.
>
> Manufacturers love to use their own unique IR protocols, even within the same range of devices (for example, TV-boxes). Therefore, remotes from different companies and sometimes from different models from the same company, are unable to work with other devices of the same type.

### Exploring an IR signal

The most reliable way to see how the remote IR signal looks like is to use an oscilloscope. It does not demodulate or invert the received signal, it is just displayed "as is". This is useful for testing and debugging. I will show the expected signal on the example of the NEC IR protocol.

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Usually, there is a preamble at the beginning of an encoded packet. This allows the receiver to determine the level of gain and background. There are also protocols without preamble, for example, Sharp.

Then data is transmitted. The structure, preamble, and bit encoding method are determined by the specific protocol.

**NEC IR protocol** contains a short command and a repeat code, which is sent while the button is pressed. Both the command and the repeat code have the same preamble at the beginning.

NEC **command**, in addition to the preamble, consists of an address byte and a command-number byte, by which the device understands what needs to be performed. Address and command-number bytes are duplicated with inverse values, to check the integrity of the transmission. There is an additional stop bit at the end of the command.

The **repeat code** has a "1" after the preamble, which is a stop bit.

For **logic "0" and "1"** NEC uses Pulse Distance Encoding: first, a pulse burst is transmitted after which there is a pause, its length sets the value of the bit.

### Air Conditioners

Unlike other remotes, **air conditioners do not transmit just the code of the pressed button**. They also **transmit all the information** when a button is pressed to assure that the **air conditioned machine and the remote are synchronised**.\
This will avoid that a machine set as 20ºC is increased to 21ºC with one remote, and then when another remote, which still has the temperature as 20ºC, is used to increase more the temperature, it will "increase" it to 21ºC (and not to 22ºC thinking it's in 21ºC).

### Attacks

You can attack Infrared with Flipper Zero:

{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

## References

- [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

{#include ../../../../../../home/runner/work/HackTricks-Feed/HackTricks-Feed/src/banners/hacktricks-training.md}


