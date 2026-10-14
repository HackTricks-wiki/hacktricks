# Infrared

{{#include ../../banners/hacktricks-training.md}}

## How the Infrared Works <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Infrared light is invisible to humans**. IR wavelength is from **0.7 to 1000 microns**. Household remotes use an IR signal for data transmission and operate in the wavelength range of 0.75..1.4 microns. A microcontroller in the remote makes an infrared LED blink with a specific frequency, turning the digital signal into an IR signal.

To receive IR signals a **photoreceiver** is used. It **converts IR light into voltage pulses**, which are already **digital signals**. Usually, there is a **dark light filter inside the receiver**, which lets **only the desired wavelength through** and cuts out noise.<sup>[[1]](#references)</sup>

### Variety of IR Protocols <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR protocols differ in 3 factors:<sup>[[1]](#references)</sup>

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

The most reliable way to see how the remote IR signal looks like is to use an oscilloscope. It does not demodulate or invert the received signal, it is just displayed "as is". This is useful for testing and debugging. I will show the expected signal on the example of the NEC IR protocol.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Usually, there is a preamble at the beginning of an encoded packet. This allows the receiver to determine the level of gain and background. There are also protocols without preamble, for example, Sharp.

Then data is transmitted. The structure, preamble, and bit encoding method are determined by the specific protocol.

**NEC IR protocol** contains a short command and a repeat code, which is sent while the button is pressed. Both the command and the repeat code have the same preamble at the beginning.

NEC **command**, in addition to the preamble, consists of an address byte and a command-number byte, by which the device understands what needs to be performed. Address and command-number bytes are duplicated with inverse values, to check the integrity of the transmission. There is an additional stop bit at the end of the command.

The **repeat code** has a "1" after the preamble, which is a stop bit.

For **logic "0" and "1"** NEC uses Pulse Distance Encoding: first, a pulse burst is transmitted after which there is a pause, its length sets the value of the bit.

### Air Conditioners

Unlike other remotes, **air conditioners do not transmit just the code of the pressed button**. They also **transmit all the information** when a button is pressed to assure that the **air conditioned machine and the remote are synchronised**.\
This will avoid that a machine set as 20ºC is increased to 21ºC with one remote, and then when another remote, which still has the temperature as 20ºC, is used to increase more the temperature, it will "increase" it to 21ºC (and not to 22ºC thinking it's in 21ºC).<sup>[[1]](#references)</sup>

---

## Attacks & Offensive Research <a href="#attacks" id="attacks"></a>

You can attack Infrared with Flipper Zero:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Smart-TV / Set-top Box Takeover (EvilScreen)

Recent academic work (EvilScreen, 2022) demonstrated that **multi-channel remotes that combine Infrared with Bluetooth or Wi-Fi can be abused to fully hijack modern smart-TVs**. The attack chains high-privilege IR service codes together with authenticated Bluetooth packets, bypassing channel-isolation and allowing arbitrary app launches, microphone activation, or factory-reset without physical access. Eight mainstream TVs from different vendors — including a Samsung model claiming ISO/IEC 27001 compliance — were confirmed vulnerable. Mitigation requires vendor firmware fixes or completely disabling unused IR receivers.<sup>[[2]](#references)</sup>

### Air-Gapped Data Exfiltration via IR LEDs (aIR-Jumper family)

Security cameras commonly include **night-vision IR LEDs**. The aIR-Jumper prototype showed that malware controlling those LEDs could **exfiltrate secrets through windows** to an external camera at up to **20 bit/s per surveillance camera** over tens of metres. In the reverse direction, the researchers demonstrated infiltration at more than **100 bit/s** over distances from hundreds of metres to kilometres.<sup>[[3]](#references)</sup> Because the light is outside the visible spectrum, operators may not notice it. Countermeasures include:

* Physically shield or remove IR LEDs in sensitive areas
* Monitor camera LED duty-cycle and firmware integrity
* Deploy IR-cut filters on windows and surveillance cameras

An attacker can also use strong IR projectors to **infiltrate** commands into the network by flashing data back to insecure cameras. 

### Long-Range Brute-Force & Extended Protocols with Flipper Zero 1.0

Firmware 1.0 (September 2024) expanded the universal-remotes library and added dynamic loading of infrared asset files from microSD.<sup>[[4]](#references)</sup> Its learning and universal-remote functions can replay or try known commands against nearby TVs and air conditioners. Range depends heavily on the emitter, optics, ambient light, and receiver; external IR hardware can extend it, but a fixed distance should not be assumed.

---

## Tooling & Practical Examples <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – portable transceiver with learning, replay and dictionary-bruteforce modes (see above).
* **Arduino / ESP32** + IR LED / TSOP38xx receiver – cheap DIY analyser/transmitter. Combine with the `Arduino-IRremote` library (v4.x supports >40 protocols).
* **Logic analysers** (Saleae/FX2) – capture raw timings when protocol is unknown.
* **Smartphones with IR-blaster** (e.g., Xiaomi) – quick field test but limited range.

### Software

* **`Arduino-IRremote`** – actively maintained C++ library:<sup>[[5]](#references)</sup>
  ```cpp
  #include <IRremote.hpp>
  void setup(){ IrSender.begin(3); }
  void loop(){
    IrSender.sendNEC(0x00, 0x10, 0); // address, command, repeats
    delay(5000);
  }
  ```
* **IRscrutinizer / AnalysIR** – GUI decoders that import raw captures and auto-identify protocol + generate Pronto/Arduino code.
* **LIRC / ir-keytable (Linux)** – receive and inject IR from the command line:
  ```bash
  sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
  irsend SEND_ONCE samsung KEY_POWER
  ```

---

## Defensive Measures <a href="#defense" id="defense"></a>

* Disable or cover IR receivers on devices deployed in public spaces when not required.
* Enforce *pairing* or cryptographic checks between smart-TVs and remotes; isolate privileged “service” codes.
* Deploy IR-cut filters or continuous-wave detectors around classified areas to break optical covert channels.
* Monitor firmware integrity of cameras/IoT appliances that expose controllable IR LEDs.

## References

- [1] [Flipper Zero Infrared blog post](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen Attack: Smart TV Hijacking via Multi-channel Remote Control Mimicry (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: Covert Air-Gap Exfiltration/Infiltration via Security Cameras & Infrared (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)
- [4] [Flipper Zero Blog - Firmware 1.0 Released](https://blog.flipper.net/released-firmware-1/)
- [5] [Arduino-IRremote - usage and protocol documentation](https://github.com/Arduino-IRremote/Arduino-IRremote)

{{#include ../../banners/hacktricks-training.md}}
