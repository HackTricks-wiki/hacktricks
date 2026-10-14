# FZ - Infrared

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

For more info about how Infrared works check:


{{#ref}}
../infrared.md
{{#endref}}

## IR Signal Receiver in Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper Zero uses a demodulating IR receiver to capture signals from common IR remotes. Some phones, including certain Xiaomi models, include an IR transmitter, but most cannot receive and decode remote-control signals.<sup>[[1]](#references)</sup>

The Flipper infrared **receiver is quite sensitive**. You can even **catch the signal** while remaining **somewhere in between** the remote and the TV. Pointing the remote directly at Flipper's IR port is unnecessary. This comes in handy when someone is switching channels while standing near the TV, and both you and Flipper are some distance away.

Protocol decoding happens in software. Recognized protocols can be stored as decoded commands; unsupported protocols can be captured and replayed as raw timing data, subject to the hardware's carrier-frequency and timing limits.<sup>[[1]](#references)</sup>

## Actions

### Universal Remotes

Flipper Zero's universal-remote mode cycles through known commands from its infrared database for supported TVs, audio equipment, projectors, and air conditioners. It is not guaranteed to control every device, and it should be used only on equipment you own or are authorized to test.<sup>[[1]](#references)</sup>

It is enough to press the power button in the Universal Remote mode, and Flipper will **sequentially send "Power Off"** commands of all the TVs it knows: Sony, Samsung, Panasonic... and so on. When the TV receives its signal, it will react and turn off.

Such brute-force takes time. The larger the dictionary, the longer it will take to finish. It is impossible to find out which signal exactly the TV recognized since there is no feedback from the TV.

### Learn New Remote

Flipper Zero can **capture an infrared signal**. If it recognizes the protocol and command, it stores a decoded representation; otherwise, it can store the raw timing data for later replay.<sup>[[1]](#references)</sup>

## References

- [1] [Taking over TVs with Flipper Zero Infrared Port](https://blog.flipperzero.one/infrared/)

{{#include ../../../banners/hacktricks-training.md}}
