# FZ - Infrared

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

For more info about how Infrared works check:

{{#ref}}
../infrared.md
{{#endref}}

## IR Signal Receiver in Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper uses a digital IR signal receiver TSOP, which **allows intercepting signals from IR remotes**. There are some **smartphones** like Xiaomi, which also have an IR port, but keep in mind that **most of them can only transmit** signals and are **unable to receive** them.

The Flipper infrared **receiver is quite sensitive**. You can even **catch the signal** while remaining **somewhere in between** the remote and the TV. Pointing the remote directly at Flipper's IR port is unnecessary. This comes in handy when someone is switching channels while standing near the TV, and both you and Flipper are some distance away.

As the **decoding of the infrared** signal happens on the **software** side, Flipper Zero potentially supports the **reception and transmission of any IR remote codes**. In the case of **unknown** protocols which could not be recognized - it **records and plays back** the raw signal exactly as received.

## Actions

### Universal Remotes

Flipper Zero can be used as a **universal remote to control any TV, air conditioner, or media center**. In this mode, Flipper **bruteforces** all **known codes** of all supported manufacturers **according to the dictionary from the SD card**. You don't need to choose a particular remote to turn off a restaurant TV.

It is enough to press the power button in the Universal Remote mode, and Flipper will **sequentially send "Power Off"** commands of all the TVs it knows: Sony, Samsung, Panasonic... and so on. When the TV receives its signal, it will react and turn off.

Such brute-force takes time. The larger the dictionary, the longer it will take to finish. It is impossible to find out which signal exactly the TV recognized since there is no feedback from the TV.

### Learn New Remote

It's possible to **capture an infrared signal** with Flipper Zero. If it **finds the signal in the database** Flipper will automatically **know which device this is** and will let you interact with it.\
If it doesn't, Flipper can **store** the **signal** and will allow you to **replay it**.

## References

- [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

{{#include ../../../banners/hacktricks-training.md}}



