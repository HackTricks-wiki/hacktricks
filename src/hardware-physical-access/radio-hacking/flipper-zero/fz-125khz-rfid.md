# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

## Intro

For background on how 125 kHz tags work, see:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

The [low-frequency RFID introduction](../pentesting-rfid.md#low-frequency-rfid-tags-125khz) explains the common tag families and their data formats.

## Actions

### Read

Use **Read** to capture the tag data. After a successful read, Flipper Zero can emulate the saved tag.<sup>[[1]](#references)</sup>

> [!WARNING]
> Some intercom readers attempt to detect writable duplicate tags by issuing a write command before reading. A Flipper Zero emulation does not expose writable tag memory in the same way.<sup>[[1]](#references)</sup>

### Add manually

You can manually enter tag data in Flipper Zero, save it, and then emulate it.<sup>[[1]](#references)</sup>

#### IDs on cards

Sometimes a card has all or part of its ID printed on its exterior.

- **EM Marin**

For example, the pictured EM-Marin card exposes the last three of its five ID bytes. If the tag cannot be read, the two missing bytes may be brute-forced.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Similarly, the pictured HID card prints only two of the three ID bytes.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulate/Write

After reading a tag or entering its ID manually, Flipper Zero can emulate the saved credential. For supported writable tags, it can also write the saved data to a compatible card.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero: Diving into RFID Protocols](https://blog.flipperzero.one/rfid/)

{{#include ../../../banners/hacktricks-training.md}}
