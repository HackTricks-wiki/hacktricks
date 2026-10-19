# Radio Hacking

{{#include ../../banners/hacktricks-training.md}}

Radio security testing examines how a device transmits, receives, and interprets wireless signals. A software-defined radio (SDR) can help locate a signal, record in-phase/quadrature (I/Q) samples, and test demodulation and decoding without committing to protocol-specific hardware.<sup>[[1]](#references)</sup>

A practical workflow is to identify the frequency band and channel width, capture several known device actions, compare the resulting signals, and then determine the modulation and packet structure. Test replay or transmission only in an isolated environment and on frequencies and equipment for which you have authorization. The pages in this section cover RFID, NFC, sub-GHz radio, infrared, BLE, and related tools.<sup>[[1]](#references)</sup>

## Find the relevant interface

- For an access badge or contact key, start with [RFID/NFC tag types and attacks](pentesting-rfid.md), [Proxmark3 workflows](proxmark-3.md), or [iButton and 1-Wire keys](ibutton.md). The [Flipper Zero guide](flipper-zero/README.md) links to its interface-specific actions.
- For a remote-control signal, use [sub-GHz RF and rolling codes](sub-ghz-rf.md) or [infrared protocols and attacks](infrared.md).
- For nearby devices and sensors, use [BLE advertising, GATT, and mesh testing](pentesting-ble-bluetooth-low-energy.md) or [LPWAN/LoRaWAN security](low-power-wide-area-network.md).
- For captured or unknown RF signals, use [SigDigger signal analysis](../hardware-hacking/radio.md#sigdigger) or the [FISSURE framework](fissure-the-rf-framework.md).
- For satellite terminal downlinks, see [VSAT forward-link signal injection](vsat-forward-link-injection.md).



## References

- [1] [Great Scott Gadgets - Software Defined Radio with HackRF](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
