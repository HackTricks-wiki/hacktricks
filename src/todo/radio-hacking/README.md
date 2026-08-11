# Radio Hacking

{{#include ../../banners/hacktricks-training.md}}

Radio security testing examines how a device transmits, receives, and interprets wireless signals. A software-defined radio (SDR) can help locate a signal, record in-phase/quadrature (I/Q) samples, and test demodulation and decoding without committing to protocol-specific hardware.<sup>[[1]](#references)</sup>

A practical workflow is to identify the frequency band and channel width, capture several known device actions, compare the resulting signals, and then determine the modulation and packet structure. Test replay or transmission only in an isolated environment and on frequencies and equipment for which you have authorization. The pages in this section cover RFID, NFC, sub-GHz radio, infrared, BLE, and related tools.<sup>[[1]](#references)</sup>

## References

- [1] [Great Scott Gadgets - Software Defined Radio with HackRF](https://greatscottgadgets.com/sdr/1/)

{{#include ../../banners/hacktricks-training.md}}
