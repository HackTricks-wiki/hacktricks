# VSAT Forward-Link Signal Injection

{{#include ../../banners/hacktricks-training.md}}

A VSAT terminal normally treats its satellite downlink as traffic from the operator's hub. In a DVB-RCS system, that forward link can carry both user IP packets and modem control messages. If the receiver does not authenticate a message before processing it, a locally injected signal can cross the radio-to-control-plane trust boundary. This is **downlink injection at the terminal**, not an uplink to the satellite or passive downlink interception. The demonstrated outcome depends on the modem's protocol implementation and message authentication, not on DVB-RCS alone.<sup>[[1]](#references)[[2]](#references)</sup>

## Test in an RF-contained lab

Use an owned terminal, its firmware, and an SDR connected to the modem's receive input through appropriate attenuation, or a shielded RF setup. Do not radiate on a live satellite channel. First record the terminal's configured start-up carrier, symbol rate, and population ID; these guide forward-link acquisition.<sup>[[1]](#references)[[3]](#references)</sup> The DVB-RCS acquisition chain uses the Network Information Table (NIT) to locate the RCS Map Table (RMT), then the Program Association Table (PAT) and Program Map Table (PMT) to locate the forward-link signalling streams. A terminal may retune through multiple transport-stream carriers before reaching the data stream.<sup>[[3]](#references)</sup>

1. Decode or reconstruct the target's start-up transport stream and inspect its NIT, RMT, service IDs, packet IDs (PIDs), and clock-reference handling. Compare the standard with the target's parser and logs; vendor-specific ordering or descriptors can prevent an otherwise valid stream from being accepted.
2. In the lab transmitter, encapsulate a harmless UDP probe as `UDP/IP → MPE → MPEG-TS → DVB-S2 I/Q` and feed it through an SDR sink to the isolated receive path. Keep the transport stream's Program Clock Reference (PCR) consistent with the byte rate, or the modem may lose synchronization before it processes the probe.
3. Confirm both **demodulator lock** and receipt of the probe on an owned internal endpoint. Lock alone proves only that the physical layer accepted the waveform. Then check whether unauthenticated management or update *signalling* is exposed, without installing an image or changing service configuration.

The published MDM2200 case used a GNU Radio source module for DVB-RCS/MPE/MPEG-TS and `gr-dtv` for DVB-S2 modulation. Its modem required target-specific initialization details: an SDT before the PAT/PMT, an RCS content descriptor with table ID `0x3E`, and an RMT private byte of `0x01` for its GSE/4CPM mode. Do not assume those values work on another terminal.<sup>[[1]](#references)</sup> The researchers also observed that multicast MPE packets reached receiving modems in their setup, so targeting was not limited to a known unicast MAC address.<sup>[[1]](#references)</sup> A separate analysis found unprotected control and software-update signalling on the studied system, but that finding must be verified per implementation.<sup>[[2]](#references)</sup>

An IPsec or VPN tunnel for user traffic does not authenticate earlier DVB-RCS signalling or the modem's own update parser. For an authorized assessment, distinguish cryptographic protection of **user IP**, **forward-link control**, and **maintenance/recovery** traffic rather than treating a secure user tunnel as proof that radio injection is blocked.<sup>[[1]](#references)[[2]](#references)</sup>

For initial I/Q inspection, see [radio signal analysis](../hardware-hacking/radio.md). For board-side firmware and parser inspection, see [firmware analysis](../firmware-analysis/). Return to the [Radio Hacking overview](./) for other interfaces.

## References

- [1] [Bisping et al. - Wireless Signal Injection Attacks on VSAT Satellite Modems (USENIX Security 2024)](https://www.usenix.org/system/files/usenixsecurity24-bisping.pdf)
- [2] [Willbold et al. - VSAsTer: Uncovering Inherent Security Issues in Current VSAT System Practices (WiSec 2024)](https://www.lenders.ch/publications/conferences/wisec24.pdf)
- [3] [ETSI EN 301 790 - DVB interaction channel for satellite distribution systems](https://www.etsi.org/deliver/etsi_en/301700_301799/301790/01.04.01_40/en_301790v010401o.pdf)
{{#include ../../banners/hacktricks-training.md}}
