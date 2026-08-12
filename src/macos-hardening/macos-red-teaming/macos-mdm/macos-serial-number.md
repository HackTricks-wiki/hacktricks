# macOS Serial Number

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Do not assume that every Mac has a decodable 12-character serial number. Apple's older format encoded manufacturing and configuration information, but Apple began introducing randomized serial numbers with new products in 2021. The randomized format does not expose manufacturing or configuration details.<sup>[[1]](#references)</sup>

### Legacy 12-character format

For many devices manufactured from 2010 until the randomized transition, the 12-character format can still provide useful inventory clues:<sup>[[3]](#references)</sup>

- Characters 1–3 identify the manufacturing location.
- Characters 4–5 encode the production half-year and week.
- Characters 6–8 distinguish units produced at the same location and time.
- Characters 9–12 identify the model or configuration code.

For example, `C02L13ECF8J2` follows this legacy structure. Community-maintained factory mappings include prefixes such as `FC`, `F`, `XA`, `XB`, `QP`, and `G8` for United States locations; `RN` for Mexico; `CK` for Cork; `VM` for a Foxconn location in the Czech Republic; `SG` or `E` for Singapore; `MB` for Malaysia; `PT` or `CY` for Korea; and `EE`, `QT`, or `UV` for Taiwan. Numerous prefixes—including `FK`, `F1`, `F2`, `W8`, `DL`, `DM`, `DN`, `YM`, `7J`, `1C`, `4H`, `WQ`, `F7`, `C0`, `C3`, and `C7`—have been associated with Chinese facilities; `RM` has been associated with refurbished devices.<sup>[[3]](#references)</sup>

The fourth-character date codes run from `C` (first half of 2010) through `Z` (second half of 2019), with the sequence reused afterward. For the fifth character, digits `1`–`9` represent weeks 1–9, while letters `C`–`Y` excluding vowels and `S` represent weeks 10–27; add 26 when the fourth character denotes the second half of a year.<sup>[[3]](#references)</sup>

These mappings are useful for legacy triage but are not authoritative proof of origin, age, or authenticity. Confirm the result through Apple's inventory data.

For reliable identification, retrieve the serial number from the device and use Apple's coverage or technical-specification lookup instead of trying to infer the model from character positions.<sup>[[2]](#references)</sup>

### Retrieve the serial number

The graphical interface displays it under **Apple menu > About This Mac**.<sup>[[2]](#references)</sup> From a shell, either of the following commands reads the platform serial number:

```bash
system_profiler SPHardwareDataType | awk -F ': ' '/Serial Number/ {print $2}'
ioreg -rd1 -c IOPlatformExpertDevice | awk -F '"' '/IOPlatformSerialNumber/ {print $4}'
```

Treat a serial number as an identifier, not an authenticator: confirm the device through the relevant Apple or MDM inventory workflow before making enrollment or ownership decisions.

## References

- [1] [MacRumors - Apple begins transition to randomized serial numbers](https://www.macrumors.com/2021/05/05/purple-iphone-12-randomized-serial-number/)
- [2] [Apple Support - Find your Mac model name and serial number](https://support.apple.com/en-us/102767)
- [3] [Beetstech - Decode the meaning behind an Apple serial number](https://beetstech.com/blog/decode-meaning-behind-apple-serial-number)

{{#include ../../../banners/hacktricks-training.md}}
