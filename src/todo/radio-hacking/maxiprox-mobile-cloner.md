# Building a Portable HID MaxiProx 125 kHz Mobile Cloner

{{#include ../../banners/hacktricks-training.md}}

## Goal
Turn a mains-powered HID MaxiProx 5375 long-range 125 kHz reader into a field-deployable, battery-powered badge cloner that silently harvests proximity cards during physical-security assessments.

The conversion covered here is based on TrustedSec’s “Let’s Clone a Cloner – Part 3: Putting It All Together” research series and combines mechanical, electrical and RF considerations so the final device can be thrown in a backpack and immediately used on site.

> [!warning]
> Manipulating mains-powered equipment and Lithium-ion power-banks can be dangerous.  Verify every connection **before** energising the circuit and keep the antennas, coax and ground planes exactly as they were in the factory design to avoid detuning the reader.

## Bill of Materials (BOM)

* HID MaxiProx 5375 reader (or any 12 V HID Prox® long-range reader)
* ESP RFID Tool v2.2 (ESP32-based Wiegand sniffer/logger)
* USB-PD (Power-Delivery) trigger module able to negotiate 12 V @ ≥3 A
* 100 W USB-C power-bank (outputs 12 V PD profile)
* 26 AWG silicone-insulated hook-up wire – red/white
* Panel-mount SPST toggle switch (for beeper kill-switch)
* NKK AT4072 switch-guard / accident-proof cap
* Soldering iron, solder wick & desolder pump
* ABS-rated hand tools: coping-saw, utility-knife, flat & half-round files
* Drill bits 1/16″ (1.5 mm) and 1/8″ (3 mm)
* 3 M VHB double-sided tape & Zip-ties

## 1. Power Sub-System

1. Desolder and remove the factory buck-converter daughter-board used to generate 5 V for the logic PCB.
2. Mount a USB-PD trigger next to the ESP RFID Tool and route the trigger’s USB-C receptacle to the outside of the enclosure.
3. The PD trigger negotiates 12 V from the power-bank and feeds it directly to the MaxiProx (the reader natively expects 10–14 V).  A secondary 5 V rail is taken from the ESP board to power any accessories.
4. The 100 W battery pack is positioned flush against the internal standoff so there are **no** power cables draped across the ferrite antenna, preserving RF performance.

## 2. Beeper Kill-Switch – Silent Operation

1. Locate the two speaker pads on the MaxiProx logic board.
2. Wick *both* pads clean, then re-solder only the **negative** pad.
3. Solder 26 AWG wires (white = negative, red = positive) to the beeper pads and route them through a newly cut slot to a panel-mount SPST switch.
4. When the switch is open the beeper circuit is broken and the reader operates in complete silence – ideal for covert badge harvesting.
5. Fit an NKK AT4072 spring-loaded safety cap over the toggle.  Carefully enlarge the bore with a coping-saw / file until it snaps over the switch body.  The guard prevents accidental activation inside a backpack.

## 3. Enclosure & Mechanical Work

• Use flush cutters then a knife & file to *remove* the internal ABS “bump-out” so the large USB-C battery sits flat on the standoff.
• Carve two parallel channels in the enclosure wall for the USB-C cable; this locks the battery in place and eliminates movement/vibration.
• Create a rectangular aperture for the battery’s **power** button:
  1. Tape a paper stencil over the location.
  2. Drill 1/16″ pilot holes in all four corners.
  3. Enlarge with a 1/8″ bit.
  4. Join the holes with a coping saw; finish the edges with a file.  
  ✱  A rotary Dremel was *avoided* – the high-speed bit melts thick ABS and leaves an ugly edge.

## 4. Final Assembly

1. Re-install the MaxiProx logic board and re-solder the SMA pigtail to the reader’s PCB ground pad.
2. Mount the ESP RFID Tool and USB-PD trigger using 3 M VHB.
3. Dress all wiring with zip-ties, keeping power leads **far** from the antenna loop.
4. Tighten the enclosure screws until the battery is lightly compressed; the internal friction prevents the pack from shifting when the device recoils after every card read.

## 5. Range & Shielding Tests

* Using a 125 kHz **Pupa** test card the portable cloner achieved consistent reads at **≈ 8 cm** in free-air – identical to mains-powered operation.
* Placing the reader inside a thin-walled metal cash box (to simulate a bank lobby desk) reduced range to ≤ 2 cm, confirming that substantial metal enclosures act as effective RF shields.

## Usage Workflow

1. Charge the USB-C battery, connect it, and flip the main power switch.
2. (Optional) Open the beeper guard and enable audible feedback when bench-testing; lock it down before covert field use.
3. Walk past the target badge holder – the MaxiProx will energise the card and the ESP RFID Tool captures the Wiegand stream.
4. Dump captured credentials over Wi-Fi or USB-UART and replay/clone as required.

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|--------------|------|
| Reader reboots when card presented | PD trigger negotiated 9 V not 12 V | Verify trigger jumpers / try higher-power USB-C cable |
| No read range | Battery or wiring sitting *on top* of the antenna | Re-route cables & keep 2 cm clearance around the ferrite loop |
| Beeper still chirps | Switch wired on positive lead instead of negative | Move kill-switch to break the **negative** speaker trace |

## References

- [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}