# JTAG

{{#include ../../banners/hacktricks-training.md}}

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)is a tool can be used with a Raspberry PI or an Arduino to find to try JTAG pins from an unknown chip.\
In the **Arduino**, connect the **pins from 2 to 11 to 10pins potentially belonging to a JTAG**. Load the program in the Arduino and it will try to bruteforce all the pins to find if any pins belongs to JTAG and which one is each.\
In the **Raspberry PI** you can only use **pins from 1 to 6** (6pins, so you will go slower testing each potential JTAG pin).

### Arduino

In Arduino, after connecting the cables (pin 2 to 11 to JTAG pins and Arduino GND to the baseboard GND), **load the JTAGenum program in Arduino** and in the Serial Monitor send a **`h`** (command for help) and you should see the help:

![](<../../images/image (939).png>)

![](<../../images/image (578).png>)

Configure **"No line ending" and 115200baud**.\
Send the command s to start scanning:

![](<../../images/image (774).png>)

If you are contacting a JTAG, you will find one or several **lines starting by FOUND!** indicating the pins of JTAG.

{{#include ../../banners/hacktricks-training.md}}



