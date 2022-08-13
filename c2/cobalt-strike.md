# Cobalt Strike

### Listeners

Cobalt Strike -> Listeners -> Add/Edit then you can select where to listen, which kind of beacon to use (http, dns, smb...) and more

### Generate & Host payloads

#### Generate payloads in files

Attacks -> Packages ->&#x20;

* **`HTMLApplication`** for HTA files
* **`MS Office Macro`** for an office document with a macro
* **`Windows Executable`** for a .exe, .dll orr service .exe
* **`Windows Executable (S)`** for a **stageless** .exe, .dll or service .exe (better stageless than staged, less IoCs)

#### Generate & Host payloads

A`ttacks -> Web Drive-by -> Scripted Web Delivery (S)` This will generate a script/executable to download the beacon from cobalt strike in formats such as: bitsadmin, exe, powershell and python

#### Host Payloads

If you already has the file you want to host in a web sever just go to `Attacks -> Web Drive-by -> Host File` and select the file to host and web server config.

### Beacon Options

```bash
# Execute local .NET binary
execute-assembly </path/to/executable.exe>


# Screenshots
printscreen    # Take a single screenshot via PrintScr method
screenshot     # Take a single screenshot
screenwatch    # Take periodic screenshots of desktop
## Go to View -> Screenshots to see them

# keylogger
keylogger [pid] [x86|x64]
## View > Keystrokes to see the keys pressed
```
