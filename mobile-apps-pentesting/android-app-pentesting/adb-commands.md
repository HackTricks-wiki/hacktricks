# ADB Commands

**Information obtained from:** [**http://adbshell.com/**](http://adbshell.com/)\*\*\*\*

## Connection

```text
adb devices
```

This will list the connected devices; if "_**unathorised**_" appears, this means that you have to **unblock** your **mobile** and **accept** the connection.

This indicates to the device that it has to start and adb server in port 5555:

```text
adb tcpip 5555
```

Connect to that IP and that Port:

```text
adb connect <IP>:<PORT>
```

If you get an error like the following in a Virtual Android software \(like Genymotion\):

```text
adb server version (41) doesn't match this client (36); killing...
```

It's because you are trying to connect to an ADB server with a different version. Just try to find the adb binary the software is using \(go to `C:\Program Files\Genymobile\Genymotion` and search for adb.exe\)

## Packet Manager

### Install/Uninstall

#### adb install \[option\] &lt;path&gt;

```text
adb install test.apk
```

```text
adb install -l test.apk forward lock application
```

```text
adb install -r test.apk replace existing application
```

```text
adb install -t test.apk allow test packages
```

```text
adb install -s test.apk install application on sdcard
```

```text
adb install -d test.apk allow version code downgrade
```

```text
adb install -p test.apk partial application install
```

#### adb uninstall \[options\] &lt;PACKAGE&gt;

```text
adb uninstall com.test.app
```

```text
adb uninstall -k com.test.app Keep the data and cache directories around after package removal.
```

### Packages

Prints all packages, optionally only those whose package name contains the text in &lt;FILTER&gt;.

#### adb shell pm list packages \[options\] &lt;FILTER-STR&gt;

```text
adb shell pm list packages <FILTER-STR>
```

```text
adb shell pm list packages -f <FILTER-STR> #See their associated file.
```

```text
adb shell pm list packages -d <FILTER-STR> #Filter to only show disabled packages.
```

```text
adb shell pm list packages -e <FILTER-STR> #Filter to only show enabled packages.
```

```text
adb shell pm list packages -s <FILTER-STR> #Filter to only show system packages.
```

```text
adb shell pm list packages -3 <FILTER-STR> #Filter to only show third party packages.
```

```text
adb shell pm list packages -i <FILTER-STR> #See the installer for the packages.
```

```text
adb shell pm list packages -u <FILTER-STR> #Also include uninstalled packages.
```

```text
adb shell pm list packages --user <USER_ID> <FILTER-STR> #The user space to query.
```

#### adb shell pm path &lt;PACKAGE&gt;

Print the path to the APK of the given .

```text
adb shell pm path com.android.phone
```

#### adb shell pm clear &lt;PACKAGE&gt;

Delete all data associated with a package.

```text
adb shell pm clear com.test.abc
```

## File Manager

#### adb pull &lt;remote&gt; \[local\]

Download a specified file from an emulator/device to your computer.

```text
adb pull /sdcard/demo.mp4 ./
```

#### adb push &lt;local&gt; &lt;remote&gt;

Upload a specified file from your computer to an emulator/device.

```text
adb push test.apk /sdcard
```

## Screencapture/Screenrecord

#### adb shell screencap &lt;filename&gt;

Taking a screenshot of a device display.

```text
adb shell screencap /sdcard/screen.png
```

#### adb shell screenrecord \[options\] &lt;filename&gt;

Recording the display of devices running Android 4.4 \(API level 19\) and higher.

```text
adb shell screenrecord /sdcard/demo.mp4
adb shell screenrecord --size <WIDTHxHEIGHT>
adb shell screenrecord --bit-rate <RATE>
adb shell screenrecord --time-limit <TIME> #Sets the maximum recording time, in seconds. The default and maximum value is 180 (3 minutes).
adb shell screenrecord --rotate # Rotates 90 degrees
adb shell screenrecord --verbose
```

\(press Ctrl-C to stop recording\)

**You can download the files \(images and videos\) using** _**adb pull**_

## Shell

#### adb shell

Get a shell inside the device

```text
adb shell
```

#### adb shell &lt;CMD&gt;

Execute a command inside the device

```text
adb shell ls
```

## Processes

If you want to get the PID of the process of your application you can execute:

```text
adb shell ps
```

And search for your application

Or you can do

```text
adb shell pidof com.your.application
```

And it will print the PID of the application

## System

```text
adb root
```

Restarts the adbd daemon with root permissions. Then, you have to conenct again to the ADB server and you will be root \(if available\)

```text
adb sideload <update.zip>
```

flashing/restoring Android update.zip packages.

## Logs

### Logcat

To **filter the messages of only one application**, get the PID of the application and use grep \(linux/macos\) or findstr \(windows\) to filter the output of logcat:

```text
adb logcat | grep 4526
adb logcat | findstr 4526
```

#### adb logcat \[option\] \[filter-specs\]

```text
adb logcat
```

Notes: press Ctrl-C to stop monitor

```text
adb logcat *:V lowest priority, filter to only show Verbose level
```

```text
adb logcat *:D filter to only show Debug level
```

```text
adb logcat *:I filter to only show Info level
```

```text
adb logcat *:W filter to only show Warning level
```

```text
adb logcat *:E filter to only show Error level
```

```text
adb logcat *:F filter to only show Fatal level
```

```text
adb logcat *:S Silent, highest priority, on which nothing is ever printed
```

#### adb logcat -b &lt;Buffer&gt;

```text
adb logcat -b radio View the buffer that contains radio/telephony related messages.
```

```text
adb logcat -b event View the buffer containing events-related messages.
```

```text
adb logcat -b main default
```

```text
adb logcat -c Clears the entire log and exits.
```

```text
adb logcat -d Dumps the log to the screen and exits.
```

```text
adb logcat -f test.logs Writes log message output to test.logs .
```

```text
adb logcat -g Prints the size of the specified log buffer and exits.
```

```text
adb logcat -n <count> Sets the maximum number of rotated logs to <count>. 
```

### dumpsys

dumps system data

#### adb shell dumpsys \[options\]

```text
adb shell dumpsys
```

adb shell dumpsys meminfo

```text
adb shell dumpsys battery
```

Notes: A mobile device with Developer Options enabled running Android 5.0 or higher.

```text
adb shell dumpsys batterystats collects battery data from your device
```

Notes: [Battery Historian](https://github.com/google/battery-historian) converts that data into an HTML visualization. **STEP 1** _adb shell dumpsys batterystats &gt; batterystats.txt_ **STEP 2** _python historian.py batterystats.txt &gt; batterystats.html_

```text
adb shell dumpsys batterystats --reset erases old collection data
```

adb shell dumpsys activity

## Backup

Backup an android device from adb.

```bash
adb backup [-apk] [-shared] [-system] [-all] -f file.backup
# -apk -- Include APK from Third partie's applications
# -shared -- Include removable storage
# -system -- Include system Applciations
# -all -- Include all the applications

adb shell pm list packages -f -3      #List packages
adb backup -f myapp_backup.ab -apk com.myapp # backup on one device
adb restore myapp_backup.ab                  # restore to the same or any other device
```

If you want to inspect the content of the backup:

```bash
( printf "\x1f\x8b\x08\x00\x00\x00\x00\x00" ; tail -c +25 myapp_backup.ab ) |  tar xfvz -
```

