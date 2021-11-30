# Escaping from KIOSKs

## Check for possible actions inside the GUI application

**Common Dialogs** are those options of **saving a file**, **opening a file**, selecting a font, a color... Most of them will **offer a full Explorer functionality**. This means that you will be able to access Explorer functionalities if you can access these options:

* Close/Close as
* Open/Open with
* Print
* Export/Import
* Search
* Scan

You should check if you can:

* Modify or create new files
* Create symbolic links
* Get access to restricted areas
* Execute other apps

### Command Execution

Maybe **using a **_**Open with**_** option** you can open/execute some kind of shell.

#### Windows

For example _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ find more binaries that can be used to execute commands (and perform unexpected actions) here: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX __&#x20;

_bash, sh, zsh..._ More here: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Bypassing path restrictions

* **Environment variables**: There are a lot of environment variables that are pointing to some path
* **Other protocols**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **Symbolic links**
* **Shortcuts**: CTRL+N (open new session), CTRL+R (Execute Commands), CTRL+SHIFT+ESC (Task Manager),  Windows+E (open explorer), CTRL-B, CTRL-I (Favourites), CTRL-H (History), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
  * Hidden Administrative menu: CTRL-ALT-F8, CTRL-ESC-F9
* **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
* **UNC paths**: Paths to connect to shared folders. You should try to connect to the C$ of the local machine ("\\\127.0.0.1\c$\Windows\System32")
  * **More UNC paths:**

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUTERNAME% | %COMSPEC%            |
| %HOMEDRIVE%               | %HOMEPATH%     | %LOCALAPPDATA%       |
| %LOGONSERVER%             | %PATH%         | %PATHEXT%            |
| %ProgramData%             | %ProgramFiles% | %ProgramFiles(x86)%  |
| %PROMPT%                  | %PSModulePath% | %Public%             |
| %SYSTEMDRIVE%             | %SYSTEMROOT%   | %TEMP%               |
| %TMP%                     | %USERDOMAIN%   | %USERNAME%           |
| %USERPROFILE%             | %WINDIR%       |                      |

### Download Your Binaries

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Accessing filesystem from the browser

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### ShortCuts

* Sticky Keys – Press SHIFT 5 times&#x20;
* Mouse Keys – SHIFT+ALT+NUMLOCK&#x20;
* High Contrast – SHIFT+ALT+PRINTSCN&#x20;
* Toggle Keys – Hold NUMLOCK for 5 seconds&#x20;
* Filter Keys – Hold right SHIFT for 12 seconds&#x20;
* WINDOWS+F1 – Windows Search&#x20;
* WINDOWS+D – Show Desktop&#x20;
* WINDOWS+E – Launch Windows Explorer&#x20;
* WINDOWS+R – Run&#x20;
* WINDOWS+U – Ease of Access Centre&#x20;
* WINDOWS+F – Search&#x20;
* SHIFT+F10 – Context Menu&#x20;
* CTRL+SHIFT+ESC – Task Manager&#x20;
* CTRL+ALT+DEL – Splash screen on newer Windows versions&#x20;
* F1 – Help F3 – Search&#x20;
* F6 – Address Bar&#x20;
* F11 – Toggle full screen within Internet Explorer&#x20;
* CTRL+H – Internet Explorer History&#x20;
* CTRL+T – Internet Explorer – New Tab&#x20;
* CTRL+N – Internet Explorer – New Page&#x20;
* CTRL+O – Open File&#x20;
* CTRL+S – Save CTRL+N – New RDP / Citrix

### Swipes

* Swipe from the left side to the right to see all open Windows, minimizing the KIOSK app and accessing the whole OS directly;
* Swipe from the right side to the left to open Action Center, minimizing the KIOSK app and accessing the whole OS directly;
* Swipe in from the top edge to make the title bar visible for an app opened in full screen mode;
* Swipe up from the bottom to show  the taskbar in a full screen app.

### Internet Explorer Tricks

#### 'Image Toolbar'

It's a toolbar that appears on the top-left of image when it's clicked. You will be able to Save, Print, Mailto, Open "My Pictures" in Explorer. The Kiosk needs to be using Internet Explorer.

#### Shell Protocol

Type this URLs to obtain an Explorer view:

* `shell:Administrative Tools`
* `shell:DocumentsLibrary`
* `shell:Libraries`
* `shell:UserProfiles`
* `shell:Personal`
* `shell:SearchHomeFolder`
* `shell:NetworkPlacesFolder`
* `shell:SendTo`
* `shell:UserProfiles`
* `shell:Common Administrative Tools`
* `shell:MyComputerFolder`
* `shell:InternetFolder`
* `Shell:Profile`
* `Shell:ProgramFiles`
* `Shell:System`
* `Shell:ControlPanelFolder`
* `Shell:Windows`
* `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Control Panel
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> My Computer
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> My Network Places
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

## Browsers tricks

Backup iKat versions:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\


## iPad

### Gestures and bottoms

#### Swipe up with four (or five) fingers / Double-tap Home button

To view the multitask view and change App

#### Swipe one way or another with four or five fingers

In order to change to the next/last App

#### Pinch the screen with five fingers / Touch Home button / Swipe up with 1 finger from the bottom of the screen in a quick motion to the up

To access Home

#### Swipe one finger from the bottom of the screen just 1-2 inches (slow)

The dock will appear

#### Swipe down from the top of the display with 1 finger

To view your notifications

#### Swipe down with 1 finger the top-right corner of the screen

To see iPad Pro's control centre

#### Swipe 1 finger from the left of the screen 1-2 inches

To see Today view

#### Swipe fast 1 finger from the centre of the screen to the right or left

To change to next/last App

#### Press and hold the On/**Off**/Sleep button at the upper-right corner of the **iPad +** Move the Slide to **power off** slider all the way to the right,

To power off

#### Press the  On/**Off**/Sleep button at the upper-right corner of the **iPad and the Home button for a few second**

To force a hard power off

#### Press the  On/**Off**/Sleep button at the upper-right corner of the **iPad and the Home button quickly**

To take a screenshot that will pop up in the lower left of the display. Press both buttons at the same time very briefly as if you hold them a few seconds a hard power off will be performed.

### Shortcuts

You should have an iPad keyboard or a USB keyboard adaptor. Only shortcuts that could help escaping from the application will be shown here.

| Key | Name         |
| --- | ------------ |
| ⌘   | Command      |
| ⌥   | Option (Alt) |
| ⇧   | Shift        |
| ↩   | Return       |
| ⇥   | Tab          |
| ^   | Control      |
| ←   | Left Arrow   |
| →   | Right Arrow  |
| ↑   | Up Arrow     |
| ↓   | Down Arrow   |

#### System shortcuts

These shortcuts are for the visual settings and sound settings, depending on the use of the iPad.

| Shortcut | Action                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Dim Sscreen                                                                    |
| F2       | Brighten screen                                                                |
| F7       | Back one song                                                                  |
| F8       | Play/pause                                                                     |
| F9       | Skip song                                                                      |
| F10      | Mute                                                                           |
| F11      | Decrease volume                                                                |
| F12      | Increase volume                                                                |
| ⌘ Space  | Display a list of available languages; to choose one, tap the space bar again. |

#### iPad navigation

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Go to Home                                              |
| ⌘⇧H (Command-Shift-H)                              | Go to Home                                              |
| ⌘ (Space)                                          | Open Spotlight                                          |
| ⌘⇥ (Command-Tab)                                   | List last ten used apps                                 |
| ⌘\~                                                | Go t the last App                                       |
| ⌘⇧3 (Command-Shift-3)                              | Screenshot (hovers in bottom left to save or act on it) |
| ⌘⇧4                                                | Screenshot and open it in the editor                    |
| Press and hold ⌘                                   | List of shortcuts available for the App                 |
| ⌘⌥D (Command-Option/Alt-D)                         | Brings up the dock                                      |
| ^⌥H (Control-Option-H)                             | Home button                                             |
| ^⌥H H (Control-Option-H-H)                         | Show multitask bar                                      |
| ^⌥I (Control-Option-i)                             | Item chooser                                            |
| Escape                                             | Back button                                             |
| → (Right arrow)                                    | Next item                                               |
| ← (Left arrow)                                     | Previous item                                           |
| ↑↓ (Up arrow, Down arrow)                          | Simultaneously tap selected item                        |
| ⌥ ↓ (Option-Down arrow)                            | Scroll down                                             |
| ⌥↑ (Option-Up arrow)                               | Scroll up                                               |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Scroll left or right                                    |
| ^⌥S (Control-Option-S)                             | Turn VoiceOver speech on or off                         |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Switch to the previous app                              |
| ⌘⇥ (Command-Tab)                                   | Switch back to the original app                         |
| ←+→, then Option + ← or Option+→                   | Navigate through Dock                                   |

#### Safari shortcuts

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Open Location                                    |
| ⌘T                      | Open a new tab                                   |
| ⌘W                      | Close the current tab                            |
| ⌘R                      | Refresh the current tab                          |
| ⌘.                      | Stop loading the current tab                     |
| ^⇥                      | Switch to the next tab                           |
| ^⇧⇥ (Control-Shift-Tab) | Move to the previous tab                         |
| ⌘L                      | Select the text input/URL field to modify it     |
| ⌘⇧T (Command-Shift-T)   | Open last closed tab (can be used several times) |
| ⌘\[                     | Goes back one page in your browsing history      |
| ⌘]                      | Goes forward one page in your browsing history   |
| ⌘⇧R                     | Activate Reader Mode                             |

#### Mail shortcuts

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Open Location                |
| ⌘T                         | Open a new tab               |
| ⌘W                         | Close the current tab        |
| ⌘R                         | Refresh the current tab      |
| ⌘.                         | Stop loading the current tab |
| ⌘⌥F (Command-Option/Alt-F) | Search in your mailbox       |

### References

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)
