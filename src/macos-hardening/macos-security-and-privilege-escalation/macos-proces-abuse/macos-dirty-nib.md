# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

**For further detail about the technique check the original post from:** [**https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/) and the following post by [**https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/**](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)**.** Here is a summary:

### What are Nib files

Nib (short for NeXT Interface Builder) files, part of Apple's development ecosystem, are intended for defining **UI elements** and their interactions in applications. They encompass serialized objects such as windows and buttons, and are loaded at runtime. Despite their ongoing usage, Apple now advocates for Storyboards for more comprehensive UI flow visualization.

The main Nib file is referenced in the value **`NSMainNibFile`** inside the `Info.plist` file of the application and is loaded by the function **`NSApplicationMain`** executed in the `main` function of the application.

### Dirty Nib Injection Process

#### Creating and Setting Up a NIB File

1. **Initial Setup**:
   - Create a new NIB file using XCode.
   - Add an Object to the interface, setting its class to `NSAppleScript`.
   - Configure the initial `source` property via User Defined Runtime Attributes.
2. **Code Execution Gadget**:
   - The setup facilitates running AppleScript on demand.
   - Integrate a button to activate the `Apple Script` object, specifically triggering the `executeAndReturnError:` selector.
3. **Testing**:

   - A simple Apple Script for testing purposes:

     ```bash
     set theDialogText to "PWND"
     display dialog theDialogText
     ```

   - Test by running in the XCode debugger and clicking the button.

#### Targeting an Application (Example: Pages)

1. **Preparation**:
   - Copy the target app (e.g., Pages) into a separate directory (e.g., `/tmp/`).
   - Initiate the app to sidestep Gatekeeper issues and cache it.
2. **Overwriting NIB File**:
   - Replace an existing NIB file (e.g., About Panel NIB) with the crafted DirtyNIB file.
3. **Execution**:
   - Trigger the execution by interacting with the app (e.g., selecting the `About` menu item).

#### Proof of Concept: Accessing User Data

- Modify the AppleScript to access and extract user data, such as photos, without user consent.

### Code Sample: Malicious .xib File

- Access and review a [**sample of a malicious .xib file**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4) that demonstrates executing arbitrary code.

### Other Example

In the post [https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/) you can find tutorial on how to create a dirty nib.

### Addressing Launch Constraints

- Launch Constraints hinder app execution from unexpected locations (e.g., `/tmp`).
- It's possible to identify apps not protected by Launch Constraints and target them for NIB file injection.

### Additional macOS Protections

From macOS Sonoma onwards, modifications inside App bundles are restricted. However, earlier methods involved:

1. Copying the app to a different location (e.g., `/tmp/`).
2. Renaming directories within the app bundle to bypass initial protections.
3. After running the app to register with Gatekeeper, modifying the app bundle (e.g., replacing MainMenu.nib with Dirty.nib).
4. Renaming directories back and rerunning the app to execute the injected NIB file.

**Note**: Recent macOS updates have mitigated this exploit by preventing file modifications within app bundles post Gatekeeper caching, rendering the exploit ineffective.

{{#include ../../../banners/hacktricks-training.md}}



