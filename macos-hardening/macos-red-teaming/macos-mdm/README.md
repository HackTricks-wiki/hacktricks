# macOS MDM

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

**To learn about macOS MDMs check:**

* [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
* [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Basics

### **MDM (Mobile Device Management) Overview**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile\_device\_management) (MDM) is utilized for overseeing various end-user devices like smartphones, laptops, and tablets. Particularly for Apple's platforms (iOS, macOS, tvOS), it involves a set of specialized features, APIs, and practices. The operation of MDM hinges on a compatible MDM server, which is either commercially available or open-source, and must support the [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Key points include:

* Centralized control over devices.
* Dependence on an MDM server that adheres to the MDM protocol.
* Capability of the MDM server to dispatch various commands to devices, for instance, remote data erasure or configuration installation.

### **Basics of DEP (Device Enrollment Program)**

The [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP\_Guide.pdf) (DEP) offered by Apple streamlines the integration of Mobile Device Management (MDM) by facilitating zero-touch configuration for iOS, macOS, and tvOS devices. DEP automates the enrollment process, allowing devices to be operational right out of the box, with minimal user or administrative intervention. Essential aspects include:

* Enables devices to autonomously register with a pre-defined MDM server upon initial activation.
* Primarily beneficial for brand-new devices, but also applicable for devices undergoing reconfiguration.
* Facilitates a straightforward setup, making devices ready for organizational use swiftly.

### **Security Consideration**

It's crucial to note that the ease of enrollment provided by DEP, while beneficial, can also pose security risks. If protective measures are not adequately enforced for MDM enrollment, attackers might exploit this streamlined process to register their device on the organization's MDM server, masquerading as a corporate device.

{% hint style="danger" %}
**Security Alert**: Simplified DEP enrollment could potentially allow unauthorized device registration on the organization's MDM server if proper safeguards are not in place.
{% endhint %}

### Basics What is SCEP (Simple Certificate Enrolment Protocol)?

* A relatively old protocol, created before TLS and HTTPS were widespread.
* Gives clients a standardized way of sending a **Certificate Signing Request** (CSR) for the purpose of being granted a certificate. The client will ask the server to give him a signed certificate.

### What are Configuration Profiles (aka mobileconfigs)?

* Apple’s official way of **setting/enforcing system configuration.**
* File format that can contain multiple payloads.
* Based on property lists (the XML kind).
* “can be signed and encrypted to validate their origin, ensure their integrity, and protect their contents.” Basics — Page 70, iOS Security Guide, January 2018.

## Protocols

### MDM

* Combination of APNs (**Apple server**s) + RESTful API (**MDM** **vendor** servers)
* **Communication** occurs between a **device** and a server associated with a **device** **management** **product**
* **Commands** delivered from the MDM to the device in **plist-encoded dictionaries**
* All over **HTTPS**. MDM servers can be (and are usually) pinned.
* Apple grants the MDM vendor an **APNs certificate** for authentication

### DEP

* **3 APIs**: 1 for resellers, 1 for MDM vendors, 1 for device identity (undocumented):
  * The so-called [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). This is used by MDM servers to associate DEP profiles with specific devices.
  * The [DEP API used by Apple Authorized Resellers](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) to enroll devices, check enrollment status, and check transaction status.
  * The undocumented private DEP API. This is used by Apple Devices to request their DEP profile. On macOS, the `cloudconfigurationd` binary is responsible for communicating over this API.
* More modern and **JSON** based (vs. plist)
* Apple grants an **OAuth token** to the MDM vendor

**DEP "cloud service" API**

* RESTful
* sync device records from Apple to the MDM server
* sync “DEP profiles” to Apple from the MDM server (delivered by Apple to the device later on)
* A DEP “profile” contains:
  * MDM vendor server URL
  * Additional trusted certificates for server URL (optional pinning)
  * Extra settings (e.g. which screens to skip in Setup Assistant)

## Serial Number

Apple devices manufactured after 2010 generally have **12-character alphanumeric** serial numbers, with the **first three digits representing the manufacturing location**, the following **two** indicating the **year** and **week** of manufacture, the next **three** digits providing a **unique** **identifier**, and the **last** **four** digits representing the **model number**.

{% content-ref url="macos-serial-number.md" %}
[macos-serial-number.md](macos-serial-number.md)
{% endcontent-ref %}

## Steps for enrolment and management

1. Device record creation (Reseller, Apple): The record for the new device is created
2. Device record assignment (Customer): The device is assigned to a MDM server
3. Device record sync (MDM vendor): MDM sync the device records and push the DEP profiles to Apple
4. DEP check-in (Device): Device gets his DEP profile
5. Profile retrieval (Device)
6. Profile installation (Device) a. incl. MDM, SCEP and root CA payloads
7. MDM command issuance (Device)

![](<../../../.gitbook/assets/image (694).png>)

The file `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` exports functions that can be considered **high-level "steps"** of the enrolment process.

### Step 4: DEP check-in - Getting the Activation Record

This part of the process occurs when a **user boots a Mac for the first time** (or after a complete wipe)

![](<../../../.gitbook/assets/image (1044).png>)

or when executing `sudo profiles show -type enrollment`

* Determine **whether device is DEP enabled**
* Activation Record is the internal name for **DEP “profile”**
* Begins as soon as the device is connected to Internet
* Driven by **`CPFetchActivationRecord`**
* Implemented by **`cloudconfigurationd`** via XPC. The **"Setup Assistant**" (when the device is firstly booted) or the **`profiles`** command will **contact this daemon** to retrieve the activation record.
  * LaunchDaemon (always runs as root)

It follows a few steps to get the Activation Record performed by **`MCTeslaConfigurationFetcher`**. This process uses an encryption called **Absinthe**

1. Retrieve **certificate**
   1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Initialize** state from certificate (**`NACInit`**)
   1. Uses various device-specific data (i.e. **Serial Number via `IOKit`**)
3. Retrieve **session key**
   1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Establish the session (**`NACKeyEstablishment`**)
5. Make the request
   1. POST to [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) sending the data `{ "action": "RequestProfileConfiguration", "sn": "" }`
   2. The JSON payload is encrypted using Absinthe (**`NACSign`**)
   3. All requests over HTTPs, built-in root certificates are used

![](<../../../.gitbook/assets/image (566) (1).png>)

The response is a JSON dictionary with some important data like:

* **url**: URL of the MDM vendor host for the activation profile
* **anchor-certs**: Array of DER certificates used as trusted anchors

### **Step 5: Profile Retrieval**

![](<../../../.gitbook/assets/image (444).png>)

* Request sent to **url provided in DEP profile**.
* **Anchor certificates** are used to **evaluate trust** if provided.
  * Reminder: the **anchor\_certs** property of the DEP profile
* **Request is a simple .plist** with device identification
  * Examples: **UDID, OS version**.
* CMS-signed, DER-encoded
* Signed using the **device identity certificate (from APNS)**
* **Certificate chain** includes expired **Apple iPhone Device CA**

![](<../../../.gitbook/assets/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Step 6: Profile Installation

* Once retrieved, **profile is stored on the system**
* This step begins automatically (if in **setup assistant**)
* Driven by **`CPInstallActivationProfile`**
* Implemented by mdmclient over XPC
  * LaunchDaemon (as root) or LaunchAgent (as user), depending on context
* Configuration profiles have multiple payloads to install
* Framework has a plugin-based architecture for installing profiles
* Each payload type is associated with a plugin
  * Can be XPC (in framework) or classic Cocoa (in ManagedClient.app)
* Example:
  * Certificate Payloads use CertificateService.xpc

Typically, **activation profile** provided by an MDM vendor will **include the following payloads**:

* `com.apple.mdm`: to **enroll** the device in MDM
* `com.apple.security.scep`: to securely provide a **client certificate** to the device.
* `com.apple.security.pem`: to **install trusted CA certificates** to the device’s System Keychain.
* Installing the MDM payload equivalent to **MDM check-in in the documentation**
* Payload **contains key properties**:
*
  * MDM Check-In URL (**`CheckInURL`**)
  * MDM Command Polling URL (**`ServerURL`**) + APNs topic to trigger it
* To install MDM payload, request is sent to **`CheckInURL`**
* Implemented in **`mdmclient`**
* MDM payload can depend on other payloads
* Allows **requests to be pinned to specific certificates**:
  * Property: **`CheckInURLPinningCertificateUUIDs`**
  * Property: **`ServerURLPinningCertificateUUIDs`**
  * Delivered via PEM payload
* Allows device to be attributed with an identity certificate:
  * Property: IdentityCertificateUUID
  * Delivered via SCEP payload

### **Step 7: Listening for MDM commands**

* After MDM check-in is complete, vendor can **issue push notifications using APNs**
* Upon receipt, handled by **`mdmclient`**
* To poll for MDM commands, request is sent to ServerURL
* Makes use of previously installed MDM payload:
  * **`ServerURLPinningCertificateUUIDs`** for pinning request
  * **`IdentityCertificateUUID`** for TLS client certificate

## Attacks

### Enrolling Devices in Other Organisations

As previously commented, in order to try to enrol a device into an organization **only a Serial Number belonging to that Organization is needed**. Once the device is enrolled, several organizations will install sensitive data on the new device: certificates, applications, WiFi passwords, VPN configurations [and so on](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Therefore, this could be a dangerous entrypoint for attackers if the enrolment process isn't correctly protected:

{% content-ref url="enrolling-devices-in-other-organisations.md" %}
[enrolling-devices-in-other-organisations.md](enrolling-devices-in-other-organisations.md)
{% endcontent-ref %}

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
