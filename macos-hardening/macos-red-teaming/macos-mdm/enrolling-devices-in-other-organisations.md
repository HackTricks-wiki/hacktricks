# Enrolling Devices in Other Organisations

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Intro

As [**previously commented**](./#what-is-mdm-mobile-device-management)**,** in order to try to enrol a device into an organization **only a Serial Number belonging to that Organization is needed**. Once the device is enrolled, several organizations will install sensitive data on the new device: certificates, applications, WiFi passwords, VPN configurations [and so on](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Therefore, this could be a dangerous entrypoint for attackers if the enrolment process isn't correctly protected.

**The following is a summary of the research [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Check it for further technical details!**

## Overview of DEP and MDM Binary Analysis

This research delves into the binaries associated with the Device Enrollment Program (DEP) and Mobile Device Management (MDM) on macOS. Key components include:

- **`mdmclient`**: Communicates with MDM servers and triggers DEP check-ins on macOS versions before 10.13.4.
- **`profiles`**: Manages Configuration Profiles, and triggers DEP check-ins on macOS versions 10.13.4 and later.
- **`cloudconfigurationd`**: Manages DEP API communications and retrieves Device Enrollment profiles.

DEP check-ins utilize the `CPFetchActivationRecord` and `CPGetActivationRecord` functions from the private Configuration Profiles framework to fetch the Activation Record, with `CPFetchActivationRecord` coordinating with `cloudconfigurationd` through XPC.

## Tesla Protocol and Absinthe Scheme Reverse Engineering

The DEP check-in involves `cloudconfigurationd` sending an encrypted, signed JSON payload to _iprofiles.apple.com/macProfile_. The payload includes the device's serial number and the action "RequestProfileConfiguration". The encryption scheme used is referred to internally as "Absinthe". Unraveling this scheme is complex and involves numerous steps, which led to exploring alternative methods for inserting arbitrary serial numbers in the Activation Record request.

## Proxying DEP Requests

Attempts to intercept and modify DEP requests to _iprofiles.apple.com_ using tools like Charles Proxy were hindered by payload encryption and SSL/TLS security measures. However, enabling the `MCCloudConfigAcceptAnyHTTPSCertificate` configuration allows bypassing the server certificate validation, although the payload's encrypted nature still prevents modification of the serial number without the decryption key.

## Instrumenting System Binaries Interacting with DEP

Instrumenting system binaries like `cloudconfigurationd` requires disabling System Integrity Protection (SIP) on macOS. With SIP disabled, tools like LLDB can be used to attach to system processes and potentially modify the serial number used in DEP API interactions. This method is preferable as it avoids the complexities of entitlements and code signing.

**Exploiting Binary Instrumentation:**
Modifying the DEP request payload before JSON serialization in `cloudconfigurationd` proved effective. The process involved:

1. Attaching LLDB to `cloudconfigurationd`.
2. Locating the point where the system serial number is fetched.
3. Injecting an arbitrary serial number into the memory before the payload is encrypted and sent.

This method allowed for retrieving complete DEP profiles for arbitrary serial numbers, demonstrating a potential vulnerability.

### Automating Instrumentation with Python

The exploitation process was automated using Python with the LLDB API, making it feasible to programmatically inject arbitrary serial numbers and retrieve corresponding DEP profiles.

### Potential Impacts of DEP and MDM Vulnerabilities

The research highlighted significant security concerns:

1. **Information Disclosure**: By providing a DEP-registered serial number, sensitive organizational information contained in the DEP profile can be retrieved.
2. **Rogue DEP Enrollment**: Without proper authentication, an attacker with a DEP-registered serial number can enroll a rogue device into an organization's MDM server, potentially gaining access to sensitive data and network resources.

In conclusion, while DEP and MDM provide powerful tools for managing Apple devices in enterprise environments, they also present potential attack vectors that need to be secured and monitored.



<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
