# Baseline Monitoring

## Baseline

A baseline consist on take a snapshot of certain part of a system in oder to c**ompare it with a future status to highlight changes**.

For example, you can calculate and store the hash of each file of the filesystem to .be able to find out which files were modified.\
This can also be done with the user accounts created, processes running, services running and any other thing that shouldn't change much, or at all. 

### File Integrity Monitoring

File integrity monitoring is one of the most powerful techniques used to secure IT infrastructures and business data against a wide variety of both known and unknown threats.\
The goal is to generate a **baseline of all the files** that you want monitor and then **periodically** **check** those files for possible **changes** (in the content, attribute, metadata...).

1\. **Baseline comparison,** wherein one or more file attributes will be captured or calculated and stored as a baseline that can be compared against at some future time. This can be as simple as the time and date of the file, however, since this data can be easily spoofed, a more trustworthy approach is typically used. This may include periodically assessing the cryptographic checksum for a monitored file, (e.g. using the MD5 or SHA-2 hashing algorithm) and then comparing the result to the previously calculated checksum.

2\. **Real-time change notification**, which is typically implemented within or as an extension to the kernel of the operating system that will flag when a file is accessed or modified.

### Tools

* [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
* [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

## References

* [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)
