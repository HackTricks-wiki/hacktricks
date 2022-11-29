# FISSURE - The RF Framework 
**Frequency Independent SDR-based Signal Understanding and Reverse Engineering**

FISSURE is an open-source RF and reverse engineering framework designed for all skill levels with hooks for signal detection and classification, protocol discovery, attack execution, IQ manipulation, vulnerability analysis, automation, and AI/ML. The framework was built to promote the rapid integration of software modules, radios, protocols, signal data, scripts, flow graphs, reference material, and third-party tools. FISSURE is a workflow enabler that keeps software in one location and allows teams to effortlessly get up to speed while sharing the same proven baseline configuration for specific Linux distributions.

The framework and tools included with FISSURE are designed to detect the presence of RF energy, understand the characteristics of a signal, collect and analyze samples, develop transmit and/or injection techniques, and craft custom payloads or messages. FISSURE contains a growing library of protocol and signal information to assist in identification, packet crafting, and fuzzing. Online archive capabilities exist to download signal files and build playlists to simulate traffic and test systems. 

The friendly Python codebase and user interface allows beginners to quickly learn about popular tools and techniques involving RF and reverse engineering. Educators in cybersecurity and engineering can take advantage of the built-in material or utilize the framework to demonstrate their own real-world applications. Developers and researchers can use FISSURE for their daily tasks or to expose their cutting-edge solutions to a wider audience. As awareness and usage of FISSURE grows in the community, so will the extent of its capabilities and the breadth of the technology it encompasses.

**Additional Information**

- [AIS Page](https://www.ainfosec.com/technologies/fissure/)
- [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE_Poore_GRCon22.pdf)
- [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
- [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Getting Started

**Supported**

There are three branches within FISSURE to make file navigation easier and reduce code redundancy. The Python2_maint-3.7 branch contains a codebase built around Python2, PyQt4, and GNU Radio 3.7; the Python3_maint-3.8 branch is built around Python3, PyQt5, and GNU Radio 3.8; and the Python3_maint-3.10 branch is built around Python3, PyQt5, and GNU Radio 3.10.

Operating System            |  FISSURE Branch
:-------------------------:|:-------------------------:
| Ubuntu 18.04 (x64) | Python2_maint-3.7 | 
| Ubuntu 18.04.5 (x64) | Python2_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3_maint-3.8 |
| KDE neon 5.25 (x64) | Python3_maint-3.8 |

**In-Progress (beta)**

These operating systems are still in beta status. They are under development and several features are known to be missing. Items in the installer might conflict with existing programs or fail to install until the status is removed.

Operating System            |  FISSURE Branch
:-------------------------:|:-------------------------:
| DragonOS Focal (x86_64) | Python3_maint-3.8 |
| Ubuntu 22.04 (x64) | Python3_maint-3.10 |

Note: Certain software tools do not work for every OS. Refer to [Software And Conflicts](https://github.com/ainfosec/FISSURE/blob/Python3_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Installation** 
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```

This will install PyQt software dependencies required to launch the installation GUIs if they are not found. 

Next, select the option that best matches your operating system (should be detected automatically if your OS matches an option).

Python2_maint-3.7            |  Python3_maint-3.8            |  Python3_maint-3.10
:-------------------------:|:-------------------------:|:-------------------------:
![install1b](https://github.com/ainfosec/FISSURE/blob/Python3_maint-3.8/Icons/README/install1b.png)  |  ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3_maint-3.8/Icons/README/install1a.png)  |  ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3_maint-3.8/Icons/README/install1c.png)

It is recommended to install FISSURE on a clean operating system to avoid existing conflicts. Select all the recommended checkboxes (Default button) to avoid errors while operating the various tools within FISSURE. There will be multiple prompts throughout the installation, mostly asking for elevated permissions and user names. If an item contains a "Verify" section at the end, the installer will run the command that follows and highlight the checkbox item green or red depending on if any errors are produced by the command. Checked items without a "Verify" section will remain black following the installation.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3_maint-3.8/Icons/README/install2.png)

**Usage**

Open a terminal and enter:

```
fissure
```

Refer to the FISSURE Help menu for more details on usage. 

## Details

**Components**
- Dashboard
- Central Hub (HIPRFISR)
- Target Signal Identification (TSI)
- Protocol Discovery (PD)
- Flow Graph & Script Executor (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3_maint-3.8/Icons/README/components.png)

**Capabilities**

<table style="padding:10px">
  <tr>
    <td><img src="https://github.com/ainfosec/FISSURE/blob/Python3_maint-3.8/Icons/README/detector.png" align="center" width="200" height="165"><dt align="center"><small><i><b>Signal Detector</b></i></small></dt></td>
    <td><img src="https://github.com/ainfosec/FISSURE/blob/Python3_maint-3.8/Icons/README/iq.png" align="center" width="200" height="165"><dt align="center"><small><i><b>IQ Manipulation</b></i></small></dt></td>
    <td><img src="https://github.com/ainfosec/FISSURE/blob/Python3_maint-3.8/Icons/README/library.png" align="center" width="200" height="165"><dt align="center"><small><i><b>Signal Lookup</b></i></small></dt></td>
    <td><img src="https://github.com/ainfosec/FISSURE/blob/Python3_maint-3.8/Icons/README/pd.png" align="center" width="200" height="165"><dt align="center"><small><i><b>Pattern Recognition</b></i></small></dt></td>
  </tr>
    <td><img src="https://github.com/ainfosec/FISSURE/blob/Python3_maint-3.8/Icons/README/attack.png" align="center" width="200" height="165"><dt align="center"><small><i><b>Attacks</b></i></small></dt></td>
    <td><img src="https://github.com/ainfosec/FISSURE/blob/Python3_maint-3.8/Icons/README/fuzzing.png" align="center" width="200" height="165"><dt align="center"><small><i><b>Fuzzing</b></i></small></dt></td>
    <td><img src="https://github.com/ainfosec/FISSURE/blob/Python3_maint-3.8/Icons/README/archive.png" align="center" width="200" height="165"><dt align="center"><small><i><b>Signal Playlists</b></i></small></dt></td>
    <td><img src="https://github.com/ainfosec/FISSURE/blob/Python3_maint-3.8/Icons/README/gallery.png" align="center" width="200" height="165"><dt align="center"><small><i><b>Image Gallery</b></i></small></dt></td>
  </tr>
  <tr>
    <td><img src="https://github.com/ainfosec/FISSURE/blob/Python3_maint-3.8/Icons/README/packet.png" align="center" width="200" height="165"><dt align="center"><small><i><b>Packet Crafting</b></i></small></dt></td>
    <td><img src="https://github.com/ainfosec/FISSURE/blob/Python3_maint-3.8/Icons/README/scapy.png" align="center" width="200" height="165"><dt align="center"><small><i><b>Scapy Integration</b></i></small></dt></td>
    <td><img src="https://github.com/ainfosec/FISSURE/blob/Python3_maint-3.8/Icons/README/crc_calculator.png" align="center" width="200" height="165"><dt align="center"><small><i><b>CRC Calculator</b></i></small></dt></td>
    <td><img src="https://github.com/ainfosec/FISSURE/blob/Python3_maint-3.8/Icons/README/log.png" align="center" width="200" height="165"><dt align="center"><small><i><b>Logging</b></i></small></dt></td>
  </tr>  
</table>

**Hardware**

The following is a list of "supported" hardware with varying levels of integration:
- USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
- HackRF
- RTL2832U
- 802.11 Adapters
- LimeSDR
- bladeRF, bladeRF 2.0 micro
- Open Sniffer
- PlutoSDR

## Lessons

FISSURE comes with several helpful guides to become familiar with different technologies and techniques. Many include steps for using various tools that are integrated into FISSURE.
- [Lesson1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3_maint-3.8/Lessons/Markdown/Lesson1_OpenBTS.md)
- [Lesson2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3_maint-3.8/Lessons/Markdown/Lesson2_LuaDissectors.md)
- [Lesson3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3_maint-3.8/Lessons/Markdown/Lesson3_Sound_eXchange.md)
- [Lesson4: ESP Boards](https://github.com/ainfosec/FISSURE/blob/Python3_maint-3.8/Lessons/Markdown/Lesson4_ESP_Boards.md)
- [Lesson5: Radiosonde Tracking](https://github.com/ainfosec/FISSURE/blob/Python3_maint-3.8/Lessons/Markdown/Lesson5_Radiosonde_Tracking.md)
- [Lesson6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3_maint-3.8/Lessons/Markdown/Lesson6_RFID.md)
- [Lesson7: Data Types](https://github.com/ainfosec/FISSURE/blob/Python3_maint-3.8/Lessons/Markdown/Lesson7_Data_Types.md)
- [Lesson8: Custom GNU Radio Blocks](https://github.com/ainfosec/FISSURE/blob/Python3_maint-3.8/Lessons/Markdown/Lesson8_Custom_GNU_Radio_Blocks.md)
- [Lesson9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3_maint-3.8/Lessons/Markdown/Lesson9_TPMS.md)
- [Lesson10: Ham Radio Exams](https://github.com/ainfosec/FISSURE/blob/Python3_maint-3.8/Lessons/Markdown/Lesson10_Ham_Radio_Exams.md)
- [Lesson11: Wi-Fi Tools](https://github.com/ainfosec/FISSURE/blob/Python3_maint-3.8/Lessons/Markdown/Lesson11_WiFi_Tools.md)

## Roadmap

- [ ] Add more hardware types, RF protocols, signal parameters, analysis tools
- [ ] Support more operating systems
- [ ] Develop class material around FISSURE (RF Attacks, Wi-Fi, GNU Radio, PyQt, etc.)
- [ ] Create a signal conditioner, feature extractor, and signal classifier with selectable AI/ML techniques
- [ ] Implement recursive demodulation mechanisms for producing a bitstream from unknown signals
- [ ] Transition the main FISSURE components to a generic sensor node deployment scheme

## Contributing

Suggestions for improving FISSURE are strongly encouraged. Leave a comment in the [Discussions](https://github.com/ainfosec/FISSURE/discussions) page or in the Discord Server if you have any thoughts regarding the following:
- New feature suggestions and design changes
- Software tools with installation steps
- New lessons or additional material for existing lessons
- RF protocols of interest
- More hardware and SDR types for integration
- IQ analysis scripts in Python
- Installation corrections and improvements

Contributions to improve FISSURE are crucial to expediting its development. Any contributions you make are greatly appreciated. If you wish to contribute through code development, please fork the repo and create a pull request:

1. Fork the project
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a pull request

Creating [Issues](https://github.com/ainfosec/FISSURE/issues) to bring attention to bugs is also welcomed.

## Collaborating

Contact Assured Information Security, Inc. (AIS) Business Development to propose and formalize any FISSURE collaboration opportunities–whether that is through dedicating time towards integrating your software, having the talented people at AIS develop solutions for your technical challenges, or integrating FISSURE into other platforms/applications.  

## License

GPL-3.0

For license details, see LICENSE file.

## Contact

Join the Discord Server: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Follow on Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Credits

We acknowledge and are grateful to these developers: 

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3_maint-3.8/CREDITS.md)

## Acknowledgments

Special thanks to Dr. Samuel Mantravadi and Joseph Reith for their contributions to this project.

