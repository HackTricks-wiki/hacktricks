# The Modbus Protocol 

## Introduction to Modbus Protocol 

The Modbus protocol is a widely used protocol in Industrial Automation and Control Systems. Modbus allows communication between various devices such as programmable logic controllers (PLCs), sensors, actuators, and other industrial devices. Understanding the Modbus Protocol is essential since this is the single most used communication protocol in the ICS and has a lot of potential attack surface for sniffing and even injecting commands into PLCs.

Here, concepts are stated point-wise providing context of the protcol and it's nature of operation. The biggest challenge in ICS system security is the cost of implementation and upgradation. These protocols and standards where designed in the early 80s and 90s which are still widely used. Since an industry has a lot of devices and connections, upgrading devices is very difficult, which provides hackers with an edge of dealing with outdated protocols. Attacks on Modbus is like practically unevitable since it is going to be used without upgradation is it's operation is critical to the industry. 

## The Client-Server Architecture

Modbus Protocol is typically used as in Client Server Architecture where a master device (client) initiates communication with one or more slave devices (servers). This is also referred to as Master-Slave architecture, which is widely used in electronics and IoT with SPI, I2C, etc. 

## Serial and Etherent Versions

Modbus Protocol is designed for both, Serial Communication as well as Ethernet Communications. The Serial Communication is widely used in legacy systems while modern devices support Ethernet which offers high data rates and is more suitable for modern industrial networks. 

## Data Representation 

Data is transmitted in Modbus protocol as ASCII or Binary, although the binary format is used due to it's compactibility with older devices. 

## Function Codes 

 ModBus Protocol works with transmission of specific function codes that are used to operate the PLCs and various control devices. This portion is important to undertstand since replay attacks can be done by retransmitting function codes. Legacy devices do not support any encryption towards data transmission and usually have long wires which connect them, which results to tampering of these wires and capturing/injected data. 

 ## Addressing of Modbus 

Each device in the network has some unique address which is essential for communication between devices. Protocols like Modbus RTU, Modbus TCP, etc. are used to implement addressing and serves like a transport layer to the data transmission. The data that is transferred is in the Modbus protocol format that contains the message.

Furthermore, Modbus also implements error checks to ensure the integrity of the transmitted data. But most of al, Modbus is a Open Standard and anyone can implement it in their devices. This made this protocol to go on global standard and it's widespread in the industrial automation industry. 

Due to it's large scale use and lack of upgradations, attacking Modbus provides a significant advantage with it's attack surface. ICS is highly dependent on communication between devices and any attacks made on them can be dangerous for the operation of the industrial systems. Attacks like replay, data injection, data sniffing and leaking, Denial of Service, data forgery, etc. can be carried out if the medium of transmission is identified by the attacker. 


