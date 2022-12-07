# docker-IntelSGX
### [Special Topics in System Security] Final Project 

There are many folders (most are failed attempts on attacks)
The final product is inside /FinalProject. It uses attack primitives discussed in "The Guards Dilemma: Efficient Code-Reuse Attacks Against Intel SGX"

tldr;
goto /FinalProject

## Description of Project

Investigating attack primitives discussed in "The Guards Dilemma: Efficient Code-Reuse Attacks Against Intel SGX" - USENIX Security '18. Specifically the CONT loop.

This project was originally supposed to be attempting hybrid attack against SGX Enclaves by reproducing and combining attacks proposed in papers such as SGXBomb, darkROP, CacheZoom, and Guards Dilemma.

Unfortunately reproduction attempts failed and some didn't have open source implementation. Furthermore, as SGX is a hardware feature most attacks are hardware and operating system dependant. Using docker could not fix this problem.

CacheZoom and SGXBomb Failed to compile due to many factors. First both require SGX to run in HW mode (requires SGX PSW and SGX Driver). Plus These attacks were conducted on specific versions of SGX that requires specific OS. Tests were conducted on Ubuntu 20.04, 18.04, 16.04, and 14.04. 

Since reproduction was difficult and time consuming project shifted to center on reproducing attacks and primitives in a controlled manner to observe how they actually function. This is why Guards Dilemma paper by Biondo and Conti was an excellent choice. This paper explore the SGX SDK which is the only part of the SGX that does not require specific hardware. Although it would not be true SGX investigating SGX SDK on a docker container would provide in depth view of the system.


