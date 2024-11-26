# Cocktail.exe Malware Project

## Overview
Cocktail.exe is a proof-of-concept malware developed for educational purposes as part of the Malware and Attack Reverse Engineering course (CSS 579 A). It demonstrates techniques such as persistence mechanisms, obfuscation, anti-debugging, and anti-disassembly.

---

## Table of Contents
1. [Abstract](#abstract)
2. [Objectives](#objectives)
3. [Technical Specifications](#technical-specifications)
4. [Design and Techniques](#design-and-techniques)
5. [Workflow](#workflow)
6. [Testing and Results](#testing-and-results)
7. [Mitigation and Detection Strategies](#mitigation-and-detection-strategies)
8. [Ethical and Legal Considerations](#ethical-and-legal-considerations)
9. [Conclusion](#conclusion)
10. [References](#references)

---

## Abstract
The malware is written in **C++** and creates a batch script that forces a Windows system into a boot-restart loop. The script is added to the Windows startup folder for persistence. Advanced techniques such as anti-debugging and obfuscation using base64 encoding and UPX packing are incorporated.

---

## Objectives
- **Purpose:** To showcase practical knowledge gained from the Malware Analysis and Attack Reverse Engineering course.
- **Learning Goals:** Familiarization with persistence techniques, obfuscation, and anti-debugging measures.

---

## Technical Specifications
- **Programming Language:** C++
- **Target Platforms:** Windows 10, Windows 7 (x86/x64)
- **System Requirements:** Windows 7 and higher

---

## Design and Techniques
- **Code Injection:** Inserts malicious code into the system.
- **Persistence Mechanisms:** Adds a batch script in the Windows startup directory.
- **Obfuscation:** Utilizes UPX packing, base64 string encoding, and anti-debugging functions.

---

## Workflow
1. **Infection Vector:** The malware acts as a loader.
2. **Execution:** Installs a batch script in the startup directory.
3. **Payload:** 
   - Restarts the system repeatedly by modifying the startup folder.
   - Encodes strings and adds junk code for obfuscation.
   - Ensures persistence.

---

## Testing and Results
- **Environment:** Use isolated environments like VirtualBox or VMware.
- **Execution Steps:** 
   1. Run the malware with administrator privileges.
   2. Observe the creation of a batch file in the startup directory.
- **Results:** Windows systems enter a boot-restart loop after infection.

---

## Mitigation and Detection Strategies
- **Countermeasures:**
  - Use antivirus software to detect signature patterns.
  - Employ behavioral analysis tools.
  - Apply security patches.
- **Limitations:** Requires elevated privileges (administrator mode) for execution.

---

## Ethical and Legal Considerations
- **Intended Use:** Solely for academic and research purposes.
- **Best Practices:** Test in isolated environments only, and ensure no harm to live systems.

---

## Conclusion
This project demonstrates the following:
- Persistence via startup folder manipulation.
- Obfuscation using UPX packing and base64 encoding.
- Challenges in counteracting infinite boot-restart malware.

---

## References
1. *Windows via C/C++*, Fifth Edition by Jeffrey Richter and Christophe Nasarre.
2. *Programming Windows*, Fifth Edition by Charles Petzold.
