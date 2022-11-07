# CTF-Checklist
A composite list of various vulnerabilities and tools to look for and use while exploiting common CTF challenges

## Forensics

| Tool        | Description | Link |
| ----------- | ----------- | ---- |
| Wireshark   | Capture packets sent by devices and analyze pcap files | [Wireshark](https://www.wireshark.org/download.html) |
| pkcrack     | Crack zip passwords or run known plaintext attacks | [pkcrack](https://www.unix-ag.uni-kl.de/~conrad/krypto/pkcrack.html) |
| volatility  | Analyze memory dumps | [volatility](https://github.com/volatilityfoundation/volatility) |
| rockyou.txt | List of common passwords helpful in many categories | [rockyou.txt](https://www.kaggle.com/datasets/wjburns/common-password-list-rockyoutxt) |
| Aperi Solve | Image forensics tool that runs many stegonography tools | [Aperi Solve](https://www.aperisolve.fr/) |
| Audacity    | Analyze, visualize, and modify audio files | [Audacity](https://www.audacityteam.org/download/) |
| SleuthKit   | Analyze disk drives and dumps | [SleuthKit](http://www.sleuthkit.org/sleuthkit/download.php) |
| John The Ripper | General purpose password cracker | [John The Ripper](http://www.openwall.com/john/) |

## Web
| Tool        | Description | Link |
| ----------- | ----------- | ---- |
| RequestBin  | Capture web requests | [RequestBin](https://requestbin.com/r) |
| revshells   | Generate reverse web shells for upload to a variety of different server types | [revshells](https://www.revshells.com/) |
| BurpSuite   | Intercept http requests, analyze them, and modify them before sending | [BurpSuite](https://portswigger.net/burp/communitydownload) |
| sqlmap      | Automate sending sql injection payloads and detect sql injections on webpages | [sqlmap](https://github.com/sqlmapproject/sqlmap) |
| SQL Injection | SQL Injection authentication bypass cheatsheet | [sql cheatsheet](https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/) |
| SUID Find   | Find SUID binaries on a linux system using ``find / -perm -u=s -type f 2>/dev/null`` | |

## Binary Exploitation
| Tool        | Description | Link |
| ----------- | ----------- | ---- |
| ir0nstone   | PWN tutorials containing many resources/scripts for solving pwn challenges | [ir0nstone](https://ir0nstone.gitbook.io/) |
| pwntools    | Python library for prototyping and writing exploits | [pwntools](https://docs.pwntools.com/en/stable/) |
| ROPGadget   | Tool for find ROP tools and crafting ROP chains | [ROPGadget](https://github.com/JonathanSalwan/ROPgadget) |
| shellstorm  | Database of shellcode in both assembly and byte format | [shellstorm](https://shell-storm.org/shellcode/index.html) |
| Wiremask Buffer Overflow | Buffer overflow pattern generator that when combined with gdb can determine the offset to EIP/RIP when no canary is present | [Wiremask](https://wiremask.eu/tools/buffer-overflow-pattern-generator/) |
| one_gadget  | Find ROP gadgets specifically for spawning a shell i.e ROPing to execve('/bin/sh/, NULL, NULL) | [one_gadget](https://github.com/david942j/one_gadget) |

## Reverse Engineering
| Tool        | Description | Link |
| ----------- | ----------- | ---- |
| Ghidra      | Reverse Engineering toolkit for decompiling binaries into C code for static analysis | [Ghidra](https://ghidra-sre.org/) |
| Uncompyle   | Decompile Python binaries | [Uncompyle](https://github.com/gstarnberger/uncompyle) |
| angr        | Binary analysis platform for Python with static/dynamic analysis support and symbolic execution | [angr](https://angr.io/) |
| jdgui       | Java decompiler for .class files | [jdgui](http://jd.benow.ca/) |

## Cryptography
| Tool        | Description | Link |
| ----------- | ----------- | ---- |
| alpertron   | Factor very large integers | [alpertron](https://www.alpertron.com.ar/ECM.HTM) |
| factordb    | Database of many factored large integers | [factordb](http://factordb.com/) |
| CyberChef   | Generally useful for analyze encoded/encrypted strings and files | [CyberChef](https://gchq.github.io/CyberChef/) |
| z3          | Theorem prover | [z3](https://github.com/Z3Prover/z3) |
| OR-Tools    | Similar to z3 but supposedly faster | [OR-Tools](https://developers.google.com/optimization/introduction/overview) |
| RsaCtfTool  | Python script for automatically running known RSA attacks given various inputs | [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) |
| sage        | Fast math good. Fast math as python library good for quick scripting solutions | [sage](https://doc.sagemath.org/html/en/index.html) |
