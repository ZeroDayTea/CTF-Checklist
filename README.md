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
| dsniff | Sniff passwords from packet capture files | [dsniff](https://www.monkey.org/~dugsong/dsniff/) |
| foremost | Extract files from other files by header | ``sudo apt install foremost`` |
| stegsnow | white space steganography | ``sudo apt install steganography`` | 

## Web
| Tool        | Description | Link |
| ----------- | ----------- | ---- |
| RequestBin  | Capture web requests | [RequestBin](https://requestbin.com/r) |
| revshells   | Generate reverse web shells for upload to a variety of different server types | [revshells](https://www.revshells.com/) |
| BurpSuite   | Intercept http requests, analyze them, and modify them before sending | [BurpSuite](https://portswigger.net/burp/communitydownload) |
| sqlmap      | Automate sending sql injection payloads and detect sql injections on webpages | [sqlmap](https://github.com/sqlmapproject/sqlmap) |
| SQL Injection | SQL Injection authentication bypass cheatsheet | [sql cheatsheet](https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/) |
| SUID Find   | Find SUID binaries on a linux system using ``find / -perm -u=s -type f 2>/dev/null`` |
| root binary find | Find binaries that run with root privileges | ``sudo -l`` |
| Dirbuster   | Find hidden directory and file paths on web servers | [Dirbuster](https://www.kali.org/tools/dirbuster/) |
| Postman     | General purpose HTTP request debugger and generator | [Postman](https://www.postman.com/downloads/) |

## Binary Exploitation
| Tool        | Description | Link |
| ----------- | ----------- | ---- |
| ir0nstone   | PWN tutorials containing many resources/scripts for solving pwn challenges | [ir0nstone](https://ir0nstone.gitbook.io/) |
| pwntools    | Python library for prototyping and writing exploits | [pwntools](https://docs.pwntools.com/en/stable/) |
| ROPGadget   | Tool for find ROP tools and crafting ROP chains | [ROPGadget](https://github.com/JonathanSalwan/ROPgadget) |
| shellstorm  | Database of shellcode in both assembly and byte format | [shellstorm](https://shell-storm.org/shellcode/index.html) |
| Wiremask Buffer Overflow | Buffer overflow pattern generator that when combined with gdb can determine the offset to EIP/RIP when no canary is present | [Wiremask](https://wiremask.eu/tools/buffer-overflow-pattern-generator/) |
| one_gadget  | Find ROP gadgets specifically for spawning a shell i.e ROPing to execve('/bin/sh/, NULL, NULL) | [one_gadget](https://github.com/david942j/one_gadget) |
| checksec    | check binary security properties of the executable revealing which attack vectors will be possible | ``sudo apt-get install checksec`` |
| Guide to Reading Assembly | The faker's guide to reading (x86) assembly language | [Assembly Guide](https://www.timdbg.com/posts/fakers-guide-to-assembly/) |

## Reverse Engineering
| Tool        | Description | Link |
| ----------- | ----------- | ---- |
| Ghidra      | Reverse Engineering toolkit for decompiling binaries into C code for static analysis | [Ghidra](https://ghidra-sre.org/) |
| Uncompyle   | Decompile Python binaries | [Uncompyle](https://github.com/gstarnberger/uncompyle) |
| angr        | Binary analysis platform for Python with static/dynamic analysis support and symbolic execution | [angr](https://angr.io/) |
| jdgui       | Java decompiler for .class files | [jdgui](http://jd.benow.ca/) |
| IDA Freeware| Binary code analysis and reverse engineering | [IDA Freeware](https://hex-rays.com/ida-free/#download) |
| ImHex        | Hex Editor for reverse engineering with patterns | [ImHex](https://github.com/WerWolv/ImHex) |

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
| xortool     | Good for multi-byte xor analysis | [xortool](https://github.com/hellman/xortool) |
| randcrack | Predict values generated by Python's random module | [randcrack](https://github.com/tna0y/Python-random-module-cracker) |
| RSA Algorithm | A nice explanation of the RSA algorithm by Lei Mao | [RSA Tutorial](https://leimao.github.io/article/RSA-Algorithm/) |
| Elliptic Curves | Elliptic Curve notes by Ben Lynn | [Elliptic Curves](https://web.archive.org/web/20220412170936/https://crypto.stanford.edu/pbc/notes/elliptic/) |
| cryptopals  | Website with learning tools and challenges for learning about cryptography | [cryptopals](https://cryptopals.com/) |

## OSINT
| Tool        | Description | Link |
| ----------- | ----------- | ---- |
| ARPSyndicate | List of helpful OSINT resources | [ARPSyndicate](https://github.com/ARPSyndicate/awesome-intelligence) |
| Epieos      | OSINT Tool search engine that performs a variety of searches | [Epieos](https://epieos.com/) |

## Papers
| Category    | Title       | Link |
| ----------- | ----------- | ---- |
| crypto      | Solving problems with the LLL algorithm | [LLL](https://www.math.fsu.edu/~hoeij/papers/LLL.pdf) |
