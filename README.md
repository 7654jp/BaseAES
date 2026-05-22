<h2 style="text-align: center;">BaseAES</h2>
<span style="text-align: center;">A simple filesystem-like vault system with strong encryption.</span>

*****

> [!CAUTION]
> **PLEASE READ PRECAUTIONS BEFORE USING THIS PROGRAM.**

### Description

This is an encrypted filesystem manager, made by @7654jp.  
This program was written in Rust, and uses AES-256-GCM for encryption.  
**This was made for my personal use. Do not use this for important purposes.**  
All data is stored in 'master.vbase' at same directory as this executable.  
If you want to split vaults, copy this application to a different directory.  
You can set each vault its password, and the vault will be protected with its hash as a key for AES.  
This vault system **IS vulnable** to a memory dump.

### Features

- Text editing
- Can parse JPEG/PNG images
- Load image in separate thread
- Support original text/image display format

*****

Contributions are welcome.  
Please send a PR or open an issue if you want to improve something.

*****

### PRECAUTIONS

**1. DATA INTEGRITY**  

THIS DOES NOT GUARANTEE THAT ENCRYPTED DATA HAS NOT BEEN ALTERED. DATA TAMPERING OR CORRUPTION MAY OCCUR.

**2. DATA LEGALITY**  

USERS ARE SOLELY RESPONSIBLE FOR VERIFYING AND ENSURING THAT THE DATA THEY COLLECT, USE, AND STORE IS LEGALLY PERMISSIBLE. THIS PROGRAM DOES NOT ASSIST WITH SUCH COMPLIANCE.

**3. ACCESS CONTROL**  

ENCRYPTION ALONE DOESN'T GUARANTEE SECURITY. PROPER ACCESS MANAGEMENT MUST BE IMPLEMENTED.

**4. KEY MANAGEMENT**  

SECURELY MANAGING ENCRYPTION KEYS IS CRITICALLY IMPORTANT. IF A KEY IS COMPROMISED, DATA CONFIDENTIALITY WILL BE LOST.

**5. DATA RECOVERY IMPOSSIBILITY**  

LOSING AN ENCRYPTION KEY WILL MAKE YOUR ENCRYPTED DATA INACCESSIBLE. SINCE IT CANNOT BE RECOVERED, THIS POSES A SIGNIFICANT RISK FOR IMPORTANT DATA.

**6. USER AGREEMENT**  

USERS MUST ACKNOWLEDGE AND ACCEPT THE RISKS ASSOCIATED WITH USING THIS PROGRAM IN ADVANCE.

*****

### Licenses

BaseAES is licensed under GPLv3.  

All crates (libraries) are licensed under the MIT license.  
You can see every license under [licenses](licences/) folder.
