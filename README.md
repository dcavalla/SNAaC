# SNAaC
This is Security Network Analytics as Code project for SNA automatic deployment and configuration version 1.

Requirements:
- Secure Network Analytics 7.3.x
- Python 3.8 or above
- Python packages:
    - ipwhois
    - ipaddress
    - requests
    - wmi       (win)
    - netifaces (macOS)

Installation

- Ensure Python 3 is installed.
    - To download and install Python 3, please visit https://www.python.org.
- Ensure the requirements are satisfied:
    - On Mac OS X: pip install -r requirements-mac.txt
    - On Windows: pip install -r requirements-win.txt
- Download the .py files located in the python directory.

Alternatively, advanced users can also use git to checkout / clone this project.

Usage

`python snaac.py`

Use --debug for debug info: `python snaac.py --debug`

For information please see SNAaC_v1_User_guide.docx

Known issues

No known issues.

Getting help

Use this project at your own risk (support not provided). If you need technical support with Cisco Stealthwatch APIs, do one of the following:
Browse the Forum

Getting involved

Contributions to this code are welcome and appreciated. See [CONTRIBUTING](CONTRIBUTING.md) for details. Please adhere to our Code of Conduct at all times.

Licensing info

This code is licensed under the BSD 3-Clause License. See [LICENSE](LICENSE) for details.