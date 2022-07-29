# XSS Restriction bypass checker
## Description
Extension for PortSwigger Burp Suite which check and bypass XSS filters. This project was a part of [Digital Security](https://github.com/DSecurity)'s Penetration Testing department internship ["Summer of Hack 2022"](https://dsec.ru/about/vacancies/#internship).

## Installation
1. Clone the repository:
```
git clone https://github.com/whoishacked/burp_xss_restriction_bypass_checker.git
```

2. Download [Jython](https://www.jython.org/)

3. Open Burp Suite Extender->Options tab and set Jython file location in Python Environment

4. Open Burp Suite Extender->Extensions tab and add the `xss_filter_bypass.py` extension.

5. This extension uses [Burp Exceptions](https://github.com/securityMB/burp-exceptions/)
for throwing exceptions in Python. You also need to install it using [manual](https://github.com/securityMB/burp-exceptions/blob/master/exceptions_fix.py).

## Usage

You can use payloads in Repeater. Just right-click, select payload
in Extensions->XSS Filter Bypass, send request and check response. Also, you can
insert any payload in the `{XSS}` tag, for example: `{XSS}this_is_my_payload{XSS}`. 
If payload works - you will see the message in the response window: `<!-- {XSS} -->`. 

## Technologies
- Python
- Jython
- Burp Exceptions
- Burp Suite API

## Authors
**Andrew Kutuzov:**
- Telegram: @andrewkutuzov
