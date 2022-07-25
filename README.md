# Simple XSS filter bypass Burp Suite extension
## Description
Extension for PortSwigger Burp Suite which check and bypass XSS filters.

## Installation
Clone the repository:
```
git clone whoishacked/burp_xss_filter_bypass_module
```

Download Jython: https://www.jython.org/

Open Burp Suite Extender->Options tab and set Jython file location in Python Environment

Open Burp Suite Extender->Extensions tab and add the `xss_filter_bypass.py` extension.

This extension uses https://github.com/securityMB/burp-exceptions/
for raise exceptions in Python. You need to install it too: 
https://github.com/securityMB/burp-exceptions/blob/master/exceptions_fix.py.

## Usage

You can use payloads in Repeater. Just right-click, select payload
in Extensions->XSS Filter Bypass, send request and check response. Also, you can
paste any payload inside tag {XSS}, for ex.: {XSS}this_is_my_payload{XSS}. 
If payload works - you will see the message: `<!-- {XSS} -->`. 

## Technologies
- Python
- Jython
- Burp Exceptions
- Burp Suite API

## Authors
**Andrew Kutuzov:**
- Telegram: @andrewkutuzov