# Simple XSS filter bypass
## Description
Extension for Portswiger Burp Suite which check and bypass XSS filters.

## Install
Clone the repository:
```
git clone whoishacked/burp_xss_filter_bypass_module
```

Download Jython: https://www.jython.org/

Open Burp Suite Extender->Options tab and set Jython file location in Python Environment

Open Burp Suite Extender->Extensions tab and add the extension.

## Usage

You can use payloads in Repeater GET/POST requests. Just right-click, select payload
in Extensions->XSS Filter Bypass, send request and check response.

## Technologies
- Python
- Jython
- Burp Suite API

## Authors
**Andrew Kutuzov:**
- Telegram: @andrewkutuzov