# coding=utf-8
from burp import IBurpExtender
from burp import IContextMenuFactory
from javax.swing import JMenuItem
import sys
import base64

if sys.version[0] == '2':
    reload(sys)
    sys.setdefaultencoding("utf-8")

menu_list = ["Add-all-Headers", "Accept-Charset", "Accept-Datetime", "Accept-Encoding", "Accept-Language",
             "Access-Control-Request-Headers", "Access-Control-Request-Method", "Authorization",
             "Cache-Control", "Content-Length", "Content-MD5", "Content-Type",
             "Forwarded", "Front-End-Https",
             "If-Modified-Since", "If-None-Match", "If-Unmodified-Since",
             "Max-Forwards", "Origin", "Proxy-Authorization", "Proxy-Connection",
             "Referer", "Upgrade-Insecure-Requests",
             "X-ATT-DeviceId", "X-Correlation-ID", "X-Csrf-Token", "X-Forwarded-For",
             "X-Forwarded-Host", "X-Forwarded-Proto", "X-Http-Method-Override", "X-Requested-With",
             "X-Request-ID", "X-Wap-Profile"]


class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Headers")
        callbacks.registerContextMenuFactory(self)
        print(base64.b64decode("WytdIEhlYWRlcnMgaXMgbG9hZGVkLi4uClsrXSAjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMKWytdICAgIEFudGhvcjogRG9yYWVtb28KWytdICAgIEJsb2c6ICAgaHR0cHM6Ly9kb3JhZW1vby5naXRodWIuaW8vClsrXSAgICBHaXRodWI6IGh0dHBzOi8vZ2l0aHViLmNvbS9kb3JhZW1vbwpbK10gIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjClsrXSBFbmpveSBpdH4K"))
    def createMenuItems(self, invocation):
        if invocation.getToolFlag() == self._callbacks.TOOL_REPEATER or self._callbacks.TOOL_PROXY:
            menu = []
            for name in menu_list:
                menu.append(JMenuItem("{}".format(name), None,
                                      actionPerformed=lambda x, y=invocation: self.Headers(x, y, name)))
        return menu

    def Headers(self, x, invocation, name, ):
        reqreps = invocation.getSelectedMessages()
        for reqrep in reqreps:
            Rep_B = reqrep.getRequest()
            Rep = self._helpers.analyzeResponse(Rep_B)
            headers = list(Rep.getHeaders())
            body = Rep_B[Rep.getBodyOffset():].tostring()
            if x.getSource().text == "Add-all-Headers":
                for name in menu_list[1:]:
                    headers.append("{}: 127.0.0.1".format(name))
                    newMessage = self._helpers.buildHttpMessage(headers, body)
                    reqrep.setRequest(newMessage)
            else:
                headers.append("{}:".format(x.getSource().text))
                newMessage = self._helpers.buildHttpMessage(headers, body)
                reqrep.setRequest(newMessage)
