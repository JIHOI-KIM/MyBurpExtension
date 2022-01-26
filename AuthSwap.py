from burp import IBurpExtender
from burp import ITab
from burp import IProxyListener
from burp import IParameter

from javax.swing import JPanel, JCheckBox, JLabel
from javax.swing import BoxLayout, Box, JTextField
from javax.swing import SwingConstants
from javax.swing.border import EmptyBorder
from java.awt import BorderLayout, Dimension, Component

import re
import requests
import os

basic_filter = []
basic_filter.append("gif")
basic_filter.append("jpg")
basic_filter.append("png")
basic_filter.append("css")
basic_filter.append("ico")
basic_filter.append("js")
basic_filter.append("svg")
basic_filter.append("eot")
basic_filter.append("wolf")
basic_filter.append("wolf2")
basic_filter.append("ttf")

def FilterFileExtension(filename) :
    global basic_filter
    for ext in basic_filter :
        if filename.endswith(ext) :
            return False
    return True

class BurpExtender(IBurpExtender, ITab, IProxyListener) :
    
    ###
    # IBurpExtender Implementation
    ###
    def registerExtenderCallbacks (self, callbacks) :
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.__path = ""
        self.__logid = 0

        callbacks.setExtensionName("AuthSwapper")
        callbacks.addSuiteTab(self)
        callbacks.registerProxyListener(self)

        return

    ###
    # IProxyListener Implementation
    ###
    def processProxyMessage(self, isReq, message) :
        if self.__isActive.isSelected() == False :
            return

        if not isReq :
            return

        if len(self.__path) < 1 :
            initPath = self.__pathText.getText()
            if not os.path.exists(initPath) :
                print("[ERROR: Disable Extension] Not such Path")
                self.__isActive.setSelected(False)
            if not os.path.isdir(initPath) :
                print("[ERROR: Disable Extension] Path is not a directory")
                self.__isActive.setSelected(False)
            self.__path = initPath

        
        info = message.getMessageInfo()
        req = info.getRequest()
        length = len(req)
        content = ""
        for i in range(0,length) :
            content += chr(req[i])

        host = re.findall("Host: .*\r\n", content)
        host = host[0].split(" ")[1]
        host = host.split("\r\n")[0]

        targetHost = self.__hostText.getText()
        if targetHost == "" :
            print("[ERROR: Disable Extension] No Target Host.")
            self.__isActive.setSelected(False)
            return
        if len(re.findall(targetHost, host)) == 0 :
            return

        filename = re.findall("GET .*[? ]", content) 
        try :
            filename = filename[0].split(" ")[1]
            filename = filename.split("?")[0]
            if not FilterFileExtension(filename) :
                return
        except :
            return

        querys = re.findall("[?].* HTTP", content)
        try :
            querys = querys[0].split("?")[1]
            querys = querys.split(" HTTP")[0]
            querys = querys.split("&")
        except :
            querys = []

        cookie = re.findall("Cookie: .*\r\n", content)
        try :
            cookie = cookie[0].split("Cookie: ")[1]
            cookie = cookie.split("\r\n")[0]
            cookie = cookie.split("; ")
        except :
            cookie = []

        b_queryChange, querys = self.MakeChange(querys)
        b_cookieChange, cookie = self.MakeChange(cookie)

        if b_queryChange == False and b_cookieChange == False :
            return

        self.TestSwap(content, querys, cookie, host, filename)
        return

    ###
    # Custom Function Implementation
    ###

    def MakeChange(self, items) :
        retval = False
        
        arg1field = self.__arg1FieldText.getText().encode("ascii")
        arg1value = self.__arg1ValueText.getText().encode("ascii")
        arg2field = self.__arg2FieldText.getText().encode("ascii")
        arg2value = self.__arg2ValueText.getText().encode("ascii")
        arg3field = self.__arg3FieldText.getText().encode("ascii")
        arg3value = self.__arg3ValueText.getText().encode("ascii")

        temp_dir = {}
        for item in items :
            try :
                field = item.split("=")[0]
                value = item.split("=")[1]
                temp_dir[field] = value
            except :
                pass

        if temp_dir.has_key(arg1field) :
            retval = True
            temp_dir[arg1field] = arg1value

        if temp_dir.has_key(arg2field) :
            retval = True
            temp_dir[arg2field] = arg2value

        if temp_dir.has_key(arg3field) :
            retval = True
            temp_dir[arg3field] = arg3value

        return retval, temp_dir

    def TestSwap(self, content, querys, cookie, host, filename) :
        senduri = "https://" + host + filename

        params = querys 
        cookie_params = cookie
        headers = content.split("\r\n")
        header_params = {}
        for item in headers :
            if item.startswith("GET") :
                continue
            if item.startswith("Cookie:") :
                continue
            if item.startswith("Host:") :
                continue
            try :
                field = item.split(": ")[0]
                value = item.split(": ")[1]
                header_params[field] = value
            except :
                pass

        try:
            res = requests.get(url=senduri, params = params, headers=header_params, cookies=cookie_params)
        except:
            return
        self.Logging(senduri, params, header_params, cookie_params, res)

    def Logging(self, url, params, headers, cookies, res) :
        print("Get Response. Logging...")
        self.__logid = self.__logid + 1
        filename = "id:%d_recode:%s.log" % (self.__logid,res.status_code)
        filepath = os.path.join(self.__path, filename)
        print("CREATE LOG %s" % filepath)
        fp = open(filepath, "w")
        fp.write(url + "\n")
        fp.write(str(params) + "\n")
        fp.write(str(cookies) + "\n")
        fp.write("[RESPONSE %d]---------------\n" % res.status_code)
        fp.write(str(res.content) + "\n")
        fp.write("[END]-----------------------\n")
        fp.close()

    ###
    # ITab Implementation
    ###
    def getTabCaption(self) :
        return "AuthSwapper"

    def getUiComponent(self) :
        panel = JPanel()
        panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
        border = EmptyBorder(30,30,30,30) 
        panel.setBorder(border)
        
        title = JLabel("AuthSwapper v1.0")
        title.setMinimumSize(Dimension(500,20))
        isActive = JCheckBox("Activate AuthSwapper")
        self.__isActive = isActive

        panel.add(title)
        panel.add(Box.createRigidArea(Dimension(0,10)))
        panel.add(isActive)
        panel.add(Box.createRigidArea(Dimension(0,10)))


        L1 = JLabel("Target Host URI (Matching)")
        L1.setHorizontalTextPosition(SwingConstants.LEFT)
        T1 = JTextField()
        self.__hostText = T1
        T1.setMaximumSize(Dimension(500,20))
        panel.add(L1)
        panel.add(Box.createRigidArea(Dimension(0,5)))
        panel.add(T1)
        panel.add(Box.createRigidArea(Dimension(0,10)))

        L2 = JLabel("Swap Argument 1")
        T2 = JTextField()
        self.__arg1FieldText = T2
        T2.setMaximumSize(Dimension(500,20))
        panel.add(L2)
        panel.add(Box.createRigidArea(Dimension(0,5)))
        panel.add(T2)
        panel.add(Box.createRigidArea(Dimension(0,10)))

        L3 = JLabel("Arg 1 Swap Value")
        T3 = JTextField()
        self.__arg1ValueText = T3
        T3.setMaximumSize(Dimension(500,20))
        panel.add(L3)
        panel.add(Box.createRigidArea(Dimension(0,5)))
        panel.add(T3)
        panel.add(Box.createRigidArea(Dimension(0,10)))

        L4 = JLabel("Swap Argument 2")
        T4 = JTextField()
        self.__arg2FieldText = T4
        T4.setMaximumSize(Dimension(500,20))
        panel.add(L4)
        panel.add(Box.createRigidArea(Dimension(0,5)))
        panel.add(T4)
        panel.add(Box.createRigidArea(Dimension(0,10)))

        L5 = JLabel("Arg 2 Swap Value")
        T5 = JTextField()
        self.__arg2ValueText = T5
        T5.setMaximumSize(Dimension(500,20))
        panel.add(L5)
        panel.add(Box.createRigidArea(Dimension(0,5)))
        panel.add(T5)
        panel.add(Box.createRigidArea(Dimension(0,10)))

        L6 = JLabel("Swap Argument 3")
        T6 = JTextField()
        self.__arg3FieldText = T6
        T6.setMaximumSize(Dimension(500,20))
        panel.add(L6)
        panel.add(Box.createRigidArea(Dimension(0,5)))
        panel.add(T6)
        panel.add(Box.createRigidArea(Dimension(0,10)))

        L7 = JLabel("Arg 3 Swap Value")
        T7 = JTextField()
        self.__arg3ValueText = T7
        T7.setMaximumSize(Dimension(500,20))
        panel.add(L7)
        panel.add(Box.createRigidArea(Dimension(0,5)))
        panel.add(T7)
        panel.add(Box.createRigidArea(Dimension(0,10)))

        L8 = JLabel("Output Folder Path")
        T8 = JTextField()
        self.__pathText = T8
        T8.setMaximumSize(Dimension(500,20))
        panel.add(L8)
        panel.add(Box.createRigidArea(Dimension(0,5)))
        panel.add(T8)
        panel.add(Box.createRigidArea(Dimension(0,10)))

        return panel


