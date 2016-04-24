#!/usr/bin/python
# -*- coding: utf-8 -*-

from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IBurpExtenderCallbacks
from burp import IHttpRequestResponse
from burp import IHttpListener
from burp import IProxyListener


from javax.swing import JFrame
from javax.swing import JProgressBar
from javax.swing import JButton
from javax.swing import JLabel
from javax.swing import JPanel
from javax.swing import JCheckBox
from javax.swing import JTable
from javax.swing import JSplitPane
from javax.swing import JScrollPane
from javax.swing import JTabbedPane
from javax.swing import JMenuItem
from javax.swing import JList
from javax.swing import JOptionPane
from javax.swing.tree import DefaultMutableTreeNode
from javax.swing.table import DefaultTableModel
from javax.swing import JTextField
from java.awt import BorderLayout
from java.awt import Dimension
from javax.swing import JTextArea
from java.awt import Color
from java.lang import *



import subprocess
import socket
import os
import re
import struct
import threading
import time
import sys
import json
import base64
import urlparse
import urllib2
import httplib
import urllib





#全局变量设定
HOSTDOMAIN = ""
NMAPPATH = "/usr/local/bin/nmap"  #Linux下要修改为/usr/bin/nmap
BINGKEY = ""                      #这里换成注册的BING KEY，不然的话二级域名查询没法用
REQUEST = ""
socket.setdefaulttimeout(3) 
#Home路径
HOMEPATH = ""                     #这里修改成插件所在的绝对路径

os.chdir(HOMEPATH)



class BurpExtender(IBurpExtender, IHttpListener, IContextMenuFactory, IProxyListener, IHttpRequestResponse, IBurpExtenderCallbacks):

    def registerExtenderCallbacks(self, callbacks):

        #右键触发扫描
        self._actionName = "Send to Spy"
        self._helers = callbacks.getHelpers()
        self._callbacks = callbacks
        #插件名字
        callbacks.setExtensionName("s1riu5TheMagician")

        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerProxyListener(self)

        return



    def quoteJTab(self, invocation):
        invMessage=invocation.getSelectedMessages()

        global REQUEST
        REQUEST = invMessage[0].getRequest().tostring()
        

        global HOSTDOMAIN
        
        HOSTDOMAIN =re.findall(r"Host: (.+?)\r\n", REQUEST)[0]


        
        
        JTabbedPaneClass()
        return  

    #创建菜单右键
    def createMenuItems(self, invocation):
        menu = []
        responses = invocation.getSelectedMessages()
        if len(responses) == 1:
            menu.append(JMenuItem(self._actionName, None, actionPerformed=lambda x, inv=invocation: self.quoteJTab(inv)))
            return menu
        return None
    


class JTabbedPaneClass:


    #判断域名返回IP地址
    def getIp(self, domain):
        domain = domain.split(":")[0]
        ipExpression = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        domainExpression = re.compile("^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$")
        if ipExpression.match(domain):
            return domain
        elif domainExpression.match(domain):
            myAddr = socket.getaddrinfo(domain,'http')[0][4][0]
            return myAddr
        
        else:
            return "domain error"


    #提取域名或IP信息
    def getDomain1(self, theDomain):
        domain1 = theDomain.split(":")[0]

        return domain1



    def __init__(self):
        

        frame = JFrame("S1riu5 Spy")
        frame.setSize(700, 690)
        frame.setLocationRelativeTo(None);
        frame.setLayout(BorderLayout())

        tabPane = JTabbedPane(JTabbedPane.TOP)

        #第一个Tab用来做C段查询

        eachIp = self.getIp(HOSTDOMAIN)

        iList = eachIp.split(".")

        theIP = iList[0] + "." + iList[1] + "." + iList[2] + ".1/24"  

        panel1 = JPanel()
        label = JLabel("IP CIDR:")
        self.textfield1 = JTextField(theIP, 15)
        button = JButton("SCAN", actionPerformed = self.cNmapScan)
        self.textArea = JTextArea(40, 65)
        self.textArea.append("IP: " + eachIp)
        self.textArea.setLineWrap(True)                  #激活自动换行功能 
        self.textArea.setWrapStyleWord(True);            # 激活断行不断字功能
                   
        panel1.add(label)
        panel1.add(self.textfield1)
        panel1.add(button)
        panel1.add(JScrollPane(self.textArea))            #设置自动滚动条
        tabPane.addTab("C segment query ", panel1)
        



        #第二个Tab用来做子域名查询



        theName = self.getDomain1(HOSTDOMAIN)

        self.textArea2 = JTextArea(40, 65)
        #self.textArea.append("IP: " + eachIp)
        self.textArea2.setLineWrap(True)                  #激活自动换行功能 
        self.textArea2.setWrapStyleWord(True)           # 激活断行不断字功能
                   


        label2 = JLabel("Domain: ")
        self.textfield2 = JTextField(theName, 15)
        button2 = JButton("SCAN", actionPerformed = self.subDomain)
        self.panel2 = JPanel()
        self.panel2.add(label2)
        self.panel2.add(self.textfield2)
        self.panel2.add(button2)
        #self.panel2.add(scrollPane)
        self.panel2.add(JScrollPane(self.textArea2))
        tabPane.addTab("subDomains", self.panel2)


        #第三个Tab用来做敏感文件扫描

        self.tableData0 = [["1", "2"]]
        colNames2 = ('url','http code')
        dataModel3 = DefaultTableModel(self.tableData0, colNames2)
        self.table3 = JTable(dataModel3)
##
 
        label3 = JLabel("URL: ")
        self.textfield3 = JTextField(HOSTDOMAIN, 15)
        self.textArea3 = JTextArea(40, 65)
        #self.textArea.append("IP: " + eachIp)
        self.textArea3.setLineWrap(True)                  #激活自动换行功能 
        self.textArea3.setWrapStyleWord(True)          # 激活断行不断字功能
        a = 0
        b = 0 
        self.label4 = JLabel(str(a) + "/" + str(b))
#
        self.chkbox1 = JCheckBox('ASP')
        self.chkbox2 = JCheckBox('ASPX')
        self.chkbox3 = JCheckBox('JSP')
        self.chkbox4 = JCheckBox('PHP')
        self.chkbox5 = JCheckBox('MDB')
        self.chkbox6 = JCheckBox('DIR')
        button3 = JButton("SCAN", actionPerformed = self.senFileScan)
        panel3 = JPanel()

        panel3.add(label3)
        panel3.add(self.textfield3)
        panel3.add(self.chkbox1)
        panel3.add(self.chkbox2)
        panel3.add(self.chkbox3)
        panel3.add(self.chkbox4)
        panel3.add(self.chkbox5)
        panel3.add(self.chkbox6)
        panel3.add(button3)
        panel3.add(self.label4)
        panel3.add(JScrollPane(self.textArea3))


#
        tabPane.addTab("Sebsitive File", panel3)
#
        frame.add(tabPane)
        frame.setVisible(True)
    #用来在第一个TAB打印nmap信息  
    def setResult(self,text):
        self.textArea.append(text)

    #用来在第二个TAB打印获得信息
    def setResult2(self,textId, textDomain, textIp):
        text = str(textId) + "----------------" + textDomain + "----------------" + str(textIp) + os.linesep
        self.textArea2.append(text)
        #self.textArea2.append("----------------------------------------" + os.linesep)

    #用来在第三个TAB打印文件扫描的结果
    def setResult3(self, theMess01):

    	self.textArea3.append(theMess01)


    def setLabel(self, a, b):
    	hg = str(a) + "/" + str(b)
    	self.label4.setText(hg)


    #C段扫描的主引擎
    def cNmapScan(self, event):

        self.textArea.setText("")
            #-------------------------------------------------------------------------------
        def ipRange(ipaddr):
            """
            Creates a generator that iterates through all of the IP addresses.
            The range can be specified in multiple formats.
        
                "192.168.1.0-192.168.1.255"    : beginning-end
                "192.168.1.0/24"               : CIDR
                "192.168.1.*"                  : wildcard
            
        
            """
            def ipaddr_to_binary(ipaddr):
                """
                A useful routine to convert a ipaddr string into a 32 bit long integer
                """
                # from Greg Jorgensens python mailing list message 
                q = ipaddr.split('.')
                return reduce(lambda a,b: long(a)*256 + long(b), q)
               
            #-------------------------------------------------------------------------------
            def binary_to_ipaddr(ipbinary):
                """
                Convert a 32-bit long integer into an ipaddr dotted-quad string
                """
                # This one is from Rikard Bosnjakovic
                return socket.inet_ntoa(struct.pack('!I', ipbinary))
            
            def ipaddr_to_binary(ipaddr):
                """
                A useful routine to convert a ipaddr string into a 32 bit long integer
                """
                # from Greg Jorgensens python mailing list message 
                q = ipaddr.split('.')
                return reduce(lambda a,b: long(a)*256 + long(b), q)
           
            #-------------------------------------------------------------------------------
            def binary_to_ipaddr(ipbinary):
                """
                Convert a 32-bit long integer into an ipaddr dotted-quad string
                """
                # This one is from Rikard Bosnjakovic
                return socket.inet_ntoa(struct.pack('!I', ipbinary))
            
            #-------------------------------------------------------------------------------
            def cidr_iprange(ipaddr, cidrmask):
                """
                Creates a generator that iterated through all of the IP addresses
                in a range given in CIDR notation
                """
                # Get all the binary one's
                mask = (long(2)**long(32-long(cidrmask))) - 1
            
                b = ipaddr_to_binary(ipaddr) 
                e = ipaddr_to_binary(ipaddr) 
                b = long(b & ~mask)
                e = long(e | mask)
            
                while (b <= e):
                    yield binary_to_ipaddr(b)
                    b = b + 1
         
            #-------------------------------------------------------------------------------
            def wildcard_iprange(ipaddr):
                """
                Creates a generator that iterates through all of the IP address
                in a range given with wild card notation
                """
                beginning = [] 
                end = [] 
                
                tmp = ipaddr.split('.')
                for i in tmp:
                    if i == '*':
                        beginning.append("0")
                        end.append("255") 
                    else:
                        beginning.append(i)
                        end.append(i) 
            
                b = beginning[:]
                e = end[:]
                
                while int(b[0]) <= int(e[0]):
                    while int(b[1]) <= int(e[1]):
                        while int(b[2]) <= int(e[2]):
                            while int(b[3]) <= int(e[3]):
                                yield b[0] + '.' + b[1] + '.' + b[2] + '.' + b[3]
                                b[3] = "%d" % (int(b[3]) + 1)
            
                            b[2] = "%d" % (int(b[2]) + 1)
                            b[3] = beginning[3]
            
                        b[1] = "%d" % (int(b[1]) + 1)
                        b[2] = beginning[2]
            
                    b[0] = "%d" % (int(b[0]) + 1)
                    b[1] = beginning[1]       
            
            # Did we get the IP address in the span format? 
            span_re = re.compile(r'''(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})   # The beginning IP Address
                                     \s*-\s*
                                     (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})   # The end IP Address
                                  ''', re.VERBOSE)
        
            res = span_re.match(ipaddr)
            if res:
                beginning = res.group(1)
                end = res.group(2)
                return span_iprange(beginning, end)
                                         
            # Did we get the IP address in the CIDR format? 
            cidr_re = re.compile(r'''(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})   # The IP Address
                                     /(\d{1,2})                             # The mask
                                  ''', re.VERBOSE)
        
            res = cidr_re.match(ipaddr)
            if res:
                addr = res.group(1)
                cidrmask = res.group(2)
                return cidr_iprange(addr, cidrmask)
        
            # Did we get the IP address in the wildcard format? 
            wild_re = re.compile(r'''(\d{1,3}|\*)\.
                                     (\d{1,3}|\*)\.
                                     (\d{1,3}|\*)\.
                                     (\d{1,3}|\*)   # The IP Address
                                  ''', re.VERBOSE)
        
            res = wild_re.match(ipaddr)
            if res:
                return wildcard_iprange(ipaddr)
            return "The ip address given to ipaddr is improperly formatted"


        ipCidr = self.textfield1.getText()

        domainExpression = re.compile("^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$")

        if domainExpression.match(ipCidr):
            JOptionPane.showMessageDialog(None, "You must enter IP", "s1riu5", JOptionPane.INFORMATION_MESSAGE)
        

        else:
            ipList = list(ipRange(ipCidr))
            print len(ipList)
            if len(ipList) == 256:
                del ipList[0]
                del ipList[254]
    
            global NMAPPATH

            scan=ScanList(ipList, self, [NMAPPATH,"-Pn", "-sT", "-sV", "--open"])
            scan.start()

    
  

    def subDomain(self, event):
    	print self.textfield2.getText()
        b = subDomainThread(self.textfield2.getText(), self)
        b.start()

        


    def senFileScan(self, event):
        #print "Hello"

        urlListASP = ["/admin.asp"]
        urlListASPX = ["/admin.aspx"]
        urlListJSP = ["/admin.jsp"]
        urlListPHP = ["/admin.php"]
        urlListMDB = ["/admin.mdb"]
        urlListDIR = ["/admin/"]
        

        if self.chkbox1.isSelected():
            
            domainTextObj1 = open("path/ASP.txt", "r")
            for each1 in domainTextObj1.readlines():
                each1 = each1.strip()
                urlListASP.append(each1)
            domainTextObj1.close()

        if self.chkbox2.isSelected():
            domainTextObj2 = open("path/ASPX.txt", "r")
            for each2 in domainTextObj2.readlines():
                each2 = each2.strip()
                urlListASPX.append(each2)
            domainTextObj2.close()
            
        if self.chkbox3.isSelected():
            domainTextObj3 = open("path/JSP.txt", "r")
            for each3 in domainTextObj3.readlines():
                each3 = each3.strip()
                urlListJSP.append(each3)
            domainTextObj3.close()
        if self.chkbox4.isSelected():
            domainTextObj4 = open("path/PHP.txt", "r")
            for each4 in domainTextObj4.readlines():
                each4 = each4.strip()
                urlListPHP.append(each4)
            domainTextObj4.close()
        if self.chkbox5.isSelected():
            domainTextObj5 = open("path/MDB.txt", "r")
            for each5 in domainTextObj5.readlines():
                each5 = each5.strip()
                urlListMDB.append(each5)
            domainTextObj5.close()
        if self.chkbox6.isSelected():
            domainTextObj6 = open("path/DIR.txt", "r")
            for each6 in domainTextObj6.readlines():
                each6 = each6.strip()
                urlListDIR.append(each6)
            domainTextObj6.close()

        app = []
        app = urlListASP + urlListASPX + urlListJSP + urlListPHP + urlListMDB + urlListDIR
        app1 = list(set(app))
        

        theUrlText = self.textfield3.getText()

        


        #if str(theUrlText[0 : 7]) == "http://":
         #   theUrlText = "http://" + theUrlText
        

        print len(app1)
        print len(app)


        #fileObj1 = eachFileScan(theUrlText, app)
        #fileObj1.start()
        ab = numControl(theUrlText, app1, self)
        ab.start()



        


class NmapScan(threading.Thread):
    def __init__(self):  
        threading.Thread.__init__(self)  
        self.thread_stop = False
        
    def setCommds(self,cmds,Jobject,pcontrol):
        self.runcms=cmds
        self.setobject=Jobject
        self.pcontrol=pcontrol
      
        
    def run(self):
        
        #self.setobject.setResult('Nmap task for '+self.runcms[5]+' is running\n')
        child1 = subprocess.Popen(self.runcms,  stdout = subprocess.PIPE, stdin = subprocess.PIPE, shell = False)
        child1.poll()
        resultScan = child1.stdout.read()
        self.setobject.setResult(resultScan)
 
        #self.setobject.setResult('Nmap task for '+self.runcms[5]+' is finnished\n')
        self.pcontrol.subnum()
        self.stop()
    def stop(self):  
        self.thread_stop = True


        
class ScanList(threading.Thread):
    def __init__(self,nlist,Jobject,cmds):
        threading.Thread.__init__(self)         #初始化自身
        self.thread_stop=False                  #初始化自身
        self.slist=nlist                        #运行扫描的任务列表
        
    


        self.left=len(self.slist)               #剩余的运行任务
        self.trueleft=len(self.slist)           #任务真正的剩余量
        self.runnum=0                           #正在运行的任务
        self.jdialog=Jobject                    #传递的消息队列
        self.commond=cmds                       #执行的任务
        self.prenum=0                           #准备执行的任务
        self.stanum=-1                          #正在运行的记录数
        self.tmpnum=0                           #临时记录
        
        
    def subnum(self):
        self.runnum-=1
        #self.trueleft-=1
        
        
    def run(self):
        while True:
            if self.runnum<4 and self.left>0:
                self.tmpcmd=self.commond
               
                self.tmpcmd.append(self.slist[self.stanum+1])
                
                global NMAPPATH
                self.ntask=NmapScan()
                self.ntask.setCommds([NMAPPATH,"-Pn", "-sT", "-sV", "--open",self.slist[self.stanum+1]],self.jdialog,self)
                self.ntask.start()
                self.runnum+=1                     #指定运行的运行数
                self.left-=1                       #减少剩余量，一定要在这记录，不然会超出线程控制
                self.stanum+=1;                    #记录运行的位置
                self.trueleft-=1
                    
            if self.trueleft==0:
                break
        
    
            time.sleep(2)       
        #print "Hello"  
                    
                    
    def stop(self):  
        self.thread_stop = True    


class subDomainThread(threading.Thread):
    def __init__(self, theMess, theObject):
        threading.Thread.__init__(self)
        self.domainMess = theMess
        self.setObject2 = theObject



    def run(self):

        ipExpression = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.+?')

        if ipExpression.match(self.domainMess):
            JOptionPane.showMessageDialog(None, "You must enter Domain name", "s1riu5", JOptionPane.INFORMATION_MESSAGE)
        else:

            #该函数用来提取顶级域名
            def getTheDomain(s):
                res = s
                domainS = [".com", ".cn", ".com.cn", ".gov", ".net", ".edu.cn", ".net.cn", ".org.cn", ".co.jp", ".gov.cn",".co.uk", "ac.cn", ".edu", ".tv",".info", ".ac", ".ag", ".am", ".at", ".be", ".biz", ".bz",".cc", ".de", ".es", ".eu", ".fm", ".gs", ".hk", ".in", ".info", ".io", ".it", ".jp", ".la",".md", ".ms", ".name", ".nl", ".nu", ".org", ".pl", ".ru", ".sc", ".se", ".sg", ".sh", ".tc",".tk", ".tv", ".tw", ".us", ".co",".uk", ".vc", ".vg", ".ws", ".il", ".li", ".nz"]
                for l in domainS:
                    regex = re.compile(r'[0-9a-zA-Z_\-]+'+l+'$')
                    m = regex.findall(s)
                    if len(m) > 0:
                        return m[0]
                    else:
                        pass
                return res

            theTopDomain = getTheDomain(self.domainMess)
   

#本来是用来字典爆破二级域名的，暂时放弃
#            domainTextObj = open("domain/subnames.txt", "r")
#            domainList = []
#            for each in domainTextObj.readlines():
#                each  = each.strip()
#                domainList.append(each)
#            
#            domainTextObj.close()
#
#            fullDomain = []
#            for i in domainList:
#                 mid = i + "." + theTopDomain
#                 fullDomain.append(mid)

            global BINGKEY

            top=100
            skip=0
            format='json'
            
            def BingSearch(query):
                payload={}
                payload['$top']=top
                payload['$skip']=skip
                payload['$format']=format
                payload['Query']="'"+query+"'"
                url='https://api.datamarket.azure.com/Bing/Search/Web?' + urllib.urlencode(payload)
                sAuth='Basic '+base64.b64encode(':'+BINGKEY)
            
                headers = { }
                headers['Authorization']= sAuth
                try:
                    req = urllib2.Request(url,headers=headers)
                    response = urllib2.urlopen(req)
                    data=response.read()
                    #print data
                    data=json.loads(data)
            
                    return data
                except Exception as e:
                    print e
                    #print e.info()
            
            urlList = []
            returnData = BingSearch("domain:" + theTopDomain)
            if not returnData['d']['results']:
                print "The Url Error"
            else:
                for tarUrl in returnData["d"]["results"]:
                    tmpUrl = urlparse.urlparse(tarUrl["Url"]).netloc
                    if tmpUrl not in urlList:
                        urlList.append(tmpUrl)

            
            #self.matrix = [None] * len(urlList)
            #for i in range(len(self.matrix)):
            #    self.matrix[i] = []*3
            #
            #j = 0
            #
            #for h in urlList:
            #
            #    self.matrix[j].append(j)
            #    self.matrix[j].append(h)
            #    self.matrix[j].append(self.getIp(h))
            #    j = j+1
            j = 0
            print j 
            print urlList
            for h in urlList:
                theSecIp = self.setObject2.getIp(h)
                print h
                self.setObject2.setResult2(j, h, theSecIp)
                j = j + 1




#敏感文件扫描的两大类

#做扫描的类
class fileScan(threading.Thread):
    def __init__(self, theHost, theUrl, thePar, theAgain):
        threading.Thread.__init__(self)
        self.thread_stop = False

    #def argsInit(self, theHost, theList):
        self.hostUrl = theHost
        self.eachUrl = theUrl
        self.parMain = thePar

        self.luoAgain = theAgain

    def requestDict(self):

        reqDict = {}
        global REQUEST

        f = REQUEST.split("\n")
        for line in f:
            listedline = line.strip().split(': ')
            if len(listedline) > 1:
                reqDict[listedline[0]] = listedline[1]
        #print reqDict
        del reqDict["Host"]
        return reqDict


    def run(self):
        #self.parMain.subnum()
        
        self.theDict = self.requestDict()
        


        try:
            connection = httplib.HTTPConnection(self.hostUrl)
            connection.request("GET", self.eachUrl, "", self.theDict)
            time.sleep(0.1)
            response = connection.getresponse()

            if response.status == 200 or response.status == 302 or response.status == 301:
                theDisMess = "http://" + self.hostUrl+self.eachUrl + "----------" + str(response.status) + os.linesep
                #print theDisMess
                self.luoAgain.setResult3(theDisMess)
            if connection:
                connection.close()
        except :
            if connection:
                connection.close()
            pass
        finally:
            if connection:
                connection.close()
        self.parMain.subnum()
        
    def stop(self):
        self.thread_stop = True

#该类主要用来控制线程数
class numControl(threading.Thread):
    def __init__(self, dUrl, thelist, theRoom):
        threading.Thread.__init__(self)         #初始化自身
        self.thread_stop=False
        self.domainUrl = dUrl

        self.paList = thelist
        self.theObj = theRoom
        self.theObj.textArea3.setText("")



        #计数器
        self.left = len(self.paList)         #一共的任务数
        self.runngingNum = 0                   #正在运行的任务数
        self.startNum = -1                     #列表索引
        self.allList = len(self.paList) - 1 


    def subnum(self):
        self.runngingNum -= 1
        #self.trueLeft -= 1

    def run(self):


        while True:

            if self.runngingNum < 20 and self.left > 0:


                self.domainUri = self.domainUrl

                self.initScan = fileScan(self.domainUri, self.paList[self.startNum+1], self, self.theObj)

                self.initScan.start()

                self.runngingNum +=1                    #指定运行的运行数
                self.left-=1                       #减少剩余量，一定要在这记录，不然会超出线程控制
                self.startNum+=1                    #记录运行的位置

                self.theObj.setLabel(self.startNum, self.allList)
#
                #print str(self.runngingNum) + " :runngingNum"
                #print str(self.left) + " :left"
                #print str(self.startNum) + " :startNum"

            if self.left==0:
               #print "stop"
               break
            #time.sleep(2)


    def stop(self):
        self.thread_stop = True


