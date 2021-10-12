"""
      __  ___  __   __   ___  __
 /\  |__)  |  /__` /__` |__  /  `
/~~\ |  \  |  .__/ .__/ |___ \__,

Security without imagination is a vulnerability.

Author: ArtsSEC
Site: https://artssec.com

Title: Burp Suite exporter extension
About: Exporter is a Burp Suite extension to copy a request to a file or the clipboard as multiple programming languages functions.

Version: 1.0

Changelog:

  1.0: Added a tab called Exporter, where you can search and filter URLs, also export from there to a file or copy to the clipboard.

  0.5: Added more snippets.

  0.2: Add python-readable exceptions. Thanks @securityMB

  0.1: First public version

"""

from burp import IBurpExtender, IContextMenuFactory, ITab
from burp import IMessageEditorController
from burp import IHttpListener
from java.awt.event import ActionListener
from java.io import PrintWriter
from java.util import ArrayList
from javax.swing.event import ChangeListener
from javax.swing import JScrollPane
from javax.swing import JSplitPane
from javax.swing import JTabbedPane
from javax.swing import JTable
from javax.swing import JButton
from javax.swing import JTextArea
from javax.swing import JTextField
from javax.swing import JLabel
from javax.swing import JComboBox
from javax.swing.table import AbstractTableModel
from threading import Lock
from javax.swing import JMenuItem, JMenu, JFileChooser, JPanel
from java.awt.datatransfer import StringSelection
from java.lang import UnsupportedOperationException
from java.awt import Toolkit
from java.awt import Color
import json

# python-readable exceptions
# Original code: https://raw.githubusercontent.com/securityMB/burp-exceptions/master/exceptions_fix.py
# Burp Exceptions Fix magic code
import sys
import functools
import inspect
import traceback


def decorate_function(original_function):
    @functools.wraps(original_function)
    def decorated_function(*args, **kwargs):
        try:
            return original_function(*args, **kwargs)
        except Exception:
            sys.stdout.write('\n\n*** PYTHON EXCEPTION\n')
            traceback.print_exc(file=sys.stdout)
            raise
    return decorated_function


def FixBurpExceptionsForClass(cls):
    for name, method in inspect.getmembers(cls, inspect.ismethod):
        setattr(cls, name, decorate_function(method))
    return cls


def FixBurpExceptions():
    for name, cls in inspect.getmembers(sys.modules['__main__'], predicate=inspect.isclass):
        FixBurpExceptionsForClass(cls)


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, AbstractTableModel, IMessageEditorController, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):

        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Exporter")
        self._callbacks.registerContextMenuFactory(self)
        self.mainpanel = JPanel()
        self.mainpanel.setLayout(None)

        self._log = ArrayList()
        self._lock = Lock()

        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        toCopyPaneBtns = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        clipboardBtn = JButton("Exporter to clipboard", actionPerformed=self.snippetToClipboard)
        fileBtn = JButton("Exporter to file", actionPerformed=self.snippetToFile)
        clipboardBtn.setEnabled(False)
        fileBtn.setEnabled(False)
        self.clipboardBtn = clipboardBtn
        self.fileBtn = fileBtn
        toCopyPaneBtns.setRightComponent(clipboardBtn)
        toCopyPaneBtns.setLeftComponent(fileBtn)

        toCopyPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        snippetCode = JTextArea()
        self.snippetCode = snippetCode
        snippetCodeScrollable = JScrollPane(snippetCode)
        toCopyPane.setRightComponent(toCopyPaneBtns)
        toCopyPane.setLeftComponent(snippetCodeScrollable)

        toCopyPaneCombo = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        snippetLanCombo = JComboBox()
        snippetLanCombo.addItem(self.ComboboxItem('0', 'Code snippets'))
        snippetLanCombo.addItem(self.ComboboxItem('1', 'cURL'))
        snippetLanCombo.addItem(self.ComboboxItem('2', 'Wget'))
        snippetLanCombo.addItem(self.ComboboxItem('3', 'Python Request'))
        snippetLanCombo.addItem(self.ComboboxItem('4', 'Perl LWP'))
        snippetLanCombo.addItem(self.ComboboxItem('5', 'PHP HTTP_Request2'))
        snippetLanCombo.addItem(self.ComboboxItem('6', 'GO Native'))
        snippetLanCombo.addItem(self.ComboboxItem('7', 'NodeJS Request'))
        snippetLanCombo.addItem(self.ComboboxItem('8', 'jQuery AJAX'))
        snippetLanCombo.addItem(self.ComboboxItem('9', 'PowerShell'))
        snippetLanCombo.addItem(self.ComboboxItem('10', 'HTML Forms'))
        snippetLanCombo.addItem(self.ComboboxItem('11', 'Ruby Net::HTTP'))
        snippetLanCombo.addItem(self.ComboboxItem('12', 'Javascript XHR'))
        snippetLanCombo.addActionListener(self.ComboboxListener(self, "snippet"))
        snippetLanCombo.setEnabled(False)
        self.snippetLanCombo = snippetLanCombo
        toCopyPaneCombo.setRightComponent(toCopyPane)
        toCopyPaneCombo.setLeftComponent(snippetLanCombo)
        toCopyPane.setResizeWeight(0.99)

        search = JLabel('Filter:')
        text = JTextField()
        self.filterText = text
        self.filterText.addActionListener(self.FilterTextListener(self, "enter"))
        searchText = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        searchText.setLeftComponent(search)
        searchText.setRightComponent(text)
        searchButtons = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        searchBtn = JButton("Search!", actionPerformed=self.searchLogs)
        resetBtn = JButton("Reset", actionPerformed=self.resetSearchLogs)
        searchButtons.setRightComponent(resetBtn)
        searchButtons.setLeftComponent(searchBtn)
        searchButtons.setResizeWeight(0.5)

        searchPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        searchPane.setLeftComponent(searchText)
        searchPane.setRightComponent(searchButtons)
        searchPane.setResizeWeight(0.9)

        logTable = Table(self)
        logTablePane = JScrollPane(logTable)
        logTableSearch = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        logTableSearch.setLeftComponent(searchPane)
        logTableSearch.setRightComponent(logTablePane)
        scrollPane = JScrollPane(logTableSearch)
        self.logTable = logTable
        splitpaneMain = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        splitpaneMain.setLeftComponent(scrollPane)
        splitpaneMain.setRightComponent(toCopyPaneCombo)
        splitpaneMain.setResizeWeight(0.5)

        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())

        self._splitpane.setLeftComponent(splitpaneMain)
        self._splitpane.setRightComponent(tabs)
        self._splitpane.setResizeWeight(0.7)

        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)

        callbacks.addSuiteTab(self)

        return

    def filterResults(self, text):
        if text == None:  # noqa
            self._log = self._partialLog if len(self._partialLog) > 0 else self._log
        else:
            self._partialLog = self._log.clone()

            self._lock.acquire()
            self._log.clear()
            self._lock.release()

            for log in self._partialLog:
                if text in log._requestResponse.request.tostring().decode('utf-8', 'replace'):
                    self._lock.acquire()
                    row = self._log.size()
                    self._log.add(log)
                    self.fireTableRowsInserted(row, row)
                    self._lock.release()
        self.logTable.updateUI()

    def searchLogs(self, event):
        text = self.filterText.getText()
        self.filterResults(text)

    def resetSearchLogs(self, event):
        self.filterResults(None)
        self.filterText.setText('')

    def snippetToClipboard(self, event):
        to_copy = self.snippetCode.getText()
        self.saveToClipboard(to_copy)

    def snippetToFile(self, event):
        to_copy = self.snippetCode.getText()
        self.saveToFile(to_copy)

    class ComboboxItem:

        def __init__(self, key, val):
            self._key = key
            self._val = val

        def get_key(self):
            return self._key

        # Set label inside ComboBox
        def __repr__(self):
            return self._val

    class TabListener(ChangeListener):

        def __init__(self, extender, name):
            self.extender = extender
            self.name = name

        def stateChanged(self, action_event):
            try:
                self.extender.setFocus(False)
            except Exception:
                pass

    class FilterTextListener(ActionListener):

        def __init__(self, extender, name):
            self.extender = extender
            self.name = name

        def actionPerformed(self, action_event):
            self.extender.searchLogs(action_event)

    class ComboboxListener(ActionListener):

        def __init__(self, extender, name):
            self.extender = extender
            self.name = name

        def possibleActions(self, code):
            actions = {
                '1': self.extender.asCURL,
                '2': self.extender.asWget,
                '3': self.extender.asPythonRequest,
                '4': self.extender.asPerl,
                '5': self.extender.asPHPRequest,
                '6': self.extender.asGO,
                '7': self.extender.asNodeJSRequest,
                '8': self.extender.asJQueryAjax,
                '9': self.extender.asPowerShell,
                '10': self.extender.asHTMLForm,
                '11': self.extender.asRuby,
                '12': self.extender.asXHR
            }

            return actions.get(code)

        def clearSnippetCode(self):
            self.extender.snippetCode.setText('')
            self.extender.clipboardBtn.setEnabled(False)
            self.extender.fileBtn.setEnabled(False)

        def actionPerformed(self, action_event):
            selected = self.extender.snippetLanCombo.getSelectedItem().get_key()
            self.extender.clipboardBtn.setEnabled(True)
            self.extender.fileBtn.setEnabled(True)
            snippet = self.possibleActions(selected)
            if snippet:
                self.extender.snippetCode.setText(snippet('n/a'))
            else:
                self.clearSnippetCode()

    def getTabCaption(self):
        return "Exporter"

    def getUiComponent(self):
        return self._splitpane

    def getRowCount(self):
        try:
            return self._log.size()
        except Exception:
            return 0

    def getColumnCount(self):
        return 4

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "#"
        if columnIndex == 1:
            return "URL"
        if columnIndex == 2:
            return "Method"
        if columnIndex == 3:
            return "Status"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return rowIndex
        if columnIndex == 1:
            return logEntry._url.toString()
        if columnIndex == 2:
            return str(logEntry._method)
        if columnIndex == 3:
            return str(logEntry._status)
        return ""

    def setFocus(self, enabled):
        '''
            :param Boolean enabled: True if focus else False
        '''
        pane = self.getUiComponent().getParent()
        if enabled:
            color = Color.decode('0xff6633')
            pane.addChangeListener(self.TabListener(self, "tab"))
        else:
            color = Color.BLACK
            pane.removeChangeListener(pane.getChangeListeners()[0])
        exporter_pane_idx = [i for i in range(0, pane.getTabCount()) if pane.getTitleAt(i) == self.getTabCaption()]
        exporter_pane_idx = exporter_pane_idx[0] if exporter_pane_idx else None
        pane.setBackgroundAt(exporter_pane_idx, color)

    def sendToExporter(self, event):
        self.setFocus(True)
        if self._context.getSelectedMessages()[0].getRequest():
            messageInfo = self._context.getSelectedMessages()[0]
            self._lock.acquire()
            row = self._log.size()
            self._log.add(LogEntry(1, self._callbacks.saveBuffersToTempFiles(messageInfo), self._helpers.analyzeRequest(messageInfo).getUrl(), self._helpers.analyzeRequest(messageInfo).method, messageInfo.getStatusCode()))
            self.fireTableRowsInserted(row, row)
            self._lock.release()
        return

    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

    def createMenuItems(self, invocation):
        self._context = invocation
        menuList = ArrayList()

        invocation_allowed = [invocation.CONTEXT_MESSAGE_EDITOR_REQUEST, invocation.CONTEXT_PROXY_HISTORY,
                              invocation.CONTEXT_TARGET_SITE_MAP_TABLE, invocation.CONTEXT_TARGET_SITE_MAP_TREE,
                              invocation.CONTEXT_MESSAGE_VIEWER_REQUEST, invocation.CONTEXT_INTRUDER_ATTACK_RESULTS, 
                              invocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS, invocation.CONTEXT_SCANNER_RESULTS, 
                              invocation.CONTEXT_SEARCH_RESULTS]

        if self._context.getInvocationContext() in invocation_allowed and len(self._context.selectedMessages) == 1:
            parentMenu = JMenu('Exporter to')

            menuItemClipboard = JMenu("To clipboard")
            menuItemFile = JMenu("To file")

            menuItemPythonRequest = JMenuItem("Python Request", actionPerformed=self.asPythonRequest, actionCommand="file")
            menuItemCURL = JMenuItem("cURL", actionPerformed=self.asCURL, actionCommand="file")
            menuItemWget = JMenuItem("Wget", actionPerformed=self.asWget, actionCommand="file")
            menuItemPhpRequest = JMenuItem("PHP HTTP_Request2", actionPerformed=self.asPHPRequest, actionCommand="file")
            menuItemGo = JMenuItem("GO Native", actionPerformed=self.asGO, actionCommand="file")
            menuItemNodeRequest = JMenuItem("NodeJS Request", actionPerformed=self.asNodeJSRequest, actionCommand="file")
            menuItemJQueryAjax = JMenuItem("jQuery AJAX", actionPerformed=self.asJQueryAjax, actionCommand="file")
            menuItemPowerShell = JMenuItem("PowerShell", actionPerformed=self.asPowerShell, actionCommand="file")
            menuItemPerl = JMenuItem("Perl LWP", actionPerformed=self.asPerl, actionCommand="file")
            menuItemHTML = JMenuItem("HTML Forms", actionPerformed=self.asHTMLForm, actionCommand="file")
            menuItemRuby = JMenuItem("Ruby - Net::HTTP", actionPerformed=self.asRuby, actionCommand="file")
            menuItemXHR = JMenuItem("Javascript - XHR", actionPerformed=self.asXHR, actionCommand="file")

            parentMenu.add(menuItemFile)
            parentMenu.add(menuItemClipboard)

            menuItemFile.add(menuItemCURL)
            menuItemFile.add(menuItemWget)
            menuItemFile.add(menuItemPythonRequest)
            menuItemFile.add(menuItemPerl)
            menuItemFile.add(menuItemPhpRequest)
            menuItemFile.add(menuItemGo)
            menuItemFile.add(menuItemNodeRequest)
            menuItemFile.add(menuItemJQueryAjax)
            menuItemFile.add(menuItemPowerShell)
            menuItemFile.add(menuItemHTML)
            menuItemFile.add(menuItemRuby)
            menuItemFile.add(menuItemXHR)

            menuItemPythonRequest = JMenuItem("Python Request", actionPerformed=self.asPythonRequest, actionCommand="clipboard")
            menuItemCURL = JMenuItem("cURL", actionPerformed=self.asCURL, actionCommand="clipboard")
            menuItemWget = JMenuItem("Wget", actionPerformed=self.asWget, actionCommand="clipboard")
            menuItemPhpRequest = JMenuItem("PHP HTTP_Request2", actionPerformed=self.asPHPRequest, actionCommand="clipboard")
            menuItemGo = JMenuItem("GO Native", actionPerformed=self.asGO, actionCommand="clipboard")
            menuItemNodeRequest = JMenuItem("NodeJS Request", actionPerformed=self.asNodeJSRequest, actionCommand="clipboard")
            menuItemJQueryAjax = JMenuItem("jQuery AJAX", actionPerformed=self.asJQueryAjax, actionCommand="clipboard")
            menuItemPowerShell = JMenuItem("PowerShell", actionPerformed=self.asPowerShell, actionCommand="clipboard")
            menuItemPerl = JMenuItem("Perl LWP", actionPerformed=self.asPerl, actionCommand="clipboard")
            menuItemHTML = JMenuItem("HTML Forms", actionPerformed=self.asHTMLForm, actionCommand="clipboard")
            menuItemRuby = JMenuItem("Ruby - Net::HTTP", actionPerformed=self.asRuby, actionCommand="clipboard")
            menuItemXHR= JMenuItem("Javascript - XHR", actionPerformed=self.asXHR, actionCommand="clipboard")

            menuItemClipboard.add(menuItemCURL)
            menuItemClipboard.add(menuItemWget)
            menuItemClipboard.add(menuItemPythonRequest)
            menuItemClipboard.add(menuItemPerl)
            menuItemClipboard.add(menuItemPhpRequest)
            menuItemClipboard.add(menuItemGo)
            menuItemClipboard.add(menuItemNodeRequest)
            menuItemClipboard.add(menuItemJQueryAjax)
            menuItemClipboard.add(menuItemPowerShell)
            menuItemClipboard.add(menuItemHTML)
            menuItemClipboard.add(menuItemRuby)
            menuItemClipboard.add(menuItemXHR)

            menuList.add(parentMenu)

            menuItemSendToExporter = JMenuItem("Send to Exporter", actionPerformed=self.sendToExporter)
            menuList.add(menuItemSendToExporter)

        # Request info
        iRequestInfo = self._helpers.analyzeRequest(self._context.getSelectedMessages()[0])
        self.setData(iRequestInfo)

        return menuList

    def setPayload(self, iRequestInfo):
        params_type = {
            0: 'url',
            1: 'body',
            2: 'cookie',
            3: 'xml',
            4: 'xml_attr',
            5: 'multipart_attr',
            6: 'json'
        }

        if self.contentType == iRequestInfo.CONTENT_TYPE_MULTIPART:
            params = {i.name: i.value for i in iRequestInfo.getParameters() if params_type[i.getType()] == "body"}
            self.payload = params
        elif self.contentType == iRequestInfo.CONTENT_TYPE_JSON:
            self.payload = str({str(i.name): str(i.value) for i in self.parameters})
        elif self.contentType == iRequestInfo.CONTENT_TYPE_XML:
            self.payload = "<?" + str(self._context.getSelectedMessages()[0].request.tostring().split("<?")[1])
        else:
            pass

    def setData(self, iRequestInfo):
        self.headers = iRequestInfo.getHeaders()
        self.parameters = iRequestInfo.getParameters()
        self.method = iRequestInfo.getMethod()
        self.contentType = iRequestInfo.getContentType()
        try:
            self.url = iRequestInfo.getUrl().toString()
        except UnsupportedOperationException:
            host = [i for i in self.headers if 'Host' in i][0].split(" ")[1]
            uri = [i for i in self.headers if self.method in i][0].split(' ')[1]
            self.url = host + uri
        self.url = 'http://' + self.url if '://' not in self.url else self.url
        self.setPayload(iRequestInfo)

    def headersDict(self):
        return dict(item.split(': ',1) for item in self.headers[1:])

    def asPythonRequest_multipart(self, headers):
        payload = self.payload
        payload_list = list(payload.items())
        payload.clear()
        headers.pop(u'Content-Type')
        for key, val in payload_list:
            new_key = '"{}"'.format(key)
            if len(val.split("\x00")) > 1:
                payload[new_key] = 'open("<yourAwesomeFileHere>", "rb")'
            else:
                new_val = '"{}"'.format(val)
                payload[new_key] = new_val
                to_copy = '''# -*- coding: UTF-8 -*-
                import requests
                requests.packages.urllib3.disable_warnings()
                url = "{url}"

payload = {payload}
headers = {headers}

response = requests.request("{method}", url, files=payload, headers=headers, verify=False)

print(response.text)'''.format(url=self.url, payload=payload, method=self.method, headers=json.dumps(headers, indent=4))  # noqa
        return to_copy.replace("'", "")

    def asPythonRequest_json(self, headers):
        payload = self.payload.replace("\n", "").replace("\t", "").replace('"', '\\"')
        to_copy = '''# -*- coding: UTF-8 -*-
import requests
requests.packages.urllib3.disable_warnings()

url = "{url}"

payload = '''"{payload}"'''
headers = {headers}

response = requests.request("{method}", url, data=payload, headers=headers, verify=False)

print(response.text)'''.format(url=self.url, payload=payload, method=self.method, headers=json.dumps(headers, indent=4))  # noqa

        return to_copy

    def asPythonRequest_none(self, headers):
        to_copy = '''# -*- coding: UTF-8 -*-
import requests
requests.packages.urllib3.disable_warnings()

url = "{url}"

headers = {headers}

response = requests.request("{method}", url, headers=headers, verify=False)

print(response.text)'''.format(url=self.url, method=self.method, headers=json.dumps(headers, indent=4))  # noqa

        return to_copy

    def asPythonRequest_xml(self, headers):
        payload = self.payload.replace("\n", "").replace("\t", "").replace('"', '\\"')
        to_copy = '''# -*- coding: UTF-8 -*-
import requests
requests.packages.urllib3.disable_warnings()

url = "{url}"

payload = "{payload}"
headers = {headers}

response = requests.request("{method}", url, data=payload, headers=headers, verify=False)

print(response.text)'''.format(url=self.url, payload=payload, method=self.method, headers=json.dumps(headers, indent=4))  # noqa

        return to_copy

    def asPythonRequest(self, event):
        if event == 'n/a':
            iRequestInfo = self._helpers.analyzeRequest(self._exporter)
            self.setData(iRequestInfo)
        else:
            iRequestInfo = self._helpers.analyzeRequest(self._context.getSelectedMessages()[0])
        headers = self.headersDict() 
        if self.contentType == iRequestInfo.CONTENT_TYPE_MULTIPART:
            to_copy = self.asPythonRequest_multipart(headers)
        elif self.contentType == iRequestInfo.CONTENT_TYPE_JSON:
            to_copy = self.asPythonRequest_json(headers)
        elif self.contentType == iRequestInfo.CONTENT_TYPE_NONE:
            to_copy = self.asPythonRequest_none(headers)
        elif self.contentType == iRequestInfo.CONTENT_TYPE_XML:
            to_copy = self.asPythonRequest_xml(headers)
        else:
            to_copy = "Not supported yet!"

        if event == 'n/a':
            return to_copy
        elif event.getActionCommand() == 'clipboard':
            # Copy to clipboard
            self.saveToClipboard(to_copy)
        else:
            # Save file
            self.saveToFile(to_copy)

    def asCURL_multipart(self, headers, iRequestInfo):
        headers.pop('Content-Length')
        formatted_headers = ' \\\n'.join(["--header '" + i + ": " + headers.get(i) + "'" for i in headers])
        formatted_data = []
        for param in iRequestInfo.getParameters():
            if len(param.value.split("\x00")) > 1:
                data = '''--form "{name}=@myAwesomeFile"'''.format(name=param.name)
            else:
                data = '''--form "{name}='{value}'"'''.format(name=param.name, value=param.value)
            formatted_data.append(data)
        raw_binary = ' \\\n'.join(formatted_data)
        to_copy = "curl -i -s -k --location --request {method} '{url}' \\\n{headers} \\\n{payload}".format(method=self.method, url=self.url, headers=formatted_headers, payload=raw_binary)  # noqa
        return to_copy

    def asCURL(self, event):
        if event == 'n/a':
            iRequestInfo = self._helpers.analyzeRequest(self._exporter)
            self.setData(iRequestInfo)
        else:
            iRequestInfo = self._helpers.analyzeRequest(self._context.getSelectedMessages()[0])
        headers = self.headersDict() 
        formatted_headers = ' \\\n'.join(["--header '" + i + ": " + headers.get(i) + "'" for i in headers])
        if self.contentType == iRequestInfo.CONTENT_TYPE_MULTIPART:
            to_copy = self.asCURL_multipart(headers, iRequestInfo)
        elif self.contentType == iRequestInfo.CONTENT_TYPE_JSON:
            to_copy = "curl -i -s -k --location --request {method} '{url}' \\\n{headers} \\\n--data-raw '{payload}'".format(method=self.method, url=self.url, headers=formatted_headers, payload=self.payload)  # noqa
        elif self.contentType == iRequestInfo.CONTENT_TYPE_NONE:
            to_copy = "curl -i -s -k --location --request {method} '{url}' \\\n{headers} \\\n".format(method=self.method, url=self.url, headers=formatted_headers)  # noqa
        elif self.contentType == iRequestInfo.CONTENT_TYPE_XML:
            to_copy = "curl -i -s -k --location --request {method} '{url}' \\\n{headers} \\\n--data-raw '{payload}'".format(method=self.method, url=self.url, headers=formatted_headers, payload=self.payload)  # noqa
        else:
            to_copy = "Not supported yet!"

        if event == 'n/a':
            return to_copy
        elif event.getActionCommand() == 'clipboard':
            # Copy to clipboard
            self.saveToClipboard(to_copy)
        else:
            # Save file
            self.saveToFile(to_copy)

    def asWget_multipart(self, formatted_headers, iRequestInfo):
        formatted_data = []
        for param in iRequestInfo.getParameters():
            if len(param.value.split("\x00")) > 1:
                data = '''--post-data "{name}=@myAwesomeFile"'''.format(name=param.name)
            else:
                data = '''--post-data "{name}='{value}'"'''.format(name=param.name, value=param.value)
            formatted_data.append(data)
        raw_binary = ' \\\n'.join(formatted_data)
        to_copy = '''wget --no-check-certificate --quiet -S \\\n--method {method} --timeout=0 \\\n{payload} \\\n{headers} \\\n{url}'''.format(url=self.url, payload=raw_binary, method=self.method, headers=formatted_headers)  # noqa

        return to_copy

    def asWget_json(self, formatted_headers):
        payload = self.payload.replace('"', '\\"')
        to_copy = '''wget --no-check-certificate --quiet -S \\\n--method {method} --timeout=0 \\\n--body-data '{payload}' \\\n{headers} \\\n{url}'''.format(url=self.url,
                                                                                                                                                         payload=payload,
                                                                                                                                                         method=self.method,
                                                                                                                                                         headers=formatted_headers)  # noqa
        return to_copy

    def asWget_none(self, formatted_headers):
        to_copy = '''wget --no-check-certificate --quiet -S \\\n--method {method} --timeout=0 \\\n{headers} \\\n{url}'''.format(url=self.url,
                                                                                                                                 method=self.method,
                                                                                                                                 headers=formatted_headers)  # noqa
        return to_copy

    def asWget_xml(self, formatted_headers):
        payload = self.payload.replace('"', '\\"')
        to_copy = '''wget --no-check-certificate --quiet -S \\\n--method {method} --timeout=0 \\\n--body-data '{payload}' \\\n{headers} \\\n{url}'''.format(url=self.url,
                                                                                                                                                         payload=payload,
                                                                                                                                                         method=self.method,
                                                                                                                                                         headers=formatted_headers)  # noqa
        return to_copy

    def asWget(self, event):
        if event == 'n/a':
            iRequestInfo = self._helpers.analyzeRequest(self._exporter)
            self.setData(iRequestInfo)
        else:
            iRequestInfo = self._helpers.analyzeRequest(self._context.getSelectedMessages()[0])
        headers = self.headersDict() 
        formatted_headers = ' \\\n'.join(["--header '" + i + ": " + headers.get(i) + "'" for i in headers])
        if self.contentType == iRequestInfo.CONTENT_TYPE_MULTIPART:
            to_copy = self.asWget_multipart(formatted_headers, iRequestInfo)
        elif self.contentType == iRequestInfo.CONTENT_TYPE_JSON:
            to_copy = self.asWget_json(formatted_headers)
        elif self.contentType == iRequestInfo.CONTENT_TYPE_NONE:
            to_copy = self.asWget_none(formatted_headers)
        elif self.contentType == iRequestInfo.CONTENT_TYPE_XML:
            to_copy = self.asWget_xml(formatted_headers)
        else:
            to_copy = "Not supported yet!"

        if event == 'n/a':
            return to_copy
        elif event.getActionCommand() == 'clipboard':
            # Copy to clipboard
            self.saveToClipboard(to_copy)
        else:
            # Save file
            self.saveToFile(to_copy)

    def asPHPRequest_multipart(self, headers, formatted_headers, method):
        payload = self.payload
        payload_list = list(payload.items())
        payload.clear()
        headers.pop(u'Content-Type')
        headers.pop(u'Content-Length')
        for key, val in payload_list:
            new_key = "'{}'".format(key)
            if len(val.split("\x00")) > 1:
                payload[new_key] = '$myAwesomeFileR'
            else:
                new_val = "'{}'".format(val)
                payload[new_key] = new_val

        payload = json.dumps(payload)
        to_copy = '''<?php
require_once 'HTTP/Request2.php';
$request = new HTTP_Request2();
$request->setUrl('{url}');
$request->setMethod({method});
$request->setConfig(array(
  'follow_redirects' => TRUE,
  'ssl_verify_peer' => FALSE,
  'ssl_verify_host' => FALSE
));
$request->setHeader(array(
{headers}
));

$nameF = '<myAwesomeFile>';
$myAwesomeFile = fopen($nameF, 'r');
$myAwesomeFileR = fread($myAwesomeFile, filesize($nameF));

$request->setBody(&dquote{payload}&dquote);
try {{
  $response = $request->send();
  if ($response->getStatus() == 200) {{
    echo $response->getBody();
  }}
  else {{
    echo 'Unexpected HTTP status: ' . $response->getStatus() . ' ' .
    $response->getReasonPhrase();
  }}
}}
catch(HTTP_Request2_Exception $e) {{
  echo 'Error: ' . $e->getMessage();
}}'''.format(url=self.url, payload=str(payload), method=method, headers=formatted_headers)  # noqa
        to_copy = to_copy.replace('"', '')
        to_copy = to_copy.replace('&dquote', '"')

        return to_copy

    def asPHPRequest_json(self, formatted_headers, method):
        payload = self.payload.replace("\n", "").replace("\t", "")
        to_copy = '''<?php
require_once 'HTTP/Request2.php';
$request = new HTTP_Request2();
$request->setUrl('{url}');
$request->setMethod({method});
$request->setConfig(array(
  'follow_redirects' => TRUE,
  'ssl_verify_peer' => FALSE,
  'ssl_verify_host' => FALSE
));
$request->setHeader(array(
{headers}
));
$request->setBody('{payload}');
try {{
  $response = $request->send();
  if ($response->getStatus() == 200) {{
    echo $response->getBody();
  }}
  else {{
    echo 'Unexpected HTTP status: ' . $response->getStatus() . ' ' .
    $response->getReasonPhrase();
  }}
}}
catch(HTTP_Request2_Exception $e) {{
  echo 'Error: ' . $e->getMessage();
}}'''.format(url=self.url, payload=payload, method=method, headers=formatted_headers)  # noqa

        return to_copy

    def asPHPRequest_none(self, formatted_headers, method):
        to_copy = '''<?php
require_once 'HTTP/Request2.php';
$request = new HTTP_Request2();
$request->setUrl('{url}');
$request->setMethod({method});
$request->setConfig(array(
  'follow_redirects' => TRUE,
  'ssl_verify_peer' => FALSE,
  'ssl_verify_host' => FALSE
));
$request->setHeader(array(
{headers}
));
try {{
  $response = $request->send();
  if ($response->getStatus() == 200) {{
    echo $response->getBody();
  }}
  else {{
    echo 'Unexpected HTTP status: ' . $response->getStatus() . ' ' .
    $response->getReasonPhrase();
  }}
}}
catch(HTTP_Request2_Exception $e) {{
  echo 'Error: ' . $e->getMessage();
}}'''.format(url=self.url, method=method, headers=formatted_headers)  # noqa

        return to_copy

    def asPHPRequest_xml(self, formatted_headers, method):
        payload = self.payload.replace("\n", "").replace("\t", "")
        to_copy = '''<?php
require_once 'HTTP/Request2.php';
$request = new HTTP_Request2();
$request->setUrl('{url}');
$request->setMethod({method});
$request->setConfig(array(
  'follow_redirects' => TRUE,
  'ssl_verify_peer' => FALSE,
  'ssl_verify_host' => FALSE
));
$request->setHeader(array(
{headers}
));
$request->setBody('{payload}');
try {{
  $response = $request->send();
  if ($response->getStatus() == 200) {{
    echo $response->getBody();
  }}
  else {{
    echo 'Unexpected HTTP status: ' . $response->getStatus() . ' ' .
    $response->getReasonPhrase();
  }}
}}
catch(HTTP_Request2_Exception $e) {{
  echo 'Error: ' . $e->getMessage();
}}'''.format(url=self.url, payload=payload, method=method, headers=formatted_headers)  # noqa

        return to_copy

    def asPHPRequest(self, event):
        def formatPhpMethod(method):
            common_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']
            return 'HTTP_Request2::METHOD_' + method if method in common_methods else method

        if event == 'n/a':
            iRequestInfo = self._helpers.analyzeRequest(self._exporter)
            self.setData(iRequestInfo)
        else:
            iRequestInfo = self._helpers.analyzeRequest(self._context.getSelectedMessages()[0])
        headers = self.headersDict() 
        formatted_headers = ',\n'.join(["  '" + i + "' => '" + headers.get(i) + "'" for i in headers])
        method = formatPhpMethod(self.method)
        if self.contentType == iRequestInfo.CONTENT_TYPE_MULTIPART:
            to_copy = self.asPHPRequest_multipart(headers, formatted_headers, method)
        elif self.contentType == iRequestInfo.CONTENT_TYPE_JSON:
            to_copy = self.asPHPRequest_json(formatted_headers, method)
        elif self.contentType == iRequestInfo.CONTENT_TYPE_NONE:
            to_copy = self.asPHPRequest_none(formatted_headers, method)
        elif self.contentType == iRequestInfo.CONTENT_TYPE_XML:
            to_copy = self.asPHPRequest_xml(formatted_headers, method)
        else:
            to_copy = "Not supported yet!"

        if event == 'n/a':
            return to_copy
        elif event.getActionCommand() == 'clipboard':
            # Copy to clipboard
            self.saveToClipboard(to_copy)
        else:
            # Save file
            self.saveToFile(to_copy)

    def asGO_multipart(self, formatted_headers):
        payload = self.payload
        payload_list = list(payload.items())
        payload.clear()
        for key, val in payload_list:
            new_key = "'{}'".format(key)
            if len(val.split("\x00")) > 1:
                payload[new_key] = '%s'
            else:
                new_val = "'{}'".format(val)
                payload[new_key] = new_val

        payload = json.dumps(payload)
        to_copy = '''package main

import (
  "fmt"
  "strings"
  "net/http"
  "io/ioutil"
  "os"
  "crypto/tls"
)

func main() {{

  url := "{url}"
  method := "{method}"

  myFile := os.Open("<YourAwesomeFile>")

  payload := strings.NewReader("{payload}", myFile)

  tr := &http.Transport{{
    TLSClientConfig: &tls.Config{{InsecureSkipVerify: true}},
  }}
  client := &http.Client {{  Transport: tr  }}
  req, err := http.NewRequest(method, url, payload)

  if err != nil {{
    fmt.Println(err)
  }}
  {headers}

  res2, err := client.Do(req)
  res := *res2
  defer res.Body.Close()
  body, err := ioutil.ReadAll(res.Body)

  fmt.Println(string(body))
}}'''.format(url=self.url, payload=payload, method=self.method, headers=formatted_headers)  # noqa

        return to_copy

    def asGO_json(self, formatted_headers):
        payload = self.payload.replace("\n", "").replace("\t", "").replace('"', '\\"') if self.payload.__class__ == str else self.payload
        to_copy = '''package main

import (
  "fmt"
  "strings"
  "net/http"
  "io/ioutil"
  "crypto/tls"
)

func main() {{

  url := "{url}"
  method := "{method}"

  payload := strings.NewReader("{payload}")

  tr := &http.Transport{{
    TLSClientConfig: &tls.Config{{InsecureSkipVerify: true}},
  }}
  client := &http.Client {{  Transport: tr  }}
  req, err := http.NewRequest(method, url, payload)

  if err != nil {{
    fmt.Println(err)
  }}
  {headers}

  res2, err := client.Do(req)
  res := *res2
  defer res.Body.Close()
  body, err := ioutil.ReadAll(res.Body)

  fmt.Println(string(body))
}}'''.format(url=self.url, payload=payload, method=self.method, headers=formatted_headers)  # noqa

        return to_copy

    def asGO_none(self, formatted_headers):
        to_copy = '''package main

import (
  "fmt"
  "strings"
  "net/http"
  "io/ioutil"
  "crypto/tls"
)

func main() {{

  url := "{url}"
  method := "{method}"

  payload := strings.NewReader("")
  tr := &http.Transport{{
    TLSClientConfig: &tls.Config{{InsecureSkipVerify: true}},
  }}
  client := &http.Client {{  Transport: tr  }}
  req, err := http.NewRequest(method, url, payload)

  if err != nil {{
    fmt.Println(err)
  }}
  {headers}

  res2, err := client.Do(req)
  res := *res2
  defer res.Body.Close()
  body, err := ioutil.ReadAll(res.Body)

  fmt.Println(string(body))
}}'''.format(url=self.url, method=self.method, headers=formatted_headers)  # noqa

        return to_copy

    def asGO_xml(self, formatted_headers):
        payload = self.payload.replace("\n", "").replace("\t", "").replace('"', '\\"') if self.payload.__class__ == str else self.payload
        to_copy = '''package main

import (
  "fmt"
  "strings"
  "net/http"
  "io/ioutil"
  "crypto/tls"
)

func main() {{

  url := "{url}"
  method := "{method}"

  payload := strings.NewReader("{payload}")

  tr := &http.Transport{{
    TLSClientConfig: &tls.Config{{InsecureSkipVerify: true}},
  }}
  client := &http.Client {{  Transport: tr  }}
  req, err := http.NewRequest(method, url, payload)

  if err != nil {{
    fmt.Println(err)
  }}
  {headers}

  res2, err := client.Do(req)
  res := *res2
  defer res.Body.Close()
  body, err := ioutil.ReadAll(res.Body)

  fmt.Println(string(body))
}}'''.format(url=self.url, payload=payload, method=self.method, headers=formatted_headers)  # noqa

        return to_copy

    def asGO(self, event):
        if event == 'n/a':
            iRequestInfo = self._helpers.analyzeRequest(self._exporter)
            self.setData(iRequestInfo)
        else:
            iRequestInfo = self._helpers.analyzeRequest(self._context.getSelectedMessages()[0])
        headers = self.headersDict()
        formatted_headers = '\n  '.join(["req.Header.Add(\"" + i + "\", \"" + headers.get(i) + "\")" for i in headers])
        if self.contentType == iRequestInfo.CONTENT_TYPE_MULTIPART:
            to_copy = self.asGO_multipart(formatted_headers)
        elif self.contentType == iRequestInfo.CONTENT_TYPE_JSON:
            to_copy = self.asGO_json(formatted_headers)
        elif self.contentType == iRequestInfo.CONTENT_TYPE_NONE:
            to_copy = self.asGO_none(formatted_headers)
        elif self.contentType == iRequestInfo.CONTENT_TYPE_XML:
            to_copy = self.asGO_xml(formatted_headers)
        else:
            to_copy = "not supported yet"

        if event == 'n/a':
            return to_copy
        elif event.getActionCommand() == 'clipboard':
            # Copy to clipboard
            self.saveToClipboard(to_copy)
        else:
            # Save file
            self.saveToFile(to_copy)

    def asNodeJSRequest_multipart(self, formatted_headers):
        payload = self.payload
        payload_list = list(payload.items())
        payload.clear()
        for key, val in payload_list:
            new_key = "'{}'".format(key)
            if len(val.split("\x00")) > 1:
                payload[new_key] = "fs.createReadStream('<YourAwesomeFileHere>');"
            else:
                new_val = "'{}'".format(val)
                payload[new_key] = new_val

        payload = json.dumps(payload)
        to_copy = '''process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
var request = require('request');
var fs = require('fs');
var options = {{
  'method': '{method}',
  'url': '{url}',
  'headers': {{
    {headers}
  }},
  body: JSON.stringify({payload})

}};
request(options, function (error, response) {{
  if (error) throw new Error(error);
  console.log(response.body);
}});
'''.format(url=self.url, payload=payload, method=self.method, headers=formatted_headers)  # noqa
        to_copy = to_copy.replace('"', '')
        to_copy = to_copy.replace('&dquote', '"')

        return to_copy

    def asNodeJSRequest_json(self, formatted_headers):
        payload = self.payload.replace("\n", "").replace("\t", "") if self.payload.__class__ == str else self.payload
        to_copy = '''process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
var request = require('request');
var options = {{
  'method': '{method}',
  'url': '{url}',
  'headers': {{
    {headers}
  }},
  body: JSON.stringify({payload})

}};
request(options, function (error, response) {{
  if (error) throw new Error(error);
  console.log(response.body);
}});
'''.format(url=self.url, payload=payload, method=self.method, headers=formatted_headers)  # noqa

        return to_copy

    def asNodeJSRequest_none(self, formatted_headers):
        to_copy = '''process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
var request = require('request');
var options = {{
  'method': '{method}',
  'url': '{url}',
  'headers': {{
    {headers}
  }},

}};
request(options, function (error, response) {{
  if (error) throw new Error(error);
  console.log(response.body);
}});
'''.format(url=self.url, method=self.method, headers=formatted_headers)  # noqa

        return to_copy

    def asNodeJSRequest_xml(self, formatted_headers):
        payload = self.payload.replace("\n", "").replace("\t", "") if self.payload.__class__ == str else self.payload
        to_copy = '''process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
var request = require('request');
var options = {{
  'method': '{method}',
  'url': '{url}',
  'headers': {{
    {headers}
  }},
  body: "{payload}"

}};
request(options, function (error, response) {{
  if (error) throw new Error(error);
  console.log(response.body);
}});
'''.format(url=self.url, payload=payload, method=self.method, headers=formatted_headers)  # noqa

        return to_copy

    def asNodeJSRequest(self, event):
        if event == 'n/a':
            iRequestInfo = self._helpers.analyzeRequest(self._exporter)
            self.setData(iRequestInfo)
        else:
            iRequestInfo = self._helpers.analyzeRequest(self._context.getSelectedMessages()[0])
        headers = self.headersDict()
        formatted_headers = '\n    '.join(["'" + i + "': '" + headers.get(i) + "'," for i in headers])
        if self.contentType == iRequestInfo.CONTENT_TYPE_MULTIPART:
            to_copy = self.asNodeJSRequest_multipart(formatted_headers)
        elif self.contentType == iRequestInfo.CONTENT_TYPE_JSON:
            to_copy = self.asNodeJSRequest_json(formatted_headers)
        elif self.contentType == iRequestInfo.CONTENT_TYPE_NONE:
            to_copy = self.asNodeJSRequest_none(formatted_headers)
        elif self.contentType == iRequestInfo.CONTENT_TYPE_XML:
            to_copy = self.asNodeJSRequest_xml(formatted_headers)
        else:
            to_copy = "not supported yet"

        if event == 'n/a':
            return to_copy
        elif event.getActionCommand() == 'clipboard':
            # Copy to clipboard
            self.saveToClipboard(to_copy)
        else:
            # Save file
            self.saveToFile(to_copy)

    def asJQueryAjax_multipart(self, payload):
        payload = self.payload
        payload_list = list(payload.items())
        payload.clear()
        for key, val in payload_list:
            new_key = "'{}'".format(key)
            if len(val.split("\x00")) > 1:
                payload[new_key] = "$('#<input>').val();"
            else:
                new_val = "'{}'".format(val)
                payload[new_key] = new_val

        return payload

    def asJQueryAjax(self, event):
        if event == 'n/a':
            iRequestInfo = self._helpers.analyzeRequest(self._exporter)
            self.setData(iRequestInfo)
        else:
            iRequestInfo = self._helpers.analyzeRequest(self._context.getSelectedMessages()[0])
        headers = self.headersDict()
        formatted_headers = '\n    '.join(["\"" + i + "\": \"" + headers.get(i) + "\"," for i in headers])
        if self.contentType == iRequestInfo.CONTENT_TYPE_NONE:
            payload = {}
        else:
            payload = self.payload.replace("\n", "").replace("\t", "") if self.payload.__class__ == str else self.payload  # noqa
        if self.contentType == iRequestInfo.CONTENT_TYPE_MULTIPART:
            payload = self.asJQueryAjax_multipart(self)
        to_copy = '''var settings = {{
  "url": "{url}",
  "method": "{method}",
  "timeout": 0,
  "headers": {{
    {headers}
  }},
  "data": JSON.stringify({payload})
}};

$.ajax(settings).done(function (response) {{
  console.log(response);
}});
'''.format(url=self.url, payload=payload, method=self.method, headers=formatted_headers)  # noqa
        if self.contentType == iRequestInfo.CONTENT_TYPE_XML:
            to_copy = '''var settings = {{
      "url": "{url}",
      "method": "{method}",
      "timeout": 0,
      "headers": {{
        {headers}
      }},
      "data": "{payload}"
    }};

    $.ajax(settings).done(function (response) {{
      console.log(response);
    }});
    '''.format(url=self.url, payload=payload, method=self.method, headers=formatted_headers)  # noqa

        if event == 'n/a':
            return to_copy
        elif event.getActionCommand() == 'clipboard':
            # Copy to clipboard
            self.saveToClipboard(to_copy)
        else:
            # Save file
            self.saveToFile(to_copy)

    def asPowerShell_multipart(self, formatted_headers):
        payload = self.payload
        payload_list = list(payload.items())
        payload.clear()
        for key, val in payload_list:
            new_key = "'{}'".format(key)
            if len(val.split("\x00")) > 1:
                payload[new_key] = "[IO.File]::ReadAllText('<YourAwesomeFile>');"
            else:
                new_val = "'{}'".format(val)
                payload[new_key] = new_val

        payload = json.dumps(payload)
        body = "-Body $body"
        if self.method.lower() == 'get':
            body = ""
        to_copy = '''add-type @"
using System.Net;using System.Security.Cryptography.X509Certificates;public class TrustAllCertsPolicy : ICertificatePolicy {{public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) {{return true;}}}}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
$headers = New-Object "System.Collections.Generic.Dictionary[[String], [String]]"
{headers}
$body = "{payload}"
$response = Invoke-RestMethod '{url}' -Method '{method}' -Headers $headers {body}
$response | ConvertTo-Json
'''.format(url=self.url, payload=payload, method=self.method, headers=formatted_headers, body=body)  # noqa
        to_copy = to_copy.replace('"', '')
        to_copy = to_copy.replace('&dquote', '"')

        return to_copy

    def asPowerShell_json(self, formatted_headers):
        payload = self.payload.replace("\n", "").replace("\t", "") if self.payload.__class__ == str else self.payload
        payload = payload.replace("\"", "`\"") if self.payload.__class__ == str else self.payload
        body = "-Body $body"
        if self.method.lower() == 'get':
            body = ""
        to_copy = '''add-type @"
using System.Net;using System.Security.Cryptography.X509Certificates;public class TrustAllCertsPolicy : ICertificatePolicy {{public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) {{return true;}}}}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
$headers = New-Object "System.Collections.Generic.Dictionary[[String], [String]]"
{headers}
$body = "{payload}"
$response = Invoke-RestMethod '{url}' -Method '{method}' -Headers $headers {body}
$response | ConvertTo-Json
'''.format(url=self.url, payload=payload, method=self.method, headers=formatted_headers, body=body)  # noqa

        return to_copy

    def asPowerShell_none(self, formatted_headers):
        to_copy = '''$headers = New-Object "System.Collections.Generic.Dictionary[[String], [String]]"
{headers}
$response = Invoke-RestMethod '{url}' -Method '{method}' -Headers $headers
$response | ConvertTo-Json
'''.format(url=self.url, method=self.method, headers=formatted_headers)  # noqa

        return to_copy

    def asPowerShell_xml(self, formatted_headers):
        payload = self.payload.replace("\n", "").replace("\t", "") if self.payload.__class__ == str else self.payload
        payload = payload.replace("\"", "`\"") if self.payload.__class__ == str else self.payload
        body = "-Body $body"
        if self.method.lower() == 'get':
            body = ""
        to_copy = '''add-type @"
using System.Net;using System.Security.Cryptography.X509Certificates;public class TrustAllCertsPolicy : ICertificatePolicy {{public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) {{return true;}}}}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
$headers = New-Object "System.Collections.Generic.Dictionary[[String], [String]]"
{headers}
$body = "{payload}"
$response = Invoke-RestMethod '{url}' -Method '{method}' -Headers $headers {body}
$response | ConvertTo-Json
'''.format(url=self.url, payload=payload, method=self.method, headers=formatted_headers, body=body)  # noqa

        return to_copy

    def asPowerShell(self, event):
        if event == 'n/a':
            iRequestInfo = self._helpers.analyzeRequest(self._exporter)
            self.setData(iRequestInfo)
        else:
            iRequestInfo = self._helpers.analyzeRequest(self._context.getSelectedMessages()[0])
        headers = self.headersDict()
        formatted_headers = '\n'.join(["$headers.Add('" + i + "', '" + headers.get(i) + "')" for i in headers])
        if self.contentType == iRequestInfo.CONTENT_TYPE_MULTIPART:
            to_copy = self.asPowerShell_multipart(formatted_headers)
        elif self.contentType == iRequestInfo.CONTENT_TYPE_JSON:
            to_copy = self.asPowerShell_json(formatted_headers)
        elif self.contentType == iRequestInfo.CONTENT_TYPE_NONE:
            to_copy = self.asPowerShell_none(formatted_headers)
        elif self.contentType == iRequestInfo.CONTENT_TYPE_XML:
            to_copy = self.asPowerShell_xml(formatted_headers)
        else:
            to_copy = "not supported yet"

        if event == 'n/a':
            return to_copy
        elif event.getActionCommand() == 'clipboard':
            # Copy to clipboard
            self.saveToClipboard(to_copy)
        else:
            # Save file
            self.saveToFile(to_copy)

    def asPerl_multipart(self, headers, cookies):
        payload = self.payload
        payload_list = list(payload.items())
        payload.clear()
        for key, val in payload_list:
            new_key = "{}".format(key)
            if len(val.split("\x00")) > 1:
                payload[new_key] = "'{}'".format("['<myAwesomeFile>']")
            else:
                new_val = "{}".format(val)
                payload[new_key] = new_val
        payload = '\n\t'.join([i + ' => \'' + payload.get(i) + '\',' for i in payload])
        formatted_headers = '\n    '.join([i + ' => \'' + headers.get(i) + '\',' for i in headers])
        formatted_headers = formatted_headers.replace("-", "_")
        formatted_headers = formatted_headers.replace("form_data", "form-data")

        to_copy = '''use LWP::UserAgent;
use HTTP::Request::Common;
use HTTP::Cookies;

my $url = URI->new(&dquote{url}&dquote);

my $cookies = HTTP::Cookies->new();
{cookies}

my $ua = LWP::UserAgent->new(ssl_opts => {{ verify_hostname => 0 }});
$ua->cookie_jar($cookies);

my $req = $ua->post($url,
    {headers}
    Content => [
	{payload}
    ],
);
'''.format(url=self.url, payload=payload, method=self.method, headers=formatted_headers, cookies=cookies)  # noqa
        to_copy = to_copy.replace('"', '')
        to_copy = to_copy.replace('&dquote', '"')
        to_copy = to_copy.replace("''", '')
        to_copy = to_copy.replace("None", '')

        return to_copy

    def asPerl_json(self, formatted_headers, cookies):
        payload = self.payload.replace("\n", "").replace("\t", "").replace('"', '\\"')
        to_copy = '''use LWP::UserAgent;
use HTTP::Request::Common;
use HTTP::Cookies;

my $url = URI->new("{url}");

my $cookies = HTTP::Cookies->new();
{cookies}

my $ua = LWP::UserAgent->new(ssl_opts => {{ verify_hostname => 0 }});
$ua->cookie_jar($cookies);

my $req = {method} $url;
{headers}
$req->content("{payload}");
my $resp = $ua->request($req);

print "Status code : ".$resp->code."\\n";
print "Response body : ".$resp->content."\\n";

'''.format(url=self.url, payload=payload, method=self.method, headers=formatted_headers, cookies=cookies)  # noqa

        return to_copy

    def asPerl_none(self, formatted_headers, cookies):
        to_copy = '''use LWP::UserAgent;
use HTTP::Request::Common;
use HTTP::Cookies;

my $url = URI->new("{url}");

my $cookies = HTTP::Cookies->new();
{cookies}

my $ua = LWP::UserAgent->new(ssl_opts => {{ verify_hostname => 0 }});
$ua->cookie_jar($cookies);

my $req = {method} $url;
{headers}
my $resp = $ua->request($req);

print "Status code : ".$resp->code."\\n";
print "Response body : ".$resp->content."\\n";

'''.format(url=self.url, method=self.method, headers=formatted_headers, cookies=cookies)  # noqa

        return to_copy

    def asPerl_xml(self, formatted_headers, cookies):
        payload = self.payload.replace("\n", "").replace("\t", "").replace('"', '\\"')
        to_copy = '''use LWP::UserAgent;
use HTTP::Request::Common;
use HTTP::Cookies;

my $url = URI->new("{url}");

my $cookies = HTTP::Cookies->new();
{cookies}

my $ua = LWP::UserAgent->new(ssl_opts => {{ verify_hostname => 0 }});
$ua->cookie_jar($cookies);

my $req = {method} $url;
{headers}
$req->content("{payload}");
my $resp = $ua->request($req);

print "Status code : ".$resp->code."\\n";
print "Response body : ".$resp->content."\\n";

'''.format(url=self.url, payload=payload, method=self.method, headers=formatted_headers, cookies=cookies)  # noqa

        return to_copy

    def asPerl(self, event):
        if event == 'n/a':
            iRequestInfo = self._helpers.analyzeRequest(self._exporter)
            self.setData(iRequestInfo)
        else:
            iRequestInfo = self._helpers.analyzeRequest(self._context.getSelectedMessages()[0])
        headers = self.headersDict()
        cookies = headers.get('Cookie')
        if cookies:
            cookies = cookies.split('; ')
            cookies = dict(item.split('=') for item in cookies)
            headers.pop('Cookie')
            path = "/"
            parts = self.url.split('://', 1)
            if ':' in parts[1]:
                url = parts[0] + '://' + parts[1].split(':', 1)[0]
            else:
                url = parts[0] + '://' + parts[1].split('/', 1)[0]

            cookies = '\n'.join(['$cookies->set_cookie(0,\'' + key + '\', \'' + cookies.get(key)
                                 + '\', \'' + path + '\', \'' + url + '\');' for key in cookies])

        formatted_headers = '\n'.join([i + '\' => \'' + headers.get(i) + '\');' for i in headers])
        if self.contentType == iRequestInfo.CONTENT_TYPE_MULTIPART:
            to_copy = self.asPerl_multipart(headers, cookies)
        elif self.contentType == iRequestInfo.CONTENT_TYPE_JSON:
            to_copy = self.asPerl_json(formatted_headers, cookies)
        elif self.contentType == iRequestInfo.CONTENT_TYPE_NONE:
            to_copy = self.asPerl_none(formatted_headers, cookies)
        elif self.contentType == iRequestInfo.CONTENT_TYPE_XML:
            to_copy = self.asPerl_xml(formatted_headers, cookies)
        else:
            to_copy = "Not supported yet!"

        if event == 'n/a':
            return to_copy
        elif event.getActionCommand() == 'clipboard':
            # Copy to clipboard
            self.saveToClipboard(to_copy)
        else:
            # Save file
            self.saveToFile(to_copy)

    def asHTMLForm_multipart(self, inputs):
        payload = self.payload
        payload_list = list(payload.items())
        payload.clear()
        for key, val in payload_list:
            if len(val.split("\x00")) > 1:
                html = """            <input type="file" name="{key}" /> \n""".format(key=key)
            else:
                html = """            <input type="text" value="{value}" name="{key}" /> \n""".format(value=val, key=key)
            inputs += html
        to_copy = '''
<html>
    <body>
        <script>hitory.pushState('', '', '/')</script>
        <form action="{url}" method="{method}">
{inputs}
            <input type="submit" value="Submit request"/>
        </form>
    </body>
</html>
    '''.format(url=self.url, inputs=inputs, method=self.method)

        return to_copy

    def asHTMLForm_none(self, inputs, iRequestInfo):
        to_copy = '''
<html>
    <body>
        <script>hitory.pushState('', '', '/')</script>
        <form action="{url}" method="{method}">
            <input type="submit" value="Submit request"/>
        </form>
    </body>
</html>
    '''.format(url=self.url, method=self.method)

        return to_copy

    def asHTMLForm(self, event):
        if event == 'n/a':
            iRequestInfo = self._helpers.analyzeRequest(self._exporter)
            self.setData(iRequestInfo)
        else:
            iRequestInfo = self._helpers.analyzeRequest(self._context.getSelectedMessages()[0])
        inputs = ""
        if self.contentType == iRequestInfo.CONTENT_TYPE_MULTIPART:
            to_copy = self.asHTMLForm_multipart(inputs)
        elif self.contentType == iRequestInfo.CONTENT_TYPE_JSON:
            to_copy = self.asHTMLForm_none(inputs, iRequestInfo)
        elif self.contentType == iRequestInfo.CONTENT_TYPE_NONE:
            to_copy = self.asHTMLForm_none(inputs, iRequestInfo)
        else:
            to_copy = "Not supported yet!"

        if event == 'n/a':
            return to_copy
        elif event.getActionCommand() == 'clipboard':
            # Copy to clipboard
            self.saveToClipboard(to_copy)
        else:
            # Save file
            self.saveToFile(to_copy)

    def asRuby_multipart(self, headers):
        payload = self.payload
        payload_list = list(payload.items())
        payload.clear()
        headers.pop(u'Content-Type')
        formatted_headers = '\n'.join(["request[\"" + i + "\" ] = [\"" + headers.get(i) + "\"]" for i in headers])
        for key, val in payload_list:
            new_key = '"{}"'.format(key)
            if len(val.split("\x00")) > 1:
                payload[new_key] = 'File.open("<yourAwesomeFileHere>", "rb")'
            else:
                new_val = '"{}"'.format(val)
                payload[new_key] = new_val
        to_copy = '''
require "uri"
require "net/http"

url = URI("{url}")
http = Net::HTTP.new(url.host, url.port);
request = Net::HTTP::Post.new(url)
{headers}
request.body = {payload}
response = http.request(request)
puts response.read_body

'''.format(url=self.url, payload=payload, method=self.method, headers=formatted_headers)  # noqa
        to_copy = to_copy.replace("'", "")

        return to_copy

    def asRuby_json(self, headers):
        payload = self.payload.replace("\n", "").replace("\t", "").replace('"', '\\"').replace("\\", "")
        formatted_headers = '\n'.join(["request[\"" + i + "\" ] = [\"" + headers.get(i) + "\"]" for i in headers])
        to_copy = '''
require "uri"
require "net/http"

url = URI("{url}")
http = Net::HTTP.new(url.host, url.port);
request = Net::HTTP::Post.new(url)
{headers}
request.body = {payload}
response = http.request(request)
puts response.read_body

'''.format(url=self.url, payload=payload, method=self.method, headers=formatted_headers)  # noqa

        return to_copy

    def asRuby_none(self, headers):
        formatted_headers = '\n'.join(["request[\"" + i + "\" ] = [\"" + headers.get(i) + "\"]" for i in headers])
        to_copy = '''
require "uri"
require "net/http"

url = URI("{url}")
http = Net::HTTP.new(url.host, url.port);
request = Net::HTTP::Post.new(url)
{headers}
response = http.request(request)
puts response.read_body

'''.format(url=self.url, method=self.method, headers=formatted_headers)  # noqa

        return to_copy

    def asRuby_xml(self, headers):
        payload = self.payload.replace("\n", "").replace("\t", "").replace('"', '\\"').replace("\\", "")
        formatted_headers = '\n'.join(["request[\"" + i + "\" ] = [\"" + headers.get(i) + "\"]" for i in headers])
        to_copy = '''
require "uri"
require "net/http"

url = URI("{url}")
http = Net::HTTP.new(url.host, url.port);
request = Net::HTTP::Post.new(url)
{headers}
request.body = "{payload}"
response = http.request(request)
puts response.read_body

'''.format(url=self.url, payload=payload, method=self.method, headers=formatted_headers)  # noqa

        return to_copy

    def asRuby(self, event):
        if event == 'n/a':
            iRequestInfo = self._helpers.analyzeRequest(self._exporter)
            self.setData(iRequestInfo)
        else:
            iRequestInfo = self._helpers.analyzeRequest(self._context.getSelectedMessages()[0])
        headers = self.headersDict()
        if self.contentType == iRequestInfo.CONTENT_TYPE_MULTIPART:
            to_copy = self.asRuby_multipart(headers)
        elif self.contentType == iRequestInfo.CONTENT_TYPE_JSON:
            to_copy = self.asRuby_json(headers)
        elif self.contentType == iRequestInfo.CONTENT_TYPE_NONE:
            to_copy = self.asRuby_none(headers)
        elif self.contentType == iRequestInfo.CONTENT_TYPE_XML:
            to_copy = self.asRuby_xml(headers)
        else:
            to_copy = "Not supported yet!"

        if event == 'n/a':
            return to_copy
        elif event.getActionCommand() == 'clipboard':
            # Copy to clipboard
            self.saveToClipboard(to_copy)
        else:
            # Save file
            self.saveToFile(to_copy)

    def asXHR_multipart(self, headers):
        payload = self.payload
        payload_list = list(payload.items())
        payload.clear()
        headers.pop(u'Content-Type')
        formatted_headers = '\n'.join(["xhr.setRequestHeader(\"" + i + "\", \"" + headers.get(i) + "\")" for i in headers])
        str_payload = ""
        for key, val in payload_list:
            if len(val.split("\x00")) > 1:
                str_payload += 'data.append("{key}", "<yourAwesomeFileContentHere>", "file")\n'.format(key=key)
            else:
                str_payload += 'data.append("{key}", "{val}")\n'.format(key=key, val=val)
        to_copy = '''var data = new FormData();
{payload}

var xhr = new XMLHttpRequest();
xhr.withCredentials = true;

xhr.addEventListener("readystatechange", function() {{
  if(this.readyState === 4) {{
    console.log(this.responseText);
  }}
}});

xhr.open("{method}", "{url}");
{headers}
xhr.send(data)
'''.format(url=self.url, payload=str_payload, method=self.method, headers=formatted_headers)  # noqa

        return to_copy

    def asXHR_json(self, headers):
        payload = self.payload
        formatted_headers = '\n'.join(["xhr.setRequestHeader(\"" + i + "\", \"" + headers.get(i) + "\")" for i in headers])
        to_copy = '''var data = JSON.stringify({payload});

var xhr = new XMLHttpRequest();
xhr.withCredentials = true;

xhr.addEventListener("readystatechange", function() {{
  if(this.readyState === 4) {{
    console.log(this.responseText);
  }}
}});

xhr.open("{method}", "{url}");
{headers}
xhr.send(data)
'''.format(url=self.url, payload=self.payload, method=self.method, headers=formatted_headers)  # noqa

        to_copy = to_copy.replace("'", '"')
        return to_copy

    def asXHR_none(self, headers):
        formatted_headers = '\n'.join(["xhr.setRequestHeader(\"" + i + "\", \"" + headers.get(i) + "\")" for i in headers])
        to_copy = '''
var xhr = new XMLHttpRequest();
xhr.withCredentials = true;

xhr.addEventListener("readystatechange", function() {{
  if(this.readyState === 4) {{
    console.log(this.responseText);
  }}
}});

xhr.open("{method}", "{url}");
{headers}
xhr.send()
'''.format(url=self.url, method=self.method, headers=formatted_headers)  # noqa

        return to_copy

    def asXHR_xml(self, headers):
        payload = self.payload.replace("\n", "").replace("\t", "").replace('"', '\\"').replace("\\", "")
        formatted_headers = '\n'.join(["xhr.setRequestHeader(\"" + i + "\", \"" + headers.get(i) + "\")" for i in headers])
        to_copy = '''var data = '{payload}';
var xhr = new XMLHttpRequest();
xhr.withCredentials = true;

xhr.addEventListener("readystatechange", function() {{
  if(this.readyState === 4) {{
    console.log(this.responseText);
  }}
}});

xhr.open("{method}", "{url}");
{headers}
xhr.send(data)
'''.format(url=self.url, payload=payload, method=self.method, headers=formatted_headers)  # noqa

        return to_copy

    def asXHR(self, event):
        if event == 'n/a':
            iRequestInfo = self._helpers.analyzeRequest(self._exporter)
            self.setData(iRequestInfo)
        else:
            iRequestInfo = self._helpers.analyzeRequest(self._context.getSelectedMessages()[0])
        headers = self.headersDict()
        if self.contentType == iRequestInfo.CONTENT_TYPE_MULTIPART:
            to_copy = self.asXHR_multipart(headers)
        elif self.contentType == iRequestInfo.CONTENT_TYPE_JSON:
            to_copy = self.asXHR_json(headers)
        elif self.contentType == iRequestInfo.CONTENT_TYPE_NONE:
            to_copy = self.asXHR_none(headers)
        elif self.contentType == iRequestInfo.CONTENT_TYPE_XML:
            to_copy = self.asXHR_xml(headers)
        else:
            to_copy = "Not supported yet!"

        if event == 'n/a':
            return to_copy
        elif event.getActionCommand() == 'clipboard':
            # Copy to clipboard
            self.saveToClipboard(to_copy)
        else:
            # Save file
            self.saveToFile(to_copy)

    def saveToClipboard(self, data):
        s = StringSelection(data)
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(s, s)

    def saveToFile(self, data):
        fd = JFileChooser()
        dialog = fd.showDialog(self.mainpanel, "Save As")

        if dialog == JFileChooser.APPROVE_OPTION:
            file = fd.getSelectedFile()
            path = file.getCanonicalPath()

            try:
                with open(path, 'w') as exportFile:
                    exportFile.write(data)
            except IOError as e:
                print("Error exporting data: " + str(e))
                self._logger.debug("Error exporting data to: " + path + ", Error: " + str(e))

        return


class Table(JTable):

    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
        return

    def changeSelection(self, row, col, toggle, extend):
        JTable.changeSelection(self, row, col, toggle, extend)
        self._extender.snippetLanCombo.setEnabled(True)
        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        self._extender._exporter = logEntry._requestResponse.getRequest()
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender.snippetLanCombo.setSelectedIndex(0)
        self._extender._currentlyDisplayedItem = logEntry._requestResponse
        if logEntry._requestResponse.getResponse():
            self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        else:
            self._extender._responseViewer.setMessage('', False)

        return


class LogEntry:

    def __init__(self, tool, requestResponse, url, method, status):
        self._tool = tool
        self._requestResponse = requestResponse
        self._url = url
        self._method = method
        self._status = status
        return


try:
    FixBurpExceptions()
except Exception:
    pass
