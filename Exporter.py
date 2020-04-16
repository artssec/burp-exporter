"""
      __  ___  __   __   ___  __  
 /\  |__)  |  /__` /__` |__  /  ` 
/~~\ |  \  |  .__/ .__/ |___ \__, 

Security without imagination is a vulnerability.

Author: ArtsSEC
Site: https://artssec.com

Title: Burp Suite exporter extension
About: Exporter is a Burp Suite extension to copy a request to the clipboard as multiple programming languages functions.

Version: 0.2

Changelog:

  0.2: Add python-readable exceptions. Thanks @securityMB

  0.1: First public version
  
"""

from burp import IBurpExtender, IContextMenuFactory
from java.util import ArrayList
from javax.swing import JMenuItem, JMenu
from java.io import PrintWriter
from java.awt.datatransfer import StringSelection
from java.awt import Toolkit
import json

# python-readable exceptions
# Original code: https://raw.githubusercontent.com/securityMB/burp-exceptions/master/exceptions_fix.py
# Burp Exceptions Fix magic code
import sys, functools, inspect, traceback

def decorate_function(original_function):
    @functools.wraps(original_function)
    def decorated_function(*args, **kwargs):
        try:
            return original_function(*args, **kwargs)
        except:
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


class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):

        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Exporter")
        self._callbacks.registerContextMenuFactory(self)

        return

    def createMenuItems(self, invocation):
        self._context = invocation
        menuList = ArrayList()

        invocation_allowed = [invocation.CONTEXT_MESSAGE_EDITOR_REQUEST, invocation.CONTEXT_PROXY_HISTORY,
                              invocation.CONTEXT_TARGET_SITE_MAP_TABLE]
        if self._context.getInvocationContext() in invocation_allowed and len(self._context.selectedMessages) == 1:
            parentMenu = JMenu('Exporter to')

            menuItemPythonRequest = JMenuItem("Python Request", actionPerformed=self.asPythonRequest)
            menuItemCURL = JMenuItem("cURL", actionPerformed=self.asCURL)
            menuItemWget = JMenuItem("Wget", actionPerformed=self.asWget)
            menuItemPhpRequest = JMenuItem("PHP HTTP_Request2", actionPerformed=self.asPHPRequest)
            menuItemGo = JMenuItem("GO Native", actionPerformed=self.asGO)
            menuItemNodeRequest = JMenuItem("NodeJS Request", actionPerformed=self.asNodeJSRequest)
            menuItemJQueryAjax = JMenuItem("jQuery AJAX", actionPerformed=self.asJQueryAjax)
            menuItemPowerShell = JMenuItem("PowerShell", actionPerformed=self.asPowerShell)
            menuItemPerl = JMenuItem("Perl LWP", actionPerformed=self.asPerl)

            parentMenu.add(menuItemCURL)
            parentMenu.add(menuItemWget)
            parentMenu.add(menuItemPythonRequest)
            parentMenu.add(menuItemPerl)
            parentMenu.add(menuItemPhpRequest)
            parentMenu.add(menuItemGo)
            parentMenu.add(menuItemNodeRequest)
            parentMenu.add(menuItemJQueryAjax)
            parentMenu.add(menuItemPowerShell)

            menuList.add(parentMenu)

        # Request info
        iRequestInfo = self._helpers.analyzeRequest(self._context.getSelectedMessages()[0])
        self.headers = iRequestInfo.getHeaders()
        self.parameters = iRequestInfo.getParameters()
        self.method = iRequestInfo.getMethod()
        self.contentType = iRequestInfo.getContentType()
        self.url = iRequestInfo.getUrl().toString()
        self.payload = ''.join(map(chr, self._context.getSelectedMessages()[0].getRequest())).split('\r\n\r\n')[1]

        return menuList

    def asPythonRequest(self, event):
        headers = dict(item.split(': ') for item in self.headers[1:])
        payload = self.payload.replace("\n", "").replace("\t", "").replace('"', '\\"')
        to_copy = '''import requests

url = "{url}"

payload = "{payload}"
headers = {headers}

response = requests.request("{method}", url, data=payload, headers=headers)

print(response.text)'''.format(url=self.url, payload=payload, method=self.method, headers=json.dumps(headers, indent=4))  # noqa

        # Copy to clipboard
        s = StringSelection(to_copy)
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(s, s)

    def asCURL(self, event):
        headers = dict(item.split(': ') for item in self.headers[1:])
        formatted_headers = ' \\\n'.join(["--header '" + i + ": " + headers.get(i) + "'" for i in headers])
        to_copy = "curl -i -s -k --location --request {method} '{url}' \\\n{headers} \\\n--data-raw '{payload}'".format(method=self.method, url=self.url, headers=formatted_headers, payload=self.payload)  # noqa

        # Copy to clipboard
        s = StringSelection(to_copy)
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(s, s)

    def asWget(self, event):
        headers = dict(item.split(': ') for item in self.headers[1:])
        formatted_headers = ' \\\n'.join(["--header '" + i + ": " + headers.get(i) + "'" for i in headers])
        payload = self.payload.replace('"', '\\"')
        to_copy = '''wget --no-check-certificate --quiet \\\n--method {method} --timeout=0 \\\n--body-data '{payload}' \\\n{headers} \\\n{url}'''.format(url=self.url, payload=payload, method=self.method, headers=formatted_headers)  # noqa

        # Copy to clipboard
        s = StringSelection(to_copy)
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(s, s)

    def asPHPRequest(self, event):
        def formatPhpMethod(method):
            common_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']
            return 'HTTP_Request2::METHOD_' + method if method in common_methods else method

        headers = dict(item.split(': ') for item in self.headers[1:])
        formatted_headers = ',\n'.join(["  '" + i + "' => '" + headers.get(i) + "'" for i in headers])
        payload = self.payload.replace("\n", "").replace("\t", "")
        to_copy = '''<?php
require_once 'HTTP/Request2.php';
$request = new HTTP_Request2();
$request->setUrl('{url}');
$request->setMethod({method});
$request->setConfig(array(
  'follow_redirects' => TRUE
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
}}'''.format(url=self.url, payload=payload, method=formatPhpMethod(self.method), headers=formatted_headers)  # noqa

        # Copy to clipboard
        s = StringSelection(to_copy)
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(s, s)

    def asGO(self, event):
        headers = dict(item.split(': ') for item in self.headers[1:])
        formatted_headers = '\n  '.join(["req.Header.Add(\"" + i + "\", \"" + headers.get(i) + "\")" for i in headers])
        payload = self.payload.replace("\n", "").replace("\t", "").replace('"', '\\"')
        to_copy = '''package main

import (
  "fmt"
  "strings"
  "net/http"
  "io/ioutil"
)

func main() {{

  url := "{url}"
  method := "{method}"

  payload := strings.NewReader("{payload}")

  client := &http.Client {{
  }}
  req, err := http.NewRequest(method, url, payload)

  if err != nil {{
    fmt.Println(err)
  }}
  {headers}

  res, err := client.Do(req)
  defer res.Body.Close()
  body, err := ioutil.ReadAll(res.Body)

  fmt.Println(string(body))
}}'''.format(url=self.url, payload=payload, method=self.method, headers=formatted_headers)  # noqa

        # Copy to clipboard
        s = StringSelection(to_copy)
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(s, s)

    def asNodeJSRequest(self, event):
        headers = dict(item.split(': ') for item in self.headers[1:])
        formatted_headers = '\n    '.join(["'" + i + "': '" + headers.get(i) + "'," for i in headers])
        payload = self.payload.replace("\n", "").replace("\t", "")
        to_copy = '''var request = require('request');
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

        # Copy to clipboard
        s = StringSelection(to_copy)
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(s, s)

    def asJQueryAjax(self, event):
        headers = dict(item.split(': ') for item in self.headers[1:])
        formatted_headers = '\n    '.join(["\"" + i + "\": \"" + headers.get(i) + "\"," for i in headers])
        payload = self.payload.replace("\n", "").replace("\t", "")
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

        # Copy to clipboard
        s = StringSelection(to_copy)
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(s, s)

    def asPowerShell(self, event):
        headers = dict(item.split(': ') for item in self.headers[1:])
        formatted_headers = '\n'.join(["$headers.Add('" + i + "', '" + headers.get(i) + "')" for i in headers])
        payload = self.payload.replace("\n", "").replace("\t", "") if self.payload else {}
        payload = payload.replace("\"", "`\"")
        to_copy = '''$headers = New-Object "System.Collections.Generic.Dictionary[[String], [String]]"
{headers}
$body = "{payload}"
$response = Invoke-RestMethod '{url}' -Method '{method}' -Headers $headers -Body $body
$response | ConvertTo-Json
'''.format(url=self.url, payload=payload, method=self.method, headers=formatted_headers)  # noqa

        # Copy to clipboard
        s = StringSelection(to_copy)
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(s, s)

    def asPerl(self, event):
        headers = dict(item.split(': ') for item in self.headers[1:])
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

            cookies = '\n'.join(["$cookies->set_cookie(0,\"" + key + "\", \"" + cookies.get(key)
                                 + "\", \"" + path + "\", \"" + url + "\");" for key in cookies])

        formatted_headers = '\n'.join(["$req->header(\"" + i + "\" => \"" + headers.get(i) + "\");" for i in headers])
        payload = self.payload.replace("\n", "").replace("\t", "").replace('"', '\\"')
        to_copy = '''use LWP::UserAgent;
use HTTP::Request::Common;
use HTTP::Cookies;

my $url = URI->new("{url}");

my $cookies = HTTP::Cookies->new();
{cookies}

my $ua = LWP::UserAgent->new();
$ua->cookie_jar($cookies);

my $req = {method} $url;
{headers}
$req->content("{payload}");
my $resp = $ua->request($req);

print "Status code : ".$resp->code."\\n";
print "Response body : ".$resp->content."\\n";

'''.format(url=self.url, payload=payload, method=self.method, headers=formatted_headers, cookies=cookies)  # noqa

        # Copy to clipboard
        s = StringSelection(to_copy)
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(s, s)


try:
    FixBurpExceptions()
except Exception:
    pass
