## About
Exporter is a [Burp Suite](https://portswigger.net/burp/) extension to copy a request to the clipboard as multiple programming languages functions.
You can export as:
 - cURL
 - Wget
 - Python Request
 - Perl LWP
 - PHP HTTP_Request2
 - Go Native
 - NodeJS Request
 - jQuery AJAX
 - PowerShell

## Requirements

 - [Jython](https://www.jython.org/download) >= 2.7.1

## Burp Suite import
In Burp Suite, under the `Extender/Extensions` tab, click on the `Add` button, select Extension type `Python`  and load the `Exporter` py file.

## Usage
You can copy the request from:
 - Proxy -> Intercept
 - Proxy -> HTTP history
 - Target -> Site map
 - Repeater

Right click -> Exporter to -> ...

## Possible improvements
 - More snippets

