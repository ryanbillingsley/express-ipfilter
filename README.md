IP Filter: A light-weight IP address based filtering system
=================================================================================

This package provides easy IP based access control. This can be achieved either by blacklisting certain IPs and whitelisting all others, or whitelisting certain IPs and blacklisting all others.

[![Build Status](https://secure.travis-ci.org/Dwolla/node-ipfilter.png?branch=master)](http://travis-ci.org/Dwolla/node-ipfilter)

## Version
0.0.4

## Requirements
- [Node](http://github.com/ry/node)

## Installation

Recommended installation is with npm. To add node-ipfilter to your project, do:

    npm install ipfilter

## Usage with Express

Blacklisting certain IP addresses, while allowing all other IPs:

```javascript
// Init dependencies
var express = require('express')
    , ipfilter = require('ipfilter')
    , app = express.createServer()
    ;

// Blacklist the following IPs
var ips = ['127.0.0.1'];

// Create the server
app.use(ipfilter(ips));
app.listen(3000);
```

Whitelisting certain IP addresses, while denying all other IPs:

```javascript
// Init dependencies
var express = require('express')
    , ipfilter = require('ipfilter')
    , app = express.createServer()
    ;

// Blacklist the following IPs
var ips = ['127.0.0.1'];

// Create the server
app.use(ipfilter(ips, {mode: 'allow'}));
app.listen(3000);
```

## Changelog

0.0.4

* Add tests
* Update docs
* Refactor, and restyle

0.0.1

* First revision

## Credits

Michael Schonfeld &lt;michael@dwolla.com&gt;

## License 

(The MIT License)

Copyright (c) 2012 Dwolla &lt;michael@dwolla.com&gt;

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.