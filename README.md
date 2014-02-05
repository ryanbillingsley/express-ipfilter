IP Filter: A light-weight IP address based filtering system
=================================================================================

This package provides easy IP based access control. This can be achieved either by blacklisting certain IPs and whitelisting all others, or whitelisting certain IPs and blacklisting all others.

[![Build Status](https://secure.travis-ci.org/baminteractive/node-ipfilter.png?branch=master)](http://travis-ci.org/baminteractive/node-ipfilter)

## Version
0.0.5

## Installation

Recommended installation is with npm. To add node-ipfilter to your project, do:

    npm install express-ipfilter

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

Using CIDR subnet masks for ranges:

```javascript
// Init dependencies
var express = require('express')
    , ipfilter = require('ipfilter')
    , app = express.createServer()
    ;

// Blacklist the following IPs
var ips = ['127.0.0.1/24'];

// Create the server
app.use(ipfilter(ips, {mode: 'allow'}));
app.listen(3000);
```

## Changelog

0.0.5

* Added ability to block by subnet mask (i.e. 127.0.0.1/24)
* Added tests for cidr functionality

0.0.4

* Add tests
* Update docs
* Refactor, and restyle

0.0.1

* First revision

## Credits

BaM Interactive - [code.bamideas.com](http://code.bamideas.com)