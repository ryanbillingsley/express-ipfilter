express-ipfilter: A light-weight IP address based filtering system
=================================================================================

This package provides easy IP based access control. This can be achieved either by blacklisting certain IPs and whitelisting all others, or whitelisting certain IPs and blacklisting all others.

[![Circle CI](https://circleci.com/gh/baminteractive/express-ipfilter/tree/master.svg?style=svg)](https://circleci.com/gh/baminteractive/express-ipfilter/tree/master)

## Version
0.0.25

## Installation

Recommended installation is with npm. To add node-ipfilter to your project, do:

    npm install express-ipfilter

## Usage with Express

Blacklisting certain IP addresses, while allowing all other IPs:

```javascript
// Init dependencies
var express = require('express')
    , ipfilter = require('express-ipfilter')
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
    , ipfilter = require('express-ipfilter')
    , app = express.createServer()
    ;

// Whitelist the following IPs
var ips = ['127.0.0.1'];

// Create the server
app.use(ipfilter(ips, {mode: 'allow'}));
app.listen(3000);
```

Using CIDR subnet masks for ranges:

```javascript
var ips = ['127.0.0.1/24'];

// Create the server
app.use(ipfilter(ips, {mode: 'allow'}));
app.listen(3000);
```

Using IP ranges:

```javascript
var ips = [['127.0.0.1','127.0.0.10']];

// Create the server
app.use(ipfilter(ips, {mode: 'allow'}));
app.listen(3000);
```

## Options

| Property      | Description   | Type  | Default|
| ------------- |-------------| -----|--------|
| mode   | whether to *deny* or *allow* to the IPs provided | string|deny|
| log   | console log actions | boolean|true|
| errorCode   | the HTTP status code to use when denying access | number|401|
| errorMessage   | the error message to use when denying access | string|Unauthorized|
| excluding   | routes that should be excluded from ip filtering | array|[]|

## Contributing

### Building from source

You can run `grunt` to build the source.  This will run `eslint` and `babel` against `src/ipfilter.js`.

There is an included `example` project that will load the package from the local build for testing.

### Running Tests

Run tests by using

`grunt test`

This will run `eslint`,`babel`, and `mocha` and output coverage data into `coverage`.  Any pull request you submit needs to be accompanied by a test.

## Changelog
0.0.24
* Added lib to version control

0.0.23
* added codio x-real-ip header

0.0.22

* Added IPv6 Support
* Added build tools
* Added test coverage and reporting

0.0.20

* Added a setting to explicitly allow CloudFlare and Forwarded IPs.  By default they are set to not allow these headers.  Thanks to @longstone!

0.0.19

* Added detection for CloudFlare forwarded ips - https://github.com/baminteractive/express-ipfilter/commit/9aa43af14f5a003bad3145eef658f429808818f9 (@lafama)

0.0.18

* Fixing bug when array of CIDR blocks are used

0.0.16

* Fixing bug when no IP address can be determined

0.0.15

* Minor bug fix

0.0.14

* Adding the ability to have exclusion urls

0.0.12

* Diagnostic Options

0.0.11

* Bug Fix for port logic

0.0.10

* Added support for IPs with port numbers

0.0.9

* Fixing deploy issues

0.0.8

* Auto deploys for npm

0.0.7

* Add support ip ranges.

0.0.6

* Fixed a bug when using console output

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
