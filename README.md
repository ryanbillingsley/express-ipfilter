IP Filter: A light-weight IP address based filtering system
=================================================================================

## Version
0.0.3

## Requirements
- [Node](http://github.com/ry/node)

## Installation

Recommended installation is with npm. To add express-csrf to your project, do:

    npm install ipfilter

## Usage

    var express = require('express'),
        ipfilter = require('ipfilter'),
        ips = ['127.0.0.1'];

    app = express.createServer();
    app.use(ipfilter(ips));
    app.listen(3000);

## Credits

Michael Schonfeld &lt;michael@dwolla.com&gt;

## License 

(The MIT License)

Copyright (c) 2011 Dwolla &lt;michael@dwolla.com&gt;

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