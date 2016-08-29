'use strict';

function IpDeniedError(message) {
  this.name = 'IpDenied';
  this.message = message || 'The requesting IP was denied';
  this.stack = new Error().stack;
}

IpDeniedError.prototype = Object.create(Error.prototype);
IpDeniedError.prototype.constructor = IpDeniedError;

module.exports = IpDeniedError;
//# sourceMappingURL=deniedError.js.map
