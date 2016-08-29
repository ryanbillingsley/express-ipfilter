'use strict';

module.exports = function IpDeniedError(message, extra) {
  Error.captureStackTrace(this, this.constructor);
  this.name = this.constructor.name;
  this.message = message || 'The requesting IP was denied';
  this.extra = extra;
};

require('util').inherits(module.exports, Error);
//# sourceMappingURL=deniedError.js.map
