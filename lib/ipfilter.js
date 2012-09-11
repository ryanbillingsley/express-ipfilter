/*!
 * Dwolla - IP Filter
 * Copyright(c) 2012 Dwolla Inc.
 * MIT Licensed
 */


/**
 * Module dependencies.
 */
var _ = require('underscore');


/**
 * node-ipfilter:
 *
 * IP Filtering middleware; 
 *
 * Examples:
 *
 *      var ipfilter = require('ipfilter'),
 *          ips = ['127.0.0.1'];
 *
 *      app.use(ipfilter(ips));
 *
 * Options:
 *
 *  - `mode` whether to deny or grant access to the IPs provided . Defaults to 'deny'.
 *  - `log` console log actions. Defaults to true.
 *  - `errorCode` the HTTP status code to use when denying access. Defaults to 401.
 *  - `errorMessage` the error message to use when denying access. Defaults to 'Unauthorized'.
 *
 * @param [Array] IP addresses
 * @param {Object} options
 * @api public
 */
module.exports = function ipfilter(ips, opts) {
  ips = ips || false;

  var settings = _.defaults( opts || {}, {
  			mode: 'deny'
  			, log: true
  			, errorCode: 401
  			, errorMessage: 'Unauthorized'
      })
      , getClientIp = function(req) {
        var ipAddress;
  
        var forwardedIpsStr = req.headers['x-forwarded-for'];
  
        if (forwardedIpsStr) {
          var forwardedIps = forwardedIpsStr.split(',');
          ipAddress = forwardedIps[0];
        }
  
        if (!ipAddress) {
          ipAddress = req.connection.remoteAddress;
        }
  
        return ipAddress;
      }
      ;
  
	return function(req, res, next) {
		// If no IPs were specified, skip
		// this middleware
		if(!ips || !ips.length) { return next(); }

		var ip = getClientIp(req) // Grab the client's IP address
		    , mode = settings.mode.toLowerCase() // Normalize mode
		    ;

		if((mode == 'allow' && ips.indexOf(ip) !== -1) || (mode == 'deny' && ips.indexOf(ip) === -1)) {
			// Grant access
			if(settings.log) {
				console.log('Access granted to IP address: ' + ip);
			}

			return next();
		}

		// Deny access
		if(settings.log) {
			console.log('Access denied to IP address: ' + ip);
		}

		res.statusCode = settings.errorCode;
		return res.end(settings.errorMessage);
	}
};