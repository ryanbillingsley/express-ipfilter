/*global describe, it, after, before, beforeEach, afterEach*/

var
ipfilter = require('./index'),
assert = require('assert');

describe('enforcing IP address blacklist restrictions', function(){

  beforeEach(function(){
    this.ipfilter = ipfilter([ '127.0.0.1' ], { log: false });
    this.req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    };
  });

  it('should allow all non-blacklisted ips', function( done ){
    this.req.connection.remoteAddress = '127.0.0.2';
    this.ipfilter( this.req, {}, function(){
      done();
    });
  });

  it('should allow all non-blacklisted forwarded ips', function( done ){
    this.req.headers['x-forwarded-for'] = '127.0.0.2';
    this.ipfilter( this.req, {}, function(){
      done();
    });
  });

  it('should deny all blacklisted ips', function( done ){
    this.req.connection.remoteAddress = '127.0.0.1';
    var res = {
      end: function(msg){
        assert.equal( 401, res.statusCode );
        done();
      }
    };

    this.ipfilter( this.req, res, function(){});
  });

  it('should deny all blacklisted forwarded ips', function( done ){
    this.req.headers['x-forwarded-for'] = '127.0.0.1';
    var res = {
      end: function(msg){
        assert.equal( 401, res.statusCode );
        done();
      }
    };

    this.ipfilter( this.req, res, function(){});
  });
});

describe('enforcing IP address whitelist restrictions', function(){

  beforeEach(function(){
    this.ipfilter = ipfilter([ '127.0.0.1' ], { log: false, mode: 'allow' });
    this.req = {
      session: {},
      headers: [],
      connection: {
        remoteAddress: ''
      }
    };
  });

  it('should allow whitelisted ips', function( done ){
    this.req.connection.remoteAddress = '127.0.0.1';
    this.ipfilter( this.req, {}, function(){
      done();
    });
  });

  it('should allow whitelisted forwarded ips', function( done ){
    this.req.headers['x-forwarded-for'] = '127.0.0.1';
    this.ipfilter( this.req, {}, function(){
      done();
    });
  });

  it('should allow whitelisted port ips',function(done){
    this.req.connection.remoteAddress = '127.0.0.1:84849';
    this.ipfilter( this.req, {}, function(){
      done();
    });
  });

  it('should deny all non-whitelisted ips', function( done ){
    this.req.connection.remoteAddress = '127.0.0.2';
    var res = {
      end: function(msg){
        assert.equal( 401, res.statusCode );
        done();
      }
    };

    this.ipfilter( this.req, res, function(){});
  });

  it('should deny all non-whitelisted forwarded ips', function( done ){
    this.req.headers['x-forwarded-for'] = '127.0.0.2';
    var res = {
      end: function(msg){
        assert.equal( 401, res.statusCode );
        done();
      }
    };

    this.ipfilter( this.req, res, function(){});
  });
});

describe('using cidr block',function(){
  describe('enforcing whitelist restrictions',function(){
    beforeEach(function(){
      // Ip range: 127.0.0.1 - 127.0.0.14
      this.ipfilter = ipfilter([ '127.0.0.1/28' ], { cidr: true, log: false, mode: 'allow' });
      this.req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      };
    });

    it('should allow whitelisted ips', function( done ){
      this.req.connection.remoteAddress = '127.0.0.1';
      this.ipfilter( this.req, {}, function(){
        done();
      });
    });

    it('should allow whitelisted forwarded ips', function( done ){
      this.req.headers['x-forwarded-for'] = '127.0.0.1';
      this.ipfilter( this.req, {}, function(){
        done();
      });
    });

    it('should deny all non-whitelisted ips', function( done ){
      this.req.connection.remoteAddress = '127.0.0.17';
      var res = {
        end: function(msg){
          assert.equal( 401, res.statusCode );
          done();
        }
      };

      this.ipfilter( this.req, res, function(){});
    });

    it('should deny all non-whitelisted forwarded ips', function( done ){
      this.req.headers['x-forwarded-for'] = '127.0.0.17';
      var res = {
        end: function(msg){
          assert.equal( 401, res.statusCode );
          done();
        }
      };

      this.ipfilter( this.req, res, function(){});
    });
  });

  describe('enforcing IP address blacklist restrictions', function(){

    beforeEach(function(){
      this.ipfilter = ipfilter([ '127.0.0.1/28' ], { cidr: true, log: false });
      this.req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      };
    });

    it('should allow all non-blacklisted ips', function( done ){
      this.req.connection.remoteAddress = '127.0.0.17';
      this.ipfilter( this.req, {}, function(){
        done();
      });
    });

    it('should allow all non-blacklisted forwarded ips', function( done ){
      this.req.headers['x-forwarded-for'] = '127.0.0.17';
      this.ipfilter( this.req, {}, function(){
        done();
      });
    });

    it('should deny all blacklisted ips', function( done ){
      this.req.connection.remoteAddress = '127.0.0.1';
      var res = {
        end: function(msg){
          assert.equal( 401, res.statusCode );
          done();
        }
      };

      this.ipfilter( this.req, res, function(){});
    });

    it('should deny all blacklisted forwarded ips', function( done ){
      this.req.headers['x-forwarded-for'] = '127.0.0.1';
      var res = {
        end: function(msg){
          assert.equal( 401, res.statusCode );
          done();
        }
      };

      this.ipfilter( this.req, res, function(){});
    });
  });

  describe("enforcing private ip restrictions",function(){
    beforeEach(function(){
      this.ipfilter = ipfilter([ '127.0.0.1/28' ], { cidr: true, log: false, allowPrivateIPs: true });
      this.req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      };
    });

    it('should allow all private ips', function( done ){
      this.req.connection.remoteAddress = '10.0.0.0';
      this.ipfilter( this.req, {}, function(){
        done();
      });
    });
  });
});

describe('using ranges',function(){
  describe('enforcing whitelist restrictions',function(){
    beforeEach(function(){
      // Ip range: 127.0.0.1 - 127.0.0.14
      this.ipfilter = ipfilter([ ['127.0.0.1','127.0.0.3'] ], { ranges: true, log: false, mode: 'allow' });
      this.req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      };
    });

    it('should allow whitelisted ips', function( done ){
      this.req.connection.remoteAddress = '127.0.0.1';
      this.ipfilter( this.req, {}, function(){
        done();
      });
    });

    it('should allow whitelisted ips with port numbers', function( done ){
      this.req.connection.remoteAddress = '127.0.0.1:93923';
      this.ipfilter( this.req, {}, function(){
        done();
      });
    });

    it('should allow whitelisted forwarded ips', function( done ){
      this.req.headers['x-forwarded-for'] = '127.0.0.1';
      this.ipfilter( this.req, {}, function(){
        done();
      });
    });

    it('should deny all non-whitelisted ips', function( done ){
      this.req.connection.remoteAddress = '127.0.0.17';
      var res = {
        end: function(msg){
          assert.equal( 401, res.statusCode );
          done();
        }
      };

      this.ipfilter( this.req, res, function(){});
    });

    it('should deny all non-whitelisted forwarded ips', function( done ){
      this.req.headers['x-forwarded-for'] = '127.0.0.17';
      var res = {
        end: function(msg){
          assert.equal( 401, res.statusCode );
          done();
        }
      };

      this.ipfilter( this.req, res, function(){});
    });
  });

  describe('enforcing ip restrictions with only one ip in the range',function(){
    beforeEach(function(){
      // Ip range: 127.0.0.1 - 127.0.0.14
      this.ipfilter = ipfilter([ ['127.0.0.1'] ], { ranges: true, log: false, mode: 'allow' });
      this.req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      };
    });

    it('should allow whitelisted ips', function( done ){
      this.req.connection.remoteAddress = '127.0.0.1';
      this.ipfilter( this.req, {}, function(){
        done();
      });
    });

    it('should deny all non-whitelisted ips', function( done ){
      this.req.connection.remoteAddress = '127.0.0.17';
      var res = {
        end: function(msg){
          assert.equal( 401, res.statusCode );
          done();
        }
      };

      this.ipfilter( this.req, res, function(){});
    });
  });

  describe('enforcing IP address blacklist restrictions', function(){

    beforeEach(function(){
      this.ipfilter = ipfilter([ ['127.0.0.1','127.0.0.3'] ], { ranges: true, log: false });
      this.req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      };
    });

    it('should allow all non-blacklisted ips', function( done ){
      this.req.connection.remoteAddress = '127.0.0.17';
      this.ipfilter( this.req, {}, function(){
        done();
      });
    });

    it('should allow all non-blacklisted forwarded ips', function( done ){
      this.req.headers['x-forwarded-for'] = '127.0.0.17';
      this.ipfilter( this.req, {}, function(){
        done();
      });
    });

    it('should deny all blacklisted ips', function( done ){
      this.req.connection.remoteAddress = '127.0.0.1';
      var res = {
        end: function(msg){
          assert.equal( 401, res.statusCode );
          done();
        }
      };

      this.ipfilter( this.req, res, function(){});
    });

    it('should deny all blacklisted forwarded ips', function( done ){
      this.req.headers['x-forwarded-for'] = '127.0.0.1';
      var res = {
        end: function(msg){
          assert.equal( 401, res.statusCode );
          done();
        }
      };

      this.ipfilter( this.req, res, function(){});
    });
  });

  describe("enforcing private ip restrictions",function(){
    beforeEach(function(){
      this.ipfilter = ipfilter([ ['127.0.0.1','127.0.0.3'] ], { ranges: true, log: false, allowPrivateIPs: true });
      this.req = {
        session: {},
        headers: [],
        connection: {
          remoteAddress: ''
        }
      };
    });

    it('should allow all private ips', function( done ){
      this.req.connection.remoteAddress = '10.0.0.0';
      this.ipfilter( this.req, {}, function(){
        done();
      });
    });
  });
});
