var jwt = require('jsonwebtoken');
var unless = require('express-unless');
var restify = require('restify');

module.exports = function(options) {
  if (!options || !options.secret) throw new Error('secret should be set');

  var _userProperty = options.userProperty || 'user';
  var middleware = function(req, res, next) {
    var token;

    if (req.method === 'OPTIONS' && req.headers.hasOwnProperty('access-control-request-headers')) {
      var hasAuthInAccessControl = !!~req.headers['access-control-request-headers']
                                    .split(',').map(function (header) {
                                      return header.trim();
                                    }).indexOf('authorization');

      if (hasAuthInAccessControl) {
        return next();
      }
    }

    if (req.headers && req.headers.authorization) {
      var parts = req.headers.authorization.split(' ');
      if (parts.length == 2) {
        var scheme = parts[0];
        var credentials = parts[1];

        if (/^Bearer$/i.test(scheme)) {
          token = credentials;
        }
      } else {
        return next(new restify.InvalidCredentialsError('Format is Authorization: Bearer [token]'));
      }
    } else if (options.credentialsRequired === false) {
      return next();
    }
    else {
      return next(new restify.errors.InvalidCredentialsError('No Authorization header was found'));
    }

    jwt.verify(token, options.secret, options, function(err, decoded) {
      if (err) return next(new restify.errors.InvalidCredentialsError(err));

      req[_userProperty] = decoded;
      next();
    });
  };

  middleware.unless = unless;

  return middleware;
};
