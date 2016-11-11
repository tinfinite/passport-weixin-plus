var url = require('url')
  , util = require('util')
  , AuthorizationError = require('passport-oauth2/lib/errors/authorizationerror')
  ;
function parse(str) {
	// Create an object with no prototype
	// https://github.com/sindresorhus/query-string/issues/47
	var ret = Object.create(null);

	if (typeof str !== 'string') {
		return ret;
	}

	str = str.trim().replace(/^(\?|#|&)/, '');

	if (!str) {
		return ret;
	}

	str.split('&').forEach(function (param) {
		var parts = param.replace(/\+/g, ' ').split('=');
		// Firefox (pre 40) decodes `%3D` to `=`
		// https://github.com/sindresorhus/query-string/pull/37
		var key = parts.shift();
		var val = parts.length > 0 ? parts.join('=') : undefined;

		key = decodeURIComponent(key);

		// missing `=` should be `null`:
		// http://w3.org/TR/2012/WD-url-20120524/#collect-url-parameters
		val = val === undefined ? null : decodeURIComponent(val);

		if (ret[key] === undefined) {
			ret[key] = val;
		} else if (Array.isArray(ret[key])) {
			ret[key].push(val);
		} else {
			ret[key] = [ret[key], val];
		}
	});

	return ret;
};

exports.authenticate = function(req, options) {
  options = options || {};
  var self = this;

  if (req.query && req.query.error) {
    if (req.query.error == 'access_denied') {
      return this.fail({
        message: req.query.error_description
      });
    } else {
      return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
    }
  }

  var callbackURL = options.callbackURL || this._callbackURL;
  if (typeof callbackURL === 'function') {
    callbackURL = callbackURL(req);
  }
  if (callbackURL) {
    var parsed = url.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(utils.originalURL(req, {
        proxy: this._trustProxy
      }), callbackURL);
    }
  }

  if (req.query && req.query.code) {
    var code = req.query.code;

    if (this._state) {
      if (!req.session) {
        return this.error(new Error('OAuth2Strategy requires session support when using state. Did you forget app.use(express.session(...))?'));
      }

      var key = this._key;
      if (!req.session[key]) {
        return this.fail({
          message: 'Unable to verify authorization request state.'
        }, 403);
      }
      var state = req.session[key].state;
      if (!state) {
        return this.fail({
          message: 'Unable to verify authorization request state.'
        }, 403);
      }

      delete req.session[key].state;
      if (Object.keys(req.session[key]).length === 0) {
        delete req.session[key];
      }

      if (state !== req.query.state) {
        return this.fail({
          message: 'Invalid authorization request state.'
        }, 403);
      }
    }
    console.log('code to get profile', code);
    var params = this.tokenParams(req, options);
    console.log('tokenparams', params);
    params.grant_type = 'authorization_code';
    params.redirect_uri = callbackURL;
    this._oauth2.getOAuthAccessToken(code, params,
      function(err, accessToken, refreshToken, params) {
        console.log('gettoken.accessToken', accessToken);
        console.log('gettoken.refreshToken', refreshToken);
        console.log('gettoken.params', params);
        if (err) {
          console.log('gettokenerr', err);
          return self.error(self._createOAuthError('Failed to obtain access token', err));
        }

        self._loadUserProfile(accessToken, params.openid, function(err, profile) {
          console.log('loaduserprofile.profile', profile);
          if (err) {
            console.log('loaduserprofile.error', err);
            return self.error(err);
          }

          function verified(err, user, info) {
            if (err) {
              return self.error(err);
            }
            if (!user) {
              return self.fail(info);
            }
            self.success(user, info);
          }

          try {
            if (self._passReqToCallback) {
              var arity = self._verify.length;
              if (arity == 6) {
                self._verify(req, accessToken, refreshToken, params, profile, verified);
              } else { // arity == 5
                self._verify(req, accessToken, refreshToken, profile, verified);
              }
            } else {
              var arity = self._verify.length;
              if (arity == 5) {
                self._verify(accessToken, refreshToken, params, profile, verified);
              } else { // arity == 4
                self._verify(accessToken, refreshToken, profile, verified);
              }
            }
          } catch (ex) {
            return self.error(ex);
          }
        });
      }
    );
  } else {
    var params = this.authorizationParams(req, options);
    params.response_type = 'code';
    params.redirect_uri = callbackURL;
    var scope = options.scope || this._scope;
    if (scope) {
      if (Array.isArray(scope)) {
        scope = scope.join(this._scopeSeparator);
      }
      params.scope = scope;
    }
    var state = options.state;
    if (state) {
      params.state = state;
    } else if (this._state) {
      if (!req.session) {
        return this.error(new Error('OAuth2Strategy requires session support when using state. Did you forget app.use(express.session(...))?'));
      }

      var key = this._key;
      state = uid(24);
      if (!req.session[key]) {
        req.session[key] = {};
      }
      req.session[key].state = state;
      params.state = state;
    }
    var location = this._oauth2.getAuthorizeUrl(params);
    console.log('location', location);
    var _location = location.substring(location.indexOf('?'));
    var _base_url= location.substring(0, location.indexOf('?') + 1);
    console.log('_location---->', _location);
    var obj = parse(_location);
    var final_url = _base_url + 'appid=' + obj['appid'] + '&redirect_uri=' + encodeURIComponent(obj['redirect_uri']) + '&response_type=' + obj['response_type'] + '&scope=' + obj['scope'] + '&state=' + obj['state'];
    console.log('final_url', final_url);
    this.redirect(final_url);
  }
};

exports._loadUserProfile = function(accessToken, openid, done) {
  var self = this;

  function loadIt() {
    return self.userProfile(accessToken, openid, done);
  }

  function skipIt() {
    return done(null);
  }

  if (typeof this._skipUserProfile == 'function' && this._skipUserProfile.length > 1) {
    // async
    this._skipUserProfile(accessToken, openid, function(err, skip) {
      if (err) {
        return done(err);
      }
      if (!skip) {
        return loadIt();
      }
      return skipIt();
    });
  } else {
    var skip = (typeof this._skipUserProfile == 'function') ? this._skipUserProfile() : this._skipUserProfile;
    if (!skip) {
      return loadIt();
    }
    return skipIt();
  }
};
