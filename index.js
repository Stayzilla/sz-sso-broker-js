var qs      = require('querystring'),
    request = require('request'),
    crypto  = require('crypto');

function SSO(broker, secret, server)
{
    this.broker = broker;
    this.secret = secret;
    this.server = server;
}

SSO.prototype.getAttachUrl = function (token, ip, returnurl) {
    var params = {
        broker   : this.broker,
        token    : token,
        ip       : ip,
        ts       : Number(new Date()),
        checksum : null,
        returnurl: returnurl
    };

    params.checksum = crypto.createHash('sha256').update([
            'attach', params.token, params.ts, params.ip, this.secret
        ].join('')).digest('hex');

    return this.server + '/v1/attach?' + qs.stringify(params);
};

SSO.prototype.getUserInfo = function (token) {
    var that = this;
    return new Promise(function (resolve, reject) {
        request({
            url: that.server + '/v1/userinfo',
            qs: {
                session_key: getSessionKey(that.broker, token, that.secret)
            }
        }, function (err, res, body) {
            if (err) {
                return reject(err);
            }

            try {
                body = JSON.parse(body);
            } catch(e) {
                return reject(e);
            }

            resolve(body.user);
        });
    });
};

SSO.prototype.logout = function (token) {
    var that = this;
    return new Promise(function (resolve, reject) {
        request({
            url: that.server + '/v1/logout',
            method: 'post',
            qs: {
                session_key: getSessionKey(that.broker, token, that.secret)
            }
        }, function (err, res, body) {
            if (err) {
                return reject(err);
            }

            try {
                body = JSON.parse(body);
            } catch(e) {
                return reject(e);
            }

            resolve(body.success);
        });
    });
};

function getSessionKey(broker, token, secret) {
    return 'sso-' + broker + '-' + crypto.createHash('sha256').update([
            'attach', token, secret
        ].join('')).digest('hex');
}

module.exports = SSO;