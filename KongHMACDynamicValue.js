// Kong HMAC Authentication
// https://docs.konghq.com/hub/kong-inc/hmac-auth


function urlParse(url) {
    var match = url.match(/^(https?:)\/\/(([^:\/?#]*)(?::([0-9]+))?)(\/[^?#]*)(?:\?([^#]*|)(#.*|))?$/);
    return match && {
        protocol: match[1],
        host: match[2],
        hostname: match[3],
        port: match[4],
        path: match[5],
        search: match[6],
        hash: match[7]
    }
}


var KongHmacDynamicValue = function() {
    this.evaluate = function(context) {
        var request = context.getCurrentRequest();
        var url_parse = urlParse(request.getUrl());

        var headers = [];
        for (var header_name of this.headers.toLowerCase().split(' ')) {
            var header = request.getHeaderByName(header_name);
            if (!header) {
                if (header_name === 'host') {
                    headers.push('host: ' + url_parse['host']);
                    continue;
                }

                if (header_name === 'request-line') {
                    var request_line = request.getMethod() + ' ' + url_parse['path'];
                    if (url_parse['search']) {
                        request_line += '?' + url_parse['search'];
                    }
                    request_line += ' HTTP/1.1';
                    headers.push(request_line);
                    continue;
                }

                if (header_name === 'date') {
                    var now = new Date();
                    var now_utc_str = now.toUTCString();
                    request.setHeader('date', now_utc_str);
                    headers.push('date: ' + now_utc_str);
                    continue;
                }

                return 'Error: Missing Header ' + header_name;
            }
            headers.push(header_name + ': ' + header);
        }

        var signing_str = headers.join('\n');
        var digest = '';
        var CryptoJS = require('crypto-js.min.js');
        if (this.algorithm === 'hmac-sha1') {
            digest = CryptoJS.HmacSHA1(signing_str, this.secret);
        } else if (this.algorithm === 'hmac-sha256') {
            digest = CryptoJS.HmacSHA256(signing_str, this.secret);
        } else if (this.algorithm === 'hmac-sha384') {
            digest = CryptoJS.HmacSHA384(signing_str, this.secret);
        } else {
            digest = CryptoJS.HmacSHA512(signing_str, this.secret);
        }

        return 'hmac username="' + this.username + '", algorithm="' + this.algorithm + '", headers="' + this.headers + 
            '", signature="' + CryptoJS.enc.Base64.stringify(digest) + '"';
    };
    this.title = function(context) {
        return 'HMAC Auth';        
    };
    this.text = function(context) {
        return 'HMAC Auth';
    };
};


KongHmacDynamicValue.identifier = 'io.winking.PawExtensions.KongHmacDynamicValue';
KongHmacDynamicValue.title = 'HMAC Auth';
KongHmacDynamicValue.help = 'https://github.com/hallelujahs/io.winking.PawExtensions.KongHmacDynamicValue';
KongHmacDynamicValue.inputs = [
    InputField('username', 'Username', 'String'),
    InputField('secret', 'Secret', 'SecureValue'),
    InputField('algorithm', 'HMAC Algorithm', 'Select', {
        choices: {'hmac-sha1': 'hmac-sha1', 'hmac-sha256': 'hmac-sha256', 'hmac-sha384': 'hmac-sha384', 'hmac-sha512': 'hmac-sha512'}, 
        persisted: true
    }),
    InputField('headers', 'Headers for HTTP signature', 'String', {
        defaultValue: 'host date request-line', 
        placeholder: 'Header Names'
    }),
];

registerDynamicValueClass(KongHmacDynamicValue);