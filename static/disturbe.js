// Generated by CoffeeScript 1.7.1
(function() {
  var DisturbeApp, GeneratePrivateKey, InputField, SCRYPT_L, SCRYPT_N, SCRYPT_P, SCRYPT_R, a, b64encode, br, button, credentialsToSecretKey, decode_utf8, div, encode_utf8, form, h1, h2, h3, h4, h5, h6, hr, i, input, label, li, nacl, option, p, scrypt, select, span, strong, ul, _ref;

  _ref = React.DOM, a = _ref.a, br = _ref.br, button = _ref.button, div = _ref.div, form = _ref.form, hr = _ref.hr, h1 = _ref.h1, h2 = _ref.h2, h3 = _ref.h3, h4 = _ref.h4, h5 = _ref.h5, h6 = _ref.h6, i = _ref.i, input = _ref.input, label = _ref.label, li = _ref.li, p = _ref.p, option = _ref.option, select = _ref.select, span = _ref.span, strong = _ref.strong, ul = _ref.ul;

  SCRYPT_N = Math.pow(2, 14);

  SCRYPT_R = 8;

  SCRYPT_P = 1;

  SCRYPT_L = 32;

  nacl = nacl_factory.instantiate();

  scrypt = scrypt_module_factory();

  encode_utf8 = nacl.encode_utf8, decode_utf8 = nacl.decode_utf8;

  credentialsToSecretKey = function(email, password) {
    var password_hash;
    password_hash = nacl.crypto_hash_string(password);
    return scrypt.crypto_scrypt(password_hash, encode_utf8(email), SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_L);
  };

  b64encode = function(x) {
    return btoa(String.fromCharCode.apply(null, x));
  };

  DisturbeApp = React.createClass({
    getInitialState: function() {
      return {
        privateKey: null
      };
    },
    setPrivateKey: function(privateKey) {
      return this.setState({
        privateKey: privateKey
      });
    },
    render: function() {
      return div(null, this.state.privateKey != null ? div(null, b64encode(this.state.privateKey)) : GeneratePrivateKey({
        onGenerateKey: this.setPrivateKey
      }));
    }
  });

  GeneratePrivateKey = React.createClass({
    getInitialState: function() {
      return {
        email: '',
        password: ''
      };
    },
    generateKey: function(event) {
      var email, password, private_key, _base;
      email = this.state.email;
      password = this.state.password;
      private_key = credentialsToSecretKey(email, password);
      return typeof (_base = this.props).onGenerateKey === "function" ? _base.onGenerateKey(private_key) : void 0;
    },
    render: function() {
      return div({
        className: 'row'
      }, div({
        className: 'col-md-12'
      }, form({
        className: 'form-horizontal'
      }, InputField({
        type: 'text',
        label: 'Email address',
        onChange: (function(email) {
          return this.setState({
            email: email
          });
        }).bind(this)
      }), InputField({
        type: 'password',
        label: 'Password',
        onChange: (function(password) {
          return this.setState({
            password: password
          });
        }).bind(this)
      }))), div({
        className: 'form-group'
      }, div({
        className: 'col-md-12 '
      }, span(null, button({
        className: 'btn btn-success pull-right',
        onClick: this.generateKey
      }, i({
        className: 'fa fa-lock fa-fw fa-lg'
      }), 'Generate Key')))));
    }
  });

  InputField = React.createClass({
    onChange: function(event) {
      var _base;
      return typeof (_base = this.props).onChange === "function" ? _base.onChange(event.target.value) : void 0;
    },
    render: function() {
      return div({
        className: 'form-group'
      }, div({
        className: 'col-md-12'
      }, div({
        className: 'input-group margin-bottom-lg'
      }, span({
        className: 'input-group-addon'
      }, span({
        className: 'text-monospace',
        style: {
          width: '12em',
          display: 'inline-block',
          fontFamily: 'monospace'
        }
      }, this.props.label)), div(null, input({
        type: this.props.type,
        placeholder: '',
        className: 'form-control',
        onChange: this.onChange
      })))));
    }
  });

  React.renderComponent(DisturbeApp(), document.getElementById('app'));

}).call(this);
