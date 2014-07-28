// Generated by CoffeeScript 1.7.1
(function() {
  var DisturbeApp, GeneratePrivateKey, InputField, KeyCabinet, SCRYPT_L, SCRYPT_N, SCRYPT_P, SCRYPT_R, a, b64encode, br, button, credentialsToSecretKey, decode_utf8, div, encode_utf8, form, h1, h2, h3, h4, h5, h6, hr, i, input, label, li, nacl, option, p, scrypt, select, span, strong, ul, _ref;

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
        userKeys: null
      };
    },
    setPrivateKey: function(privateKey) {
      var userKeys;
      userKeys = nacl.crypto_box_keypair_from_raw_sk(privateKey);
      return this.setState({
        userKeys: userKeys
      });
    },
    render: function() {
      return div(null, this.state.userKeys != null ? KeyCabinet({
        userKeys: this.state.userKeys
      }) : GeneratePrivateKey({
        onGenerateKey: this.setPrivateKey
      }));
    }
  });

  KeyCabinet = React.createClass({
    render: function() {
      return div({
        className: 'row'
      }, div({
        className: 'col-md-12'
      }, form({
        className: 'form-horizontal'
      }, InputField({
        type: 'text',
        label: span({
          className: 'text-monospace'
        }, 'Public Key'),
        value: b64encode(this.props.userKeys.boxPk)
      }), InputField({
        type: 'text',
        label: span({
          className: 'text-monospace'
        }, 'Secret Key'),
        value: b64encode(this.props.userKeys.boxSk)
      }))));
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
        label: span({
          className: 'text-monospace'
        }, 'Email address'),
        onChange: (function(email) {
          return this.setState({
            email: email
          });
        }).bind(this)
      }), InputField({
        type: 'password',
        label: span({
          className: 'text-monospace'
        }, 'Password'),
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
      }, 'Generate Key')))));
    }
  });

  InputField = React.createClass({
    onChange: function(event) {
      var _base;
      return typeof (_base = this.props).onChange === "function" ? _base.onChange(event.target.value) : void 0;
    },
    render: function() {
      var inputProps;
      inputProps = {
        type: this.props.type,
        placeholder: '',
        value: this.props.value,
        className: 'form-control',
        onChange: this.onChange
      };
      if (this.props.value != null) {
        inputProps.value = this.props.value;
      }
      console.log(inputProps.value);
      return div({
        className: 'form-group'
      }, div({
        className: 'col-md-12'
      }, div({
        className: 'input-group margin-bottom-lg'
      }, span({
        className: 'input-group-addon'
      }, span({
        style: {
          width: '12em',
          display: 'inline-block'
        }
      }, this.props.label)), div(null, input(inputProps)))));
    }
  });

  React.renderComponent(DisturbeApp(), document.getElementById('app'));

}).call(this);
