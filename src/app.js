(function() {
  var BOX_NONCE_BYTES, CIPHER_DECRYPT_INFO_FIELD, CIPHER_MESSAGE_FIELD, CIPHER_TRANSIENT_PKEY_FIELD, CIPHER_VERSION, CIPHER_VERSION_FIELD, CiphertextArea, ComposeMessage, CryptoTabPicker, DECRYPT_INFO_MESSAGE_INFO_FIELD, DECRYPT_INFO_SENDER_FIELD, DISTURBE_PROTO, DecryptMessage, DisturbeApp, EncryptMessage, FileSelect, GeneratePrivateKey, HELLO_CLIENT_TRANSIENT_PKEY_FIELD, HELLO_PADDING_BYTES, HELLO_PADDING_FIELD, HELLO_URL, HELLO_ZEROS_BOX_FIELD, INITIATE_CLIENT_TRANSIENT_PKEY_FIELD, INITIATE_COOKIE_FIELD, INITIATE_URL, INITIATE_VOUCH_FIELD, InputField, KEY_BASE64_BYTES, KeyProfile, KeyProfileItem, MESSAGE_INFO_KEY_FIELD, MESSAGE_INFO_NONCE_FIELD, MINIMUM_PASSWORD_ENTROPY_BITS, MessageView, OpakeProfile, PublicKeyField, RemoteMessaging, SCRYPT_L, SCRYPT_N, SCRYPT_P, SCRYPT_R, SERVER_DOMAIN_NAME, SERVER_PUBLIC_KEY, STRONG_PASSWORD_ENTROPY_BITS, SecretKeyField, TAB_CLOUD, TAB_DECRYPT, TAB_ENCRYPT, TIPJAR_ADDRESS, Tipjar, VOUCH_CLIENT_PKEY_FIELD, VOUCH_DOMAIN_NAME_FIELD, VOUCH_MESSAGE_FIELD, VOUCH_TRANSIENT_KEY_BOX_FIELD, VerifyPassword, a, b64decode, b64encode, br, button, bytesToSize, concatBuffers, credentialsToSecretKey, decodeUTF8, decryptMessage, disturbePb, div, encodeUTF8, encryptMessage, form, h1, h2, h3, h4, h5, h6, hr, i, img, input, label, li, option, p, scrypt, select, sendHello, sendInitiate, sendMessage, small, span, strong, textarea, toHex, ul, validPublicKey, _ref, _ref1;

  require.config({
    paths: {
      base64: '3rd-party/base64',
      bootstrap: 'components/bootstrap/dist/js/bootstrap',
      bootstrapTags: 'components/bootstrap-tagsinput/dist/bootstrap-tagsinput',
      bs58: '3rd-party/bs58',
      bytebuffer: 'components/bytebuffer/dist/ByteBufferAB',
      identicon5: '3rd-party/jquery.identicon5.packed',
      jquery: 'components/jquery/dist/jquery',
      Long: 'components/long/dist/Long',
      NProgress: 'components/nprogress/nprogress',
      tweetnacl: 'components/tweetnacl/nacl',
      ProtoBuf: 'components/protobuf/dist/ProtoBuf',
      react: 'components/react/react-with-addons',
      scrypt: '3rd-party/scrypt',
      zxcvbn: 'components/zxcvbn/zxcvbn'
    },
    shim: {
      bootstrap: {
        deps: ['jquery']
      },
      bootstrapTags: {
        deps: ['bootstrap']
      },
      bops: {
        exports: 'bops'
      },
      bytebuffer: {
        deps: ['Long']
      },
      identicon5: {
        deps: ['jquery']
      },
      jquery: {
        deps: [],
        exports: '$'
      },
      NProgress: {
        exports: 'NProgress'
      },
      ProtoBuf: {
        deps: ['bytebuffer', 'Long'],
        exports: 'ProtoBuf'
      },
      react: {
        deps: ['jquery']
      },
      exports: 'React',
      tweetnacl: {
        exports: 'nacl'
      },
      zxcvbn: {
        exports: 'zxcvbn'
      },
      waitSeconds: 0
    }
  });

  require(['jquery', 'NProgress', 'ProtoBuf', 'react', 'tweetnacl',
  'zxcvbn', 'bootstrap', 'bootstrapTags', 'identicon5', 'scrypt',
  'bs58', 'base64'],
  function($, NProgress, ProtoBuf, React, nacl, zxcvbn) {;

  _ref = React.DOM, a = _ref.a, br = _ref.br, button = _ref.button, div = _ref.div, form = _ref.form, hr = _ref.hr, h1 = _ref.h1, h2 = _ref.h2, h3 = _ref.h3, h4 = _ref.h4, h5 = _ref.h5, h6 = _ref.h6, i = _ref.i, img = _ref.img, input = _ref.input, label = _ref.label, li = _ref.li, p = _ref.p, option = _ref.option, select = _ref.select, span = _ref.span, small = _ref.small, strong = _ref.strong, textarea = _ref.textarea, ul = _ref.ul;


  /* Json CurveCP Protocol Constants */

  SERVER_PUBLIC_KEY = 'kC_rSIO7t1ryhux1sn_LrtTrLyVZNd08BCXnSHQjgmA=';

  SERVER_DOMAIN_NAME = 'opake.io';

  HELLO_URL = '/handshake/hello';

  HELLO_PADDING_BYTES = 64;

  HELLO_CLIENT_TRANSIENT_PKEY_FIELD = 'client_tpkey';

  HELLO_PADDING_FIELD = 'padding';

  HELLO_ZEROS_BOX_FIELD = 'zeros_box';

  INITIATE_URL = '/handshake/initiate';

  INITIATE_CLIENT_TRANSIENT_PKEY_FIELD = HELLO_CLIENT_TRANSIENT_PKEY_FIELD;

  INITIATE_COOKIE_FIELD = 'cookie';

  INITIATE_VOUCH_FIELD = 'vouch';

  VOUCH_CLIENT_PKEY_FIELD = 'client_pkey';

  VOUCH_TRANSIENT_KEY_BOX_FIELD = 'transient_key_box';

  VOUCH_DOMAIN_NAME_FIELD = 'domain_name';

  VOUCH_MESSAGE_FIELD = 'message';


  /* Encryption Constants */

  CIPHER_VERSION = 1;

  CIPHER_VERSION_FIELD = 'version';

  CIPHER_TRANSIENT_PKEY_FIELD = 'transient_pkey';

  CIPHER_DECRYPT_INFO_FIELD = 'decrypt_info';

  CIPHER_MESSAGE_FIELD = 'message';

  DECRYPT_INFO_SENDER_FIELD = 'sender';

  DECRYPT_INFO_MESSAGE_INFO_FIELD = 'message_info_box';

  MESSAGE_INFO_KEY_FIELD = 'message_key';

  MESSAGE_INFO_NONCE_FIELD = 'message_nonce';


  /* Key Derivation Constants */

  SCRYPT_N = Math.pow(2, 14);

  SCRYPT_R = 8;

  SCRYPT_P = 1;

  SCRYPT_L = 32;

  MINIMUM_PASSWORD_ENTROPY_BITS = 45;

  STRONG_PASSWORD_ENTROPY_BITS = 90;

  BOX_NONCE_BYTES = 24;

  KEY_BASE64_BYTES = 44;

  DISTURBE_PROTO = "package disturbe; message File { optional string name = 1; optional bytes contents = 2; } message Message { optional string text = 1; optional bytes sender = 2; repeated File files = 3; }";

  TIPJAR_ADDRESS = '1m3HdqrGAFxoWJE3V8vefPfnHVQAvC6EE';

  scrypt = scrypt_module_factory();

  _ref1 = nacl.util, encodeUTF8 = _ref1.encodeUTF8, decodeUTF8 = _ref1.decodeUTF8;

  disturbePb = ProtoBuf.loadProto(DISTURBE_PROTO).build('disturbe');

  credentialsToSecretKey = function(email, password) {
    var password_hash;
    password_hash = nacl.hash(decodeUTF8(password));
    return scrypt.crypto_scrypt(password_hash, decodeUTF8(email), SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_L);
  };

  concatBuffers = function(x, y) {
    var z;
    z = new Uint8Array(x.byteLength + y.byteLength);
    z.set(new Uint8Array(x), 0);
    z.set(new Uint8Array(y), x.byteLength);
    return z;
  };

  b64encode = function(arr) {
    var asString, base64Str, byte, _i, _len;
    asString = '';
    for (_i = 0, _len = arr.length; _i < _len; _i++) {
      byte = arr[_i];
      asString += String.fromCharCode(byte);
    }
    base64Str = btoa(asString);
    return base64Str.replace(/\+/g, '-').replace(/\//g, '_');
  };

  b64decode = function(base64Str) {
    return base64DecToArr(base64Str.replace(/-/g, '+').replace(/_/g, '/'));
  };

  toHex = function(arr) {
    var buf, elem, hexEncode, _i, _len;
    hexEncode = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'];
    buf = '';
    for (_i = 0, _len = arr.length; _i < _len; _i++) {
      elem = arr[_i];
      buf += hexEncode[(elem & 0xf0) >> 4];
      buf += hexEncode[elem & 0x0f];
    }
    return buf;
  };

  sendHello = function(transientKeys, success, error) {
    var nonce, noncedZerosBox, payload, serverPublicKey, zeros, zerosBox;
    serverPublicKey = b64decode(SERVER_PUBLIC_KEY);
    zeros = new Uint8Array(HELLO_PADDING_BYTES);
    nonce = nacl.randomBytes(nacl.box.nonceLength);
    zerosBox = nacl.box(zeros, nonce, serverPublicKey, transientKeys.secretKey);
    noncedZerosBox = concatBuffers(nonce, zerosBox);
    payload = {};
    payload[HELLO_CLIENT_TRANSIENT_PKEY_FIELD] = b64encode(transientKeys.publicKey);
    payload[HELLO_PADDING_FIELD] = b64encode(new Uint8Array(HELLO_PADDING_BYTES));
    payload[HELLO_ZEROS_BOX_FIELD] = b64encode(noncedZerosBox);
    return $.ajax({
      type: 'POST',
      url: HELLO_URL,
      data: JSON.stringify(payload),
      contentType: 'application/json',
      dataType: 'json',
      error: function(xhr) {
        return error(xhr);
      },
      success: function(data, status, xhr) {
        var cookie, cookie_box, cookie_box_cipher, cookie_box_nonce;
        cookie_box = b64decode(data.cookie_box);
        cookie_box_nonce = cookie_box.subarray(0, BOX_NONCE_BYTES);
        cookie_box_cipher = cookie_box.subarray(BOX_NONCE_BYTES);
        cookie = JSON.parse(encodeUTF8(nacl.box.open(cookie_box_cipher, cookie_box_nonce, serverPublicKey, transientKeys.secretKey)));
        return success(b64decode(cookie.server_tpkey), cookie.cookie);
      }
    });
  };

  sendInitiate = function(userKeys, transientKeys, serverTPKey, cookie, message, success, error) {
    var noncedTransientKeyBox, noncedVouchBox, payload, serverPublicKey, transientKeyBox, transientKeyNonce, vouch, vouchBox, vouchBuffer, vouchNonce;
    serverPublicKey = b64decode(SERVER_PUBLIC_KEY);
    transientKeyNonce = nacl.randomBytes(nacl.box.nonceLength);
    transientKeyBox = nacl.box(transientKeys.publicKey, transientKeyNonce, serverPublicKey, userKeys.secretKey);
    noncedTransientKeyBox = concatBuffers(transientKeyNonce, transientKeyBox);
    vouch = {};
    vouch[VOUCH_CLIENT_PKEY_FIELD] = b64encode(userKeys.publicKey);
    vouch[VOUCH_TRANSIENT_KEY_BOX_FIELD] = b64encode(noncedTransientKeyBox);
    vouch[VOUCH_DOMAIN_NAME_FIELD] = SERVER_DOMAIN_NAME;
    vouch[VOUCH_MESSAGE_FIELD] = message;
    vouchBuffer = decodeUTF8(JSON.stringify(vouch));
    vouchNonce = nacl.randomBytes(nacl.box.nonceLength);
    vouchBox = nacl.box(vouchBuffer, vouchNonce, serverTPKey, transientKeys.secretKey);
    noncedVouchBox = concatBuffers(vouchNonce, vouchBox);
    payload = {};
    payload[INITIATE_CLIENT_TRANSIENT_PKEY_FIELD] = b64encode(transientKeys.publicKey);
    payload[INITIATE_COOKIE_FIELD] = cookie;
    payload[INITIATE_VOUCH_FIELD] = b64encode(noncedVouchBox);
    return $.ajax({
      type: 'POST',
      url: INITIATE_URL,
      data: JSON.stringify(payload),
      contentType: 'application/json',
      dataType: 'json',
      error: error,
      success: function(data, status, xhr) {
        var response, response_box, response_box_cipher, response_box_nonce;
        response_box = b64decode(data.response);
        response_box_nonce = response_box.subarray(0, BOX_NONCE_BYTES);
        response_box_cipher = response_box.subarray(BOX_NONCE_BYTES);
        response = encodeUTF8(nacl.box.open(response_box_cipher, response_box_nonce, serverTPKey, transientKeys.secretKey));
        return success(response);
      }
    });
  };

  sendMessage = function(userKeys, message, success, error) {
    var serverPublicKey, transientKeys;
    transientKeys = nacl.box.keyPair();
    serverPublicKey = b64decode(SERVER_PUBLIC_KEY);
    return sendHello(transientKeys, function(serverTPKey, cookie) {
      return sendInitiate(userKeys, transientKeys, serverTPKey, cookie, message, success, error);
    }, error);
  };

  validPublicKey = function(key) {
    var error, valid;
    valid = false;
    try {
      if (typeof key === 'string') {
        key = b58decode(key);
      }
      if (key.length === nacl.box.publicKeyLength) {
        valid = true;
      }
    } catch (_error) {
      error = _error;
      valid = false;
    }
    return valid;
  };

  encryptMessage = function(senderKeys, recipientPublicKeys, message) {
    var cipher, decryptInfo, decryptInfoBox, messageBox, messageHash, messageInfo, messageKey, messageNonce, nonce, recipientPublicKey, secretToRecipient, transientKeys, _i, _len, _ref2;
    secretToRecipient = function(transientKeys, senderKeys, recipientPublicKey, messageInfo) {
      var decryptInfo, decryptInfoBox, messageInfoBox, nonce;
      nonce = nacl.randomBytes(nacl.box.nonceLength);
      messageInfoBox = nacl.box(messageInfo, nonce, recipientPublicKey, senderKeys.secretKey);
      decryptInfo = {};
      decryptInfo[DECRYPT_INFO_SENDER_FIELD] = b58encode(senderKeys.publicKey);
      decryptInfo[DECRYPT_INFO_MESSAGE_INFO_FIELD] = b64encode(messageInfoBox);
      decryptInfo = decodeUTF8(JSON.stringify(decryptInfo));
      decryptInfoBox = nacl.box(decryptInfo, nonce, recipientPublicKey, transientKeys.secretKey);
      return {
        nonce: nonce,
        decryptInfoBox: decryptInfoBox
      };
    };
    transientKeys = nacl.box.keyPair();
    if (typeof message === 'string') {
      message = decodeUTF8(message);
    }
    messageHash = nacl.hash(message);
    messageNonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    messageKey = nacl.randomBytes(nacl.secretbox.keyLength);
    messageBox = nacl.secretbox(message, messageNonce, messageKey);
    messageInfo = {};
    messageInfo[MESSAGE_INFO_KEY_FIELD] = b64encode(messageKey);
    messageInfo[MESSAGE_INFO_NONCE_FIELD] = b64encode(messageNonce);
    messageInfo = decodeUTF8(JSON.stringify(messageInfo));
    cipher = {};
    cipher[CIPHER_VERSION_FIELD] = CIPHER_VERSION;
    cipher[CIPHER_TRANSIENT_PKEY_FIELD] = b58encode(transientKeys.publicKey);
    cipher[CIPHER_MESSAGE_FIELD] = b64encode(messageBox);
    decryptInfo = {};
    cipher[CIPHER_DECRYPT_INFO_FIELD] = decryptInfo;
    for (_i = 0, _len = recipientPublicKeys.length; _i < _len; _i++) {
      recipientPublicKey = recipientPublicKeys[_i];
      if (recipientPublicKey.length !== nacl.box.publicKeyLength) {
        throw new Error("" + (b58encode(recipientPublicKey)) + " is not valid public key");
      }
      _ref2 = secretToRecipient(transientKeys, senderKeys, recipientPublicKey, messageInfo), nonce = _ref2.nonce, decryptInfoBox = _ref2.decryptInfoBox;
      decryptInfo[b64encode(nonce)] = b64encode(decryptInfoBox);
    }
    return JSON.stringify(cipher);
  };

  decryptMessage = function(userKeys, cipherText) {
    var box, cipher, decryptInfo, decryptInfoNonce, error, messageInfo, messageInfoBox, messageKey, messageNonce, nonceBase64, plaintext, senderPublicKey, transientPublicKey, _ref2;
    ({
      FORMAT_ERROR: 'The message is not valid.',
      CRYPTO_ERROR: 'The message could not be decrypted.'
    });
    try {
      cipher = JSON.parse(cipherText);
    } catch (_error) {
      error = _error;
      throw FORMAT_ERROR;
    }
    transientPublicKey = b58decode(cipher[CIPHER_TRANSIENT_PKEY_FIELD]);
    decryptInfo = null;
    decryptInfoNonce = null;
    _ref2 = cipher[CIPHER_DECRYPT_INFO_FIELD];
    for (nonceBase64 in _ref2) {
      box = _ref2[nonceBase64];
      try {
        decryptInfoNonce = b64decode(nonceBase64);
        decryptInfo = nacl.box.open(b64decode(box), decryptInfoNonce, transientPublicKey, userKeys.secretKey);
        break;
      } catch (_error) {
        error = _error;
      }
    }
    if (!((decryptInfo != null) && (decryptInfoNonce != null))) {
      throw GENERIC_ERROR;
    }
    decryptInfo = JSON.parse(encodeUTF8(decryptInfo));
    senderPublicKey = b58decode(decryptInfo[DECRYPT_INFO_SENDER_FIELD]);
    messageInfoBox = b64decode(decryptInfo[DECRYPT_INFO_MESSAGE_INFO_FIELD]);
    messageInfo = nacl.box.open(messageInfoBox, decryptInfoNonce, senderPublicKey, userKeys.secretKey);
    messageInfo = JSON.parse(encodeUTF8(messageInfo));
    messageKey = b64decode(messageInfo[MESSAGE_INFO_KEY_FIELD]);
    messageNonce = b64decode(messageInfo[MESSAGE_INFO_NONCE_FIELD]);
    return plaintext = {
      sender: senderPublicKey,
      message: nacl.secretbox.open(b64decode(cipher[CIPHER_MESSAGE_FIELD]), messageNonce, messageKey)
    };
  };

  bytesToSize = function(bytes, precision) {
    var gigabyte, kilobyte, megabyte, terabyte;
    if (precision == null) {
      precision = 1;
    }
    kilobyte = 1024;
    megabyte = kilobyte * 1024;
    gigabyte = megabyte * 1024;
    terabyte = gigabyte * 1024;
    if (bytes >= 0 && bytes < kilobyte) {
      return bytes + ' B';
    } else if (bytes >= kilobyte && bytes < megabyte) {
      return (bytes / kilobyte).toFixed(precision) + ' KiB';
    } else if (bytes >= megabyte && bytes < gigabyte) {
      return (bytes / megabyte).toFixed(precision) + ' MiB';
    } else if (bytes >= gigabyte && bytes < terabyte) {
      return (bytes / gigabyte).toFixed(precision) + ' GiB';
    } else if (bytes >= terabyte) {
      return (bytes / terabyte).toFixed(precision) + ' TiB';
    } else {
      return bytes + ' B';
    }
  };

  DisturbeApp = React.createClass({
    getInitialState: function() {
      return {
        userKeys: null,
        userData: null
      };
    },
    setPrivateKey: function(privateKey) {
      var userKeys;
      window.scrollTo(0, 0);
      userKeys = nacl.box.keyPair.fromSecretKey(privateKey);
      return this.setState({
        userKeys: userKeys
      });
    },
    setUserData: function(userData) {
      return this.setState({
        userData: {}
      });
    },
    onLogin: function(event) {
      return sendMessage(this.state.userKeys, {
        'method': 'get_userdata'
      }, (function(response) {
        return this.setUserData(response);
      }).bind(this), function(xhr) {
        return alert(xhr.responseText);
      });
    },
    containerWrap: function(inner) {
      return div(null, this.state.userKeys == null ? div({
        className: "github-fork-ribbon-wrapper right"
      }, div({
        className: "github-fork-ribbon"
      }, a({
        href: "https://github.com/mcobzarenco/disturbe"
      }, "Fork me on GitHub"))) : void 0, div({
        className: "container"
      }, div({
        className: "row"
      }, div({
        className: "col-md-10 col-md-offset-1"
      }, inner))));
    },
    render: function() {
      return this.containerWrap(div(null, this.state.userKeys != null ? div(null, div({
        className: 'logo'
      }, h1({
        className: 'large-bottom'
      }, 'opake', img({
        src: 'static/assets/logo.png'
      }))), div({
        className: 'row'
      }, div({
        className: 'col-md-12'
      }, h3(null, 'Profile'))), div({
        className: 'row'
      }, div({
        className: 'col-md-12 large-bottom'
      }, p(null, 'Anyone who has your opake ID can send messages that only you can decrypt.'), p(null, 'Spread your opake ID wide. The secret key you should never reveal.'))), OpakeProfile({
        userKeys: this.state.userKeys
      }), CryptoTabPicker({
        userKeys: this.state.userKeys
      })) : div(null, div({
        className: 'row'
      }, div({
        className: 'col-md-8 col-md-offset-2 large-bottom'
      }, div({
        className: 'logo'
      }, h1({
        className: 'large-bottom'
      }, 'opake', img({
        src: 'static/assets/logo.png'
      }))), GeneratePrivateKey({
        onGenerateKey: this.setPrivateKey
      }), hr(null), Tipjar({
        address: TIPJAR_ADDRESS
      }))))));
    }
  });

  TAB_ENCRYPT = 'encrypt';

  TAB_DECRYPT = 'decrypt';

  TAB_CLOUD = 'cloud';

  CryptoTabPicker = React.createClass({
    getInitialState: function() {
      return {
        selectedTab: TAB_ENCRYPT
      };
    },
    changeTab: function(tab, event) {
      event.stopPropagation();
      event.preventDefault();
      if (tab !== this.state.selectedTab) {
        return this.setState({
          selectedTab: tab
        });
      }
    },
    render: function() {
      var activeIf, changeTabTo, hiddenIfNot;
      activeIf = (function(tab) {
        return "" + (this.state.selectedTab === tab ? 'active' : '');
      }).bind(this);
      changeTabTo = (function(tab) {
        return this.changeTab.bind(this, tab);
      }).bind(this);
      hiddenIfNot = (function(tab) {
        if (this.state.selectedTab === tab) {
          return '';
        } else {
          return 'hidden';
        }
      }).bind(this);
      return div(null, div({
        className: 'row'
      }, div({
        className: 'col-md-12'
      }, ul({
        className: 'nav nav-tabs nav-justified',
        role: 'tablist',
        style: {
          marginTop: '2em',
          marginBottom: '1.2em',
          width: '100%'
        }
      }, li({
        className: activeIf(TAB_ENCRYPT)
      }, a({
        href: "#" + TAB_ENCRYPT,
        onClick: changeTabTo(TAB_ENCRYPT)
      }, i({
        className: 'fa fa-lock nav-icon'
      }), div({
        className: 'nav-label'
      }, 'Encrypt'))), li({
        className: activeIf(TAB_DECRYPT)
      }, a({
        href: "#" + TAB_DECRYPT,
        onClick: changeTabTo(TAB_DECRYPT)
      }, i({
        className: 'fa fa-unlock-alt nav-icon'
      }), div({
        className: 'nav-label'
      }, 'Decrypt')))))), div({
        className: hiddenIfNot(TAB_ENCRYPT)
      }, EncryptMessage({
        userKeys: this.props.userKeys
      })), div({
        className: hiddenIfNot(TAB_DECRYPT)
      }, DecryptMessage({
        userKeys: this.props.userKeys
      })));
    }
  });

  KeyProfile = React.createClass({
    getInitialState: function() {
      return {
        name: 'anonymous',
        email: '',
        social: ''
      };
    },
    componentDidMount: function() {
      return this.renderIdenticon(this.refs.identicon.getDOMNode());
    },
    renderIdenticon: function(elem) {
      return $(elem).identicon5({
        size: 80
      });
    },
    render: function() {
      return div(null, h3({
        className: 'media-heading'
      }, 'Public Key Profile'), div({
        className: 'media'
      }, span({
        className: 'pull-left',
        href: '#'
      }, div({
        className: 'media-object',
        ref: 'identicon'
      }, toHex(nacl.hash(this.props.publicKey)))), div({
        className: 'media-body'
      }, KeyProfileItem({
        name: 'Key',
        value: b58encode(this.props.publicKey, {
          iconClass: 'fa-key',
          editable: false
        })
      }), KeyProfileItem({
        name: 'Name',
        value: this.state.name,
        iconClass: 'fa-user',
        editable: true
      }), KeyProfileItem({
        name: 'Email',
        value: this.state.email,
        iconClass: 'fa-envelope-o',
        editable: true
      }), KeyProfileItem({
        name: 'Social',
        value: this.state.social,
        iconClass: 'fa-share-alt',
        editable: true
      }))));
    }
  });

  KeyProfileItem = React.createClass({
    componentDidMount: function() {
      var editable;
      editable = this.props.editable != null ? this.props.editable : false;
      if (editable) {
        return $(this.refs[this.props.name].getDOMNode()).editable({
          type: 'text',
          pk1: 1,
          title: 'enter name',
          showbuttons: false
        });
      }
    },
    render: function() {
      var icon, valueClass;
      icon = '';
      if (this.props.iconClass != null) {
        icon = i({
          className: "fa " + this.props.iconClass + " fa-fw text-muted"
        });
      }
      valueClass = '';
      if (this.props.editable) {
        valueClass = 'editable editable-click';
      }
      return div({
        className: 'user-profile-item'
      }, icon, span(null, "" + this.props.name + ": "), span({
        className: valueClass,
        ref: this.props.name,
        href: '#'
      }, this.props.value));
    }
  });

  EncryptMessage = React.createClass({
    getInitialState: function() {
      return {
        ciphertext: null
      };
    },
    clear: function() {
      return this.setState(this.getInitialState());
    },
    render: function() {
      return div(null, this.state.ciphertext == null ? div(null, div({
        className: 'row'
      }, div({
        className: 'col-md-12 large-bottom'
      }, h3(null, 'Compose an encrypted message'), p(null, 'Only the owners of the opake IDs you specify will be able to decrypt it.'))), ComposeMessage({
        userKeys: this.props.userKeys,
        onEncrypt: (function(ciphertext) {
          return this.setState({
            ciphertext: ciphertext
          });
        }).bind(this)
      })) : div(null, div({
        className: 'row'
      }, div({
        className: 'col-md-12 large-bottom'
      }, h3(null, 'Encrypted message'))), CiphertextArea({
        ciphertext: this.state.ciphertext
      }), hr(null), div({
        className: 'row'
      }, div({
        className: 'col-md-12'
      }, p(null, 'Compose a ', a({
        onClick: this.clear,
        style: {
          cursor: 'pointer'
        }
      }, 'new message'))))));
    }
  });

  ComposeMessage = React.createClass({
    getInitialState: function() {
      return {
        recipients: [],
        message: '',
        files: []
      };
    },
    getInvalidRecipientKeys: function() {
      var invalid, recipient, _i, _len, _ref2;
      invalid = [];
      _ref2 = this.state.recipients;
      for (_i = 0, _len = _ref2.length; _i < _len; _i++) {
        recipient = _ref2[_i];
        if (!recipient.valid) {
          invalid.push(recipient.key);
        }
      }
      return invalid;
    },
    componentDidMount: function() {
      var innerInput, recipientsNode;
      recipientsNode = $(this.refs.recipients.getDOMNode());
      recipientsNode.tagsinput({
        tagClass: (function(key) {
          var labelClass, recipient, recipients;
          recipients = this.state.recipients.slice(0);
          recipient = {
            key: key
          };
          if (validPublicKey(key)) {
            labelClass = 'label label-primary';
            recipient.valid = true;
          } else {
            labelClass = 'label label-danger';
            recipient.valid = false;
          }
          recipients.push(recipient);
          this.setState({
            recipients: recipients
          });
          return labelClass;
        }).bind(this),
        trimValue: true
      });
      recipientsNode.on('itemRemoved', (function(event) {
        var index, recipient, recipients, _i, _len, _ref2;
        index = -1;
        _ref2 = this.state.recipients;
        for (index = _i = 0, _len = _ref2.length; _i < _len; index = ++_i) {
          recipient = _ref2[index];
          if (recipient.key === event.item) {
            break;
          }
        }
        if (index !== -1) {
          recipients = this.state.recipients.slice(0);
          recipients.splice(index, 1);
          return this.setState({
            recipients: recipients
          });
        }
      }).bind(this));
      innerInput = $(recipientsNode.tagsinput('input'));
      innerInput.addClass('form-control');
      innerInput.css({
        width: ''
      });
      return $(this.refs.inputFiles.getDOMNode()).on('change', this.updateFiles);
    },
    updateFiles: function(event) {
      var file, files, _i, _len, _ref2;
      files = this.state.files.slice(0);
      _ref2 = event.target.files;
      for (_i = 0, _len = _ref2.length; _i < _len; _i++) {
        file = _ref2[_i];
        files.push(file);
      }
      return this.setState({
        files: files
      });
    },
    changeMessage: function(event) {
      return this.setState({
        message: event.target.value
      });
    },
    encryptBinary: function(recipientKeys, plaintext) {
      var ciphertext, error;
      try {
        ciphertext = encryptMessage(this.props.userKeys, recipientKeys, plaintext);
        NProgress.done();
        this.props.onEncrypt(ciphertext);
        return ciphertext;
      } catch (_error) {
        error = _error;
        return console.log(error);
      }
    },
    encryptMessage: function(event) {
      var error, file, fileReader, key, message, recipientKeys, recipientNode, _i, _len, _ref2, _results;
      event.preventDefault();
      NProgress.start();
      recipientNode = $(this.refs.recipients.getDOMNode());
      recipientKeys = (function() {
        var _i, _len, _ref2, _results;
        _ref2 = $(recipientNode).val().split(',');
        _results = [];
        for (_i = 0, _len = _ref2.length; _i < _len; _i++) {
          key = _ref2[_i];
          _results.push(b58decode(key));
        }
        return _results;
      })();
      try {
        if (this.props.onEncrypt != null) {
          message = new disturbePb.Message({
            text: this.state.message
          });
          message.files = [];
          if (this.state.files.length === 0) {
            this.encryptBinary(recipientKeys, new Uint8Array(message.toArrayBuffer()));
          }
          _ref2 = this.state.files;
          _results = [];
          for (_i = 0, _len = _ref2.length; _i < _len; _i++) {
            file = _ref2[_i];
            fileReader = new FileReader();
            fileReader.onloadend = (function(file, reader) {
              NProgress.inc(0.1);
              message.files.push({
                name: file.name,
                contents: reader.result
              });
              if (message.files.length === this.state.files.length) {
                return this.encryptBinary(recipientKeys, new Uint8Array(message.toArrayBuffer()));
              }
            }).bind(this, file, fileReader);
            _results.push(fileReader.readAsArrayBuffer(file));
          }
          return _results;
        }
      } catch (_error) {
        error = _error;
        return console.log(error);
      }
    },
    render: function() {
      var encryptButtonProps, error, file, invalidJoined, invalidRecipients;
      error = null;
      invalidRecipients = this.getInvalidRecipientKeys();
      if (invalidRecipients.length > 0) {
        invalidJoined = "" + (invalidRecipients.join(', '));
        if (invalidRecipients.length === 1) {
          error = "" + invalidJoined + " is not a valid opake ID";
        } else {
          error = "" + invalidJoined + " are not valid opake IDs";
        }
      }
      encryptButtonProps = {
        className: 'btn btn-success',
        onClick: this.encryptMessage
      };
      if ((error != null) || this.state.recipients.length === 0) {
        encryptButtonProps.disabled = 'true';
      }
      return div(null, form({
        className: 'form-horizontal'
      }, error != null ? div({
        className: 'form-group'
      }, div({
        className: 'col-xs-12'
      }, span({
        className: 'text-danger'
      }, error))) : void 0, div({
        className: 'form-group'
      }, div({
        className: 'col-xs-12',
        style: {
          display: 'inline-block'
        }
      }, label({
        className: 'control-label'
      }, 'Recipients'), input({
        className: 'form-control',
        type: 'text',
        defaultValue: '',
        ref: 'recipients'
      }))), div({
        className: 'form-group'
      }, div({
        className: 'col-xs-12',
        style: {
          display: 'inline-block'
        }
      }, label({
        className: 'control-label'
      }, 'Message'), textarea({
        className: 'form-control',
        value: this.state.message,
        placeholder: 'Type your message..',
        onChange: this.changeMessage,
        rows: 10
      }))), this.state.files.length > 0 ? div({
        className: 'form-group'
      }, div({
        className: 'col-md-12'
      }, (function() {
        var _i, _len, _ref2, _results;
        _ref2 = this.state.files;
        _results = [];
        for (_i = 0, _len = _ref2.length; _i < _len; _i++) {
          file = _ref2[_i];
          _results.push(span({
            className: 'label label-default attached-file'
          }, span(null, file.name), span(null, " [" + (bytesToSize(file.size)) + "] "), i({
            className: 'fa fa-fw fa-lg fa-times dismiss-icon',
            onClick: (function(file) {
              var files, index;
              files = this.state.files.slice(0);
              index = files.indexOf(file);
              files.splice(index, 1);
              return this.setState({
                files: files
              });
            }).bind(this, file)
          })));
        }
        return _results;
      }).call(this))) : void 0, div({
        className: 'form-group'
      }, div({
        className: 'col-md-12 large-bottom'
      }, input({
        style: {
          display: 'none'
        },
        type: 'file',
        ref: 'inputFiles',
        multiple: 'true'
      }), a({
        className: 'control-label',
        style: {
          cursor: 'pointer'
        },
        onClick: (function(event) {
          event.preventDefault();
          return $(this.refs.inputFiles.getDOMNode()).trigger('click');
        }).bind(this)
      }, i({
        className: 'fa fa-fw fa-lg fa-plus'
      }), 'Add files'), div({
        className: 'pull-right'
      }, button(encryptButtonProps, i({
        className: 'fa fa-fw fa-lock'
      }), span(null, 'Encrypt')))))));
    }
  });

  CiphertextArea = React.createClass({
    MAX_CIPHER_LENGTH: 50 * 1024,
    selectCiphertext: function(event) {
      var ciphertext;
      event.preventDefault();
      ciphertext = this.refs.ciphertext.getDOMNode();
      ciphertext.focus();
      return ciphertext.setSelectionRange(0, ciphertext.value.length);
    },
    isCipherDisplayable: function() {
      return this.props.ciphertext.length < this.MAX_CIPHER_LENGTH;
    },
    render: function() {
      var blob, copyButtonProps, cx, downloadUrl, textareaValue;
      blob = new Blob([this.props.ciphertext]);
      downloadUrl = (window.webkitURL || window.URL).createObjectURL(blob);
      cx = React.addons.classSet;
      copyButtonProps = {
        className: 'btn btn-default',
        onClick: this.selectCiphertext
      };
      if (!this.isCipherDisplayable()) {
        copyButtonProps.disabled = 'true';
      }
      textareaValue = '<< The encrypted message is too large to be displayed inline >>';
      if (this.isCipherDisplayable()) {
        textareaValue = this.props.ciphertext;
      }
      return form({
        className: 'form-horizontal'
      }, div({
        className: 'form-group share-cipher-bar'
      }, div({
        className: 'col-xs-12'
      }, label({
        className: 'control-label'
      }, 'Share'), div(null, button(copyButtonProps, i({
        className: 'fa fa-copy fa-lg fa-fw'
      }), 'Copy'), a({
        className: 'btn btn-default',
        href: downloadUrl,
        download: 'message.cipher',
        onClick: this.downloadCiphertext
      }, i({
        className: 'fa fa-download fa-lg fa-fw'
      }), 'Download')))), div({
        className: 'form-group'
      }, div({
        className: 'col-xs-12',
        style: {
          display: 'inline-block'
        }
      }, label({
        className: 'control-label'
      }, 'Encrypted message'), textarea({
        className: 'form-control',
        ref: 'ciphertext',
        value: textareaValue,
        readOnly: true,
        rows: 5,
        style: {
          backgroundColor: 'white',
          cursor: 'auto'
        }
      }))));
    }
  });

  DecryptMessage = React.createClass({
    FORMAT_ERROR: 'The message is not valid.',
    CRYPTO_ERROR: 'The message could not be decrypted.',
    getInitialState: function() {
      return {
        ciphertext: '',
        error: null,
        message: null
      };
    },
    clear: function() {
      return this.setState(this.getInitialState());
    },
    changeCiphertext: function(event) {
      return this.setState({
        ciphertext: event.target.value
      });
    },
    decryptFile: function(files) {
      var fileReader;
      fileReader = new FileReader();
      fileReader.onloadend = (function() {
        console.log(fileReader);
        return this.decryptMessage(fileReader.result);
      }).bind(this);
      return fileReader.readAsText(files[0]);
    },
    decryptMessage: function(ciphertext) {
      var error, message, plaintext;
      try {
        NProgress.start();
        plaintext = decryptMessage(this.props.userKeys, ciphertext);
        message = disturbePb.Message.decode(plaintext.message);
        message.sender = plaintext.sender;
        NProgress.done();
        return this.setState({
          message: message
        });
      } catch (_error) {
        error = _error;
        console.log(error);
        return this.setState({
          error: this.CRYPTO_ERROR
        });
      }
    },
    render: function() {
      return div(null, div({
        className: 'row'
      }, div({
        className: 'col-md-12 large-bottom'
      }, h3(null, 'Decrypt a message'), p(null, 'You can only decrypt a message that was encrypted for your opake ID.'))), this.state.message == null ? form({
        className: 'form-horizontal'
      }, this.state.error != null ? div({
        className: 'form-group'
      }, div({
        className: 'col-xs-12'
      }, span({
        className: 'text-danger'
      }, this.state.error))) : void 0, div({
        className: 'form-group'
      }, div({
        className: 'col-xs-12'
      }, label({
        className: 'control-label'
      }, 'From file'), div({
        style: {
          marginTop: '.5em'
        }
      }, FileSelect({
        onChange: this.decryptFile,
        ref: 'cipherFile'
      }), button({
        className: 'btn btn-success',
        style: {
          width: '12em'
        },
        onClick: (function(event) {
          event.preventDefault();
          return this.refs.cipherFile.selectFiles();
        }).bind(this)
      }, i({
        className: 'fa fa-fw fa-lg fa-file-o'
      }), span(null, 'Decrypt a file'))))), div({
        className: 'form-group'
      }, div({
        className: 'col-xs-12'
      }, label({
        className: 'control-label'
      }, 'From encrypted message'), textarea({
        className: 'form-control',
        value: this.state.message,
        placeholder: 'Copy paste the encrypted message..',
        onChange: this.changeCiphertext,
        rows: 5
      }))), div({
        className: 'row'
      }, div({
        className: 'col-md-12 large-bottom'
      }, button({
        className: 'btn btn-success',
        style: {
          width: '12em'
        },
        onClick: (function(event) {
          event.preventDefault();
          return this.decryptMessage(this.state.ciphertext);
        }).bind(this)
      }, i({
        className: 'fa fa-fw fa-lg fa-unlock-alt'
      }), span(null, 'Decrypt text'))))) : div(null, MessageView({
        message: this.state.message
      }), hr(null), div({
        className: 'row'
      }, div({
        className: 'col-md-12'
      }, p(null, 'Decrypt ', a({
        onClick: this.clear,
        style: {
          cursor: 'pointer'
        }
      }, 'another message'))))));
    }
  });

  MessageView = React.createClass({
    render: function() {
      var blob, buffer, file, limit, offset, url;
      return form({
        className: 'form-horizontal'
      }, div({
        className: 'form-group'
      }, div({
        className: 'col-xs-12',
        style: {
          display: 'inline-block'
        }
      }, label({
        className: 'control-label'
      }, 'From'), input({
        className: 'form-control',
        value: b58encode(this.props.message.sender, {
          readOnly: true,
          style: {
            backgroundColor: 'white',
            cursor: 'auto'
          }
        })
      }))), div({
        className: 'form-group'
      }, div({
        className: 'col-xs-12',
        style: {
          display: 'inline-block'
        }
      }, label({
        className: 'control-label'
      }, 'Message'), textarea({
        className: 'form-control',
        value: this.props.message.text,
        readOnly: true,
        rows: 10,
        style: {
          backgroundColor: 'white',
          cursor: 'auto'
        }
      }))), div({
        className: 'form-group'
      }, div({
        className: 'col-md-12'
      }, (function() {
        var _i, _len, _ref2, _ref3, _results;
        _ref2 = this.props.message.files;
        _results = [];
        for (_i = 0, _len = _ref2.length; _i < _len; _i++) {
          file = _ref2[_i];
          _ref3 = file.contents, buffer = _ref3.buffer, offset = _ref3.offset, limit = _ref3.limit;
          blob = new Blob([buffer.slice(offset, limit)]);
          url = (window.webkitURL || window.URL).createObjectURL(blob);
          _results.push(span({
            className: 'label label-default attached-file'
          }, span(null, file.name), span(null, " [" + (bytesToSize(limit - offset)) + "] "), a({
            href: url,
            download: file.name
          }, i({
            className: 'fa fa-fw fa-lg fa-download dismiss-icon'
          }))));
        }
        return _results;
      }).call(this))));
    }
  });

  FileSelect = React.createClass({
    componentDidMount: function() {
      if (this.props.onChange != null) {
        return $(this.refs.inputFiles.getDOMNode()).on('change', (function(event) {
          return this.props.onChange(event.target.files);
        }).bind(this));
      }
    },
    selectFiles: function() {
      return $(this.refs.inputFiles.getDOMNode()).trigger('click');
    },
    render: function() {
      return input({
        style: {
          display: 'none'
        },
        type: 'file',
        ref: 'inputFiles'
      });
    }
  });

  OpakeProfile = React.createClass({
    SIZE_COLLAPSED: 60,
    SIZE_EXPANDED: 120,
    getInitialState: function() {
      return {
        collapsed: false
      };
    },
    componentDidMount: function() {
      return this.renderIdenticon(this.refs.identicon.getDOMNode());
    },
    renderIdenticon: function(elem) {
      var size;
      size = this.state.collapsed ? this.SIZE_COLLAPSED : this.SIZE_EXPANDED;
      return $(elem).identicon5({
        size: size
      });
    },
    render: function() {
      return div(null, div({
        className: 'row'
      }, div({
        className: 'col-sm-2 hidden-xs'
      }, span({
        className: '',
        href: '#'
      }, span({
        className: 'text-muted'
      }, 'Fingerprint'), div({
        ref: 'identicon',
        style: {
          marginTop: '1em',
          marginRight: '1em'
        }
      }, toHex(nacl.hash(this.props.userKeys.publicKey))))), div({
        className: 'col-sm-10'
      }, PublicKeyField({
        publicKey: this.props.userKeys.publicKey
      }), SecretKeyField({
        secretKey: this.props.userKeys.secretKey
      }))));
    }
  });

  PublicKeyField = React.createClass({
    getInitialState: function() {
      return {
        shown: false
      };
    },
    componentDidMount: function() {
      return this.renderIdenticon(this.refs.identicon.getDOMNode());
    },
    renderIdenticon: function(elem) {
      return $(elem).identicon5({
        size: 28
      });
    },
    onCopyPublicKey: function(event) {
      var inputNode;
      event.preventDefault();
      inputNode = this.refs.inputPublicKey.getDOMNode();
      inputNode.focus();
      return inputNode.setSelectionRange(0, inputNode.value.length);
    },
    onTweet: function(event) {
      var tweet_text;
      event.preventDefault();
      tweet_text = "http://opake.io is zero knowledge messaging with end to end encryption. My opake ID is " + (b58encode(this.props.publicKey));
      return window.open("https://twitter.com/intent/tweet?text=" + encodeURIComponent(tweet_text));
    },
    render: function() {
      var inputProps;
      inputProps = {
        type: 'text',
        readOnly: true,
        className: 'form-control text-monospace',
        placeholder: '',
        value: b58encode(this.props.publicKey),
        style: {
          backgroundColor: 'white',
          cursor: 'auto'
        },
        ref: 'inputPublicKey',
        onClick: this.onCopyPublicKey
      };
      return div({
        style: {
          paddingBottom: '1em'
        }
      }, label({
        className: 'control-label',
        style: {
          fontSize: '1.3em',
          marginTop: '0em'
        }
      }, "Opake ID"), div({
        className: 'input-group input-group-lg'
      }, span({
        className: 'input-group-btn hidden-sm hidden-md hidden-lg inline-fingerprint'
      }, span({
        ref: 'identicon'
      }, toHex(nacl.hash(this.props.publicKey)))), input(inputProps), span({
        className: 'input-group-btn hidden-xs'
      }, button({
        className: 'btn btn-default',
        onClick: this.onCopyPublicKey,
        ref: 'clipboardButton'
      }, i({
        className: 'fa fa-copy fa-lg'
      }))), span({
        className: 'input-group-btn'
      }, button({
        className: 'btn btn-default',
        onClick: this.onTweet
      }, i({
        className: 'fa fa-twitter fa-lg'
      })))));
    }
  });

  SecretKeyField = React.createClass({
    getInitialState: function() {
      return {
        shown: false
      };
    },
    onShow: function(event) {
      var hideKey, newState;
      event.preventDefault();
      newState = {
        shown: !this.state.shown
      };
      if (newState.shown) {
        hideKey = (function() {
          return this.setState({
            shown: false
          });
        }).bind(this);
        newState.timeoutId = window.setTimeout(hideKey, 5000);
      } else if (this.state.timeoutId != null) {
        window.clearTimeout(this.state.timeoutId);
      }
      return this.setState(newState);
    },
    render: function() {
      var classNames, inputProps, value;
      classNames = 'form-control text-monospace';
      if (this.state.shown) {
        value = b58encode(this.props.secretKey);
      } else {
        classNames += ' text-muted';
        value = '<< Hidden >>';
      }
      inputProps = {
        className: classNames,
        type: 'text',
        readOnly: true,
        placeholder: '',
        value: value,
        style: {
          backgroundColor: 'white',
          cursor: 'auto'
        }
      };
      return div({
        style: {
          paddingBottom: '1em'
        }
      }, label({
        className: 'control-label',
        style: {
          fontSize: '1.3em'
        }
      }, 'Secret Key'), div({
        className: 'input-group input-group-lg'
      }, input(inputProps), span({
        className: 'input-group-btn'
      }, button({
        className: 'btn btn-default',
        onClick: this.onShow
      }, this.state.shown ? 'Hide' : 'Show'))));
    }
  });

  RemoteMessaging = React.createClass({
    getInitialState: function() {
      return {
        userData: null
      };
    },
    setUserData: function(userData) {
      return this.setState({
        userData: {}
      });
    },
    login: function(event) {
      return sendMessage(this.props.userKeys, {
        'method': 'get_userdata'
      }, (function(response) {
        return this.setUserData(response);
      }).bind(this), function(xhr) {
        return alert(xhr.responseText);
      });
    },
    render: function() {
      return div({
        className: 'row'
      }, div({
        className: 'col-md-12'
      }, button({
        className: 'btn btn-success',
        onClick: this.login
      }, "Sign in with opake ID")));
    }
  });

  GeneratePrivateKey = React.createClass({
    getInitialState: function() {
      return {
        email: '',
        password: '',
        validPassword: false
      };
    },
    generateKey: function(event) {
      var email, password, private_key, _base;
      event.preventDefault();
      email = this.state.email;
      password = this.state.password;
      private_key = credentialsToSecretKey(email, password);
      return typeof (_base = this.props).onGenerateKey === "function" ? _base.onGenerateKey(private_key) : void 0;
    },
    render: function() {
      var deriveButtonProps;
      deriveButtonProps = {
        className: 'btn btn-lg btn-success pull-right',
        onClick: this.generateKey
      };
      if (!this.state.validPassword) {
        deriveButtonProps.disabled = 'true';
      }
      return div({
        className: 'row'
      }, div({
        className: 'col-md-12'
      }, form({
        className: 'form-horizontal'
      }, div({
        className: 'row'
      }, div({
        className: 'col-md-12'
      }, h3(null, 'Derive your opake ID'), p(null, 'Your email and password are used to generate a unique pair of keys.'), p(null, 'The credentials do not leave your device and are never stored.'))), div({
        style: {
          marginTop: '1em'
        }
      }, InputField({
        type: 'text',
        label: 'Email',
        placeholder: 'Your email address',
        onChange: (function(email) {
          return this.setState({
            email: email
          });
        }).bind(this)
      }), InputField({
        type: 'password',
        label: 'Password',
        placeholder: 'Your strong password',
        onChange: (function(password) {
          return this.setState({
            password: password
          });
        }).bind(this)
      })), div({
        className: 'row'
      }, div({
        className: 'col-md-12'
      }, VerifyPassword({
        password: this.state.password,
        onUpdate: (function(valid) {
          return this.setState({
            validPassword: valid
          });
        }).bind(this)
      }))), div({
        className: 'form-group'
      }, div({
        className: 'col-md-12 '
      }, button(deriveButtonProps, 'Derive your opake ID'))))));
    }
  });

  VerifyPassword = React.createClass({
    getInitialState: function() {
      return {
        verifyPassword: ''
      };
    },
    componentDidUpdate: function() {
      return this.props.onUpdate(this.validPassword);
    },
    shouldComponentUpdate: function(nextProps, nextState) {
      return !(nextState.verifyPassword === this.state.verifyPassword && nextProps.password === this.props.password);
    },
    render: function() {
      var entropyClass, message, messageClass, passwordStats;
      passwordStats = zxcvbn(this.props.password);
      this.validPassword = true;
      messageClass = '';
      message = '';
      if (passwordStats.entropy < MINIMUM_PASSWORD_ENTROPY_BITS) {
        this.validPassword = false;
        message = 'Your password is not strong enough, it must to have at' + (" least " + MINIMUM_PASSWORD_ENTROPY_BITS + " bits of entropy.");
        messageClass = 'text-danger';
      } else if (passwordStats.entropy < STRONG_PASSWORD_ENTROPY_BITS) {
        messageClass = 'text-warning';
      } else {
        messageClass = 'text-success';
      }
      entropyClass = messageClass + ' password-entropy';
      if (this.state.verifyPassword.length > 0 && this.props.password !== this.state.verifyPassword) {
        if (message === '') {
          this.validPassword = false;
          messageClass = 'text-danger';
          message = 'Passwords do not match.';
        }
      } else if (message === '') {
        message = 'Everything is OK';
      }
      return div(null, div({
        className: 'row'
      }, div({
        className: 'col-md-12'
      }, div({
        className: 'password-entropy',
        style: {
          display: 'inline-block'
        }
      }, 'Entropy: ', span({
        className: entropyClass
      }, "" + passwordStats.entropy + " bits")))), div({
        className: "row"
      }, div({
        className: "col-md-12"
      }, p(null, "Your password needs to have high entropy to generate high quality keys."))), div({
        style: {
          marginBottom: "1em"
        }
      }, InputField({
        type: 'password',
        label: 'Check (optional)',
        placeholder: 'Retype password (optional)',
        onChange: (function(password) {
          return this.setState({
            verifyPassword: password
          });
        }).bind(this)
      })), div({
        className: 'row'
      }, div({
        className: 'col-md-12 large-bottom'
      }, p({
        className: messageClass
      }, message))));
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
        placeholder: this.props.placeholder,
        value: this.props.value,
        className: 'form-control input-lg',
        onChange: this.onChange
      };
      if (this.props.value != null) {
        inputProps.value = this.props.value;
      }
      if (this.props.inputClass != null) {
        inputProps.className += ' ' + this.props.inputClass;
      }
      return div({
        className: 'form-group'
      }, div({
        className: 'col-xs-12',
        style: {
          display: 'inline-block'
        }
      }, label({
        className: 'control-label'
      }, this.props.label), input(inputProps)));
    }
  });

  Tipjar = React.createClass({
    render: function() {
      return div(null, div({
        className: 'row large-bottom'
      }, div({
        className: 'col-md-12'
      }, h5(null, 'Bitcoin Tip Jar'), small(null, 'If you found this service useful and would like to support it, you can donate BTCs at the address below.'))), div({
        className: 'row large-bottom'
      }, div({
        className: 'col-md-12'
      }, div({
        className: 'input-group'
      }, div({
        className: 'input-group-addon'
      }, i({
        className: 'fa fa-btc fa-lg'
      })), input({
        className: 'form-control',
        type: 'text',
        value: this.props.address,
        readOnly: true,
        style: {
          backgroundColor: 'white',
          cursor: 'auto'
        }
      })))), div({
        className: 'row'
      }, div({
        className: 'col-md-12'
      }, small(null, 'The money will be used to pay for hosting, support further development as well as fund a comprehensive code audit.'))));
    }
  });

  $(function() {
    $('#loader').hide();
    return React.renderComponent(DisturbeApp(), document.getElementById('app'));
  });

  });;

}).call(this);
