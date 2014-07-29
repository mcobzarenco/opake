{a, br, button, div, form, hr, h1, h2, h3, h4, h5, h6, i, input,
  label, li, p, option, select, span, strong, ul} = React.DOM


### Json CurveCP Protocol Constants ###

SERVER_PUBLIC_KEY = 'kC_rSIO7t1ryhux1sn_LrtTrLyVZNd08BCXnSHQjgmA='
SERVER_DOMAIN_NAME = 'curvech.at'

HELLO_URL = '/handshake/hello'
HELLO_PADDING_BYTES = 64
HELLO_CLIENT_TRANSIENT_PKEY_FIELD = 'client_tpkey'
HELLO_PADDING_FIELD = 'padding'
HELLO_ZEROS_BOX_FIELD = 'zeros_box'

INITIATE_URL = '/handshake/initiate'
INITIATE_CLIENT_TRANSIENT_PKEY_FIELD = HELLO_CLIENT_TRANSIENT_PKEY_FIELD
INITIATE_COOKIE_FIELD = 'cookie'
INITIATE_VOUCH_FIELD = 'vouch'

VOUCH_CLIENT_PKEY_FIELD = 'client_pkey'
VOUCH_TRANSIENT_KEY_BOX_FIELD = 'transient_key_box'
VOUCH_DOMAIN_NAME_FIELD = 'domain_name'
VOUCH_MESSAGE_FIELD = 'message'


### Crypto Constants ###

BOX_NONCE_BYTES = 24

SCRYPT_N = Math.pow(2, 14)
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_L = 32


nacl = nacl_factory.instantiate()
scrypt = scrypt_module_factory()
{encode_utf8, decode_utf8} = nacl


credentialsToSecretKey = (email, password) ->
  password_hash = nacl.crypto_hash_string password
  scrypt.crypto_scrypt(password_hash, encode_utf8(email),
    SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_L)


concatBuffers = (x, y) ->
  z = new Uint8Array(x.byteLength + y.byteLength);
  z.set new Uint8Array(x), 0
  z.set new Uint8Array(y), x.byteLength
  z


b64encode = (arr) ->
  base64Str = btoa String.fromCharCode.apply(null, arr)
  base64Str.replace(/\+/g, '-').replace(/\//g, '_')


b64decode = (base64Str) ->
  base64DecToArr base64Str.replace(/-/g, '+').replace(/_/g, '/')


sendHello = (transientKeys, success, error) ->
  serverPublicKey = b64decode SERVER_PUBLIC_KEY
  zeros = new Uint8Array(HELLO_PADDING_BYTES)
  nonce = nacl.crypto_box_random_nonce()
  zerosBox = nacl.crypto_box zeros, nonce, serverPublicKey, transientKeys.boxSk
  noncedZerosBox = concatBuffers nonce, zerosBox

  payload = {}
  payload[HELLO_CLIENT_TRANSIENT_PKEY_FIELD] = b64encode transientKeys.boxPk
  payload[HELLO_PADDING_FIELD] = b64encode Uint8Array(HELLO_PADDING_BYTES)
  payload[HELLO_ZEROS_BOX_FIELD] = b64encode noncedZerosBox
  $.ajax
    type: 'POST'
    url: HELLO_URL
    data: JSON.stringify payload
    contentType: 'application/json'
    dataType: 'json'
    error: (xhr) -> error xhr
    success: (data, status, xhr) ->
      cookie_box = b64decode data.cookie_box
      cookie_box_nonce = cookie_box.subarray 0, BOX_NONCE_BYTES
      cookie_box_cipher = cookie_box.subarray BOX_NONCE_BYTES
      cookie = JSON.parse decode_utf8 nacl.crypto_box_open(
        cookie_box_cipher, cookie_box_nonce, serverPublicKey, transientKeys.boxSk)
      success b64decode(cookie.server_tpkey), cookie.cookie


sendInitiate = (userKeys, transientKeys, serverTPKey,
  cookie, message, success, error) ->
  serverPublicKey = b64decode SERVER_PUBLIC_KEY

  transientKeyNonce = nacl.crypto_box_random_nonce()
  transientKeyBox = nacl.crypto_box(
    transientKeys.boxPk, transientKeyNonce, serverPublicKey, userKeys.boxSk)
  noncedTransientKeyBox = concatBuffers transientKeyNonce, transientKeyBox

  vouch = {}
  vouch[VOUCH_CLIENT_PKEY_FIELD] = b64encode userKeys.boxPk
  vouch[VOUCH_TRANSIENT_KEY_BOX_FIELD] = b64encode noncedTransientKeyBox
  vouch[VOUCH_DOMAIN_NAME_FIELD] = SERVER_DOMAIN_NAME
  vouch[VOUCH_MESSAGE_FIELD] = message
  vouchBuffer = encode_utf8 JSON.stringify vouch

  vouchNonce = nacl.crypto_box_random_nonce()
  vouchBox = nacl.crypto_box(
    vouchBuffer, vouchNonce, serverTPKey, transientKeys.boxSk)
  noncedVouchBox = concatBuffers vouchNonce, vouchBox

  payload = {}
  payload[INITIATE_CLIENT_TRANSIENT_PKEY_FIELD] = b64encode transientKeys.boxPk
  payload[INITIATE_COOKIE_FIELD] = cookie
  payload[INITIATE_VOUCH_FIELD] = b64encode noncedVouchBox
  $.ajax
    type: 'POST'
    url: INITIATE_URL
    data: JSON.stringify payload
    contentType: 'application/json'
    dataType: 'json'
    error: (xhr) -> error xhr
    success: (data, status, xhr) ->
      response_box = b64decode data.response
      response_box_nonce = response_box.subarray 0, BOX_NONCE_BYTES
      response_box_cipher = response_box.subarray BOX_NONCE_BYTES
      response = decode_utf8 nacl.crypto_box_open(
        response_box_cipher, response_box_nonce, serverTPKey, transientKeys.boxSk)
      success response


sendMessage = (userKeys, message) ->
  transientKeys = nacl.crypto_box_keypair()
  serverPublicKey = b64decode SERVER_PUBLIC_KEY
  sendHello transientKeys,
    (serverTPKey, cookie) ->
      console.log serverTPKey
      console.log cookie
      message = {'alabama': 123}
      sendInitiate(userKeys, transientKeys, serverTPKey, cookie, message,
        (response) -> console.log response
        (xhr) -> alert xhr.responseText
      )
    (xhr) -> alert xhr.responseText


retrieveUserData = (userKeys, success, error) ->
  transientKeys = nacl.crypto_box_keypair()
  serverPublicKey = b64decode SERVER_PUBLIC_KEY

  zeros = new Uint8Array(HELLO_PADDING_BYTES)
  nonce = nacl.crypto_box_random_nonce()
  zerosBox = nacl.crypto_box zeros, nonce, serverPublicKey, transientKeys.boxSk
  noncedZerosBox = concatBuffers nonce, zerosBox
  $.ajax
    type: 'POST'
    url: HELLO_URL
    data: JSON.stringify
      client_tpkey: b64encode transientKeys.boxPk
      padding: b64encode Uint8Array(HELLO_PADDING_BYTES)
      zeros_box: b64encode noncedZerosBox
    contentType: 'application/json'
    dataType: 'json'
    error: -> alert(
      'Auch! The source cannot be created at the moment. ' +
      'Please try again or contact us at support@reinfer.io')
    success: (data, status, xhr) -> success(data)

DisturbeApp = React.createClass
  getInitialState: ->
    userKeys: null

  setPrivateKey: (privateKey) ->
    userKeys = nacl.crypto_box_keypair_from_raw_sk privateKey
    this.setState userKeys: userKeys
    #retrieveUserData userKeys, this.setUserData, (error) -> alert error
    sendMessage userKeys

  setUserData: (userData) ->
    console.log userData

  render: ->
    div null,
      if this.state.userKeys?
        KeyCabinet userKeys: this.state.userKeys
      else
        GeneratePrivateKey onGenerateKey: this.setPrivateKey


KeyCabinet = React.createClass
  render: ->
    div className: 'row',
      div className: 'col-md-12',
        form className: 'form-horizontal',
          InputField
            type: 'text'
            label: span className: 'text-monospace', 'Public Key'
            inputClass: 'text-monospace'
            value: b64encode this.props.userKeys.boxPk
          InputField
            type: 'text'
            label: span className: 'text-monospace', 'Secret Key'
            inputClass: 'text-monospace'
            value: b64encode this.props.userKeys.boxSk


GeneratePrivateKey = React.createClass
  getInitialState: ->
    email: ''
    password: ''

  generateKey: (event) ->
    email = this.state.email
    password = this.state.password
    private_key = credentialsToSecretKey email, password
    this.props.onGenerateKey? private_key

  render: ->
    div className: 'row',
      div className: 'col-md-12',
        form className: 'form-horizontal',
          InputField
            type: 'text'
            label: span className: 'text-monospace', 'Email address'
            inputClass: 'text-monospace'
            onChange: ((email) -> this.setState email: email).bind this
          InputField
            type: 'password',
            label: span className: 'text-monospace', 'Password'
            inputClass: 'text-monospace'
            onChange: ((password) -> this.setState password: password).bind this
      div className: 'form-group',
        div className: 'col-md-12 ',
          span null,
            button className: 'btn btn-success pull-right',
            onClick: this.generateKey, 'Generate Key'


  # email = 'marius@gmail.com'
    # password = 'anaaremere'
    # private_key = credentialsToSecretKey(email, password)

    # div null,
    #   div null, 'CollectEmail: ' + b64encode(private_key)


InputField = React.createClass
  onChange: (event) -> this.props.onChange? event.target.value

  render: ->
    inputProps =
      type: this.props.type
      placeholder: ''
      value: this.props.value
      className: 'form-control'
      onChange: this.onChange
    if this.props.value? then inputProps.value = this.props.value
    if this.props.inputClass?
      inputProps.className += ' ' + this.props.inputClass

    div className: 'form-group',
      div className: 'col-md-12',
        div className: 'input-group margin-bottom-lg',
          span className: 'input-group-addon',
            span style: {width: '12em', display: 'inline-block'},
            this.props.label
          div null,
            input inputProps


React.renderComponent DisturbeApp(), document.getElementById('app')
