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

MINIMUM_PASSWORD_ENTROPY_BITS = 5


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

  setUserData: (userData) ->
    console.log userData

  onLogin: (event) ->
    console.log 'login'
    sendMessage this.state.userKeys

  render: ->
    div null,
      h1 className: "text-monospace large-bottom", "curvech.at"
      if this.state.userKeys?
        div null,
          div className: "row",
            div className: "col-md-12 large-bottom",
              h3 className: "text-monospace", "Keys"
              p className: "text-monospace",
              "Your keys. Anyone who has your public key can send
              messages that only you can decrypt."
              p className: "text-monospace",
                "Spread your public key wide. The secret key you
                should keep, um, secret."
          KeyCabinet userKeys: this.state.userKeys
          div className: 'row',
            div className: 'col-md-12 ',
              button className:'btn btn-success pull-right',
              onClick:this.onLogin, 'Sign in with Public Key'
      else
        GeneratePrivateKey onGenerateKey: this.setPrivateKey


KeyCabinet = React.createClass
  render: ->
    form className: 'form-horizontal',
        PublicKeyField publicKey: this.props.userKeys.boxPk
        SecretKeyField secretKey: this.props.userKeys.boxSk


PublicKeyField = React.createClass
  getInitialState: () -> shown: false

  onClipboard: (event) ->
    event.preventDefault()

  onTweet: (event) ->
    event.preventDefault()
    tweet_text = "cryptch.at is zero knowledge messaging with end to end " +
    "encryption. My public key is #{b64encode this.props.publicKey}"
    window.open("https://twitter.com/intent/tweet?text=#{tweet_text}")

  render: ->
    inputProps =
      type: 'text'
      readOnly: true
      className: 'form-control text-monospace'
      placeholder: ''
      value: b64encode this.props.publicKey
      style: {backgroundColor: 'white'}

    div className: 'form-group',
      div className: 'col-md-12', style:{display:'inline-block'},
        div className: 'input-group margin-bottom-lg',
          span className: 'input-group-addon',
            span style: {width: '12em', display: 'inline-block'},
            span className: 'text-monospace', 'Public Key'
          input inputProps
          span className: 'input-group-btn',
            button
              className: 'btn btn-default text-monospace',
              onClick: this.onClipboard,
              i className: 'fa fa-chain fa-lg'
          span className: 'input-group-btn',
            button
              className: 'btn btn-default text-monospace',
              onClick: this.onTweet,
              i className: 'fa fa-twitter fa-lg'


SecretKeyField = React.createClass
  getInitialState: () -> shown: false

  onShow: (event) ->
    event.preventDefault()
    newState = shown: not this.state.shown
    if newState.shown
      hideKey = (() -> this.setState shown: false).bind(this)
      newState.timeoutId = window.setTimeout hideKey, 5000
    else if this.state.timeoutId?
      window.clearTimeout this.state.timeoutId
    this.setState newState

  render: ->
    classNames = 'form-control text-monospace'
    if this.state.shown
      value = b64encode this.props.secretKey
    else
      classNames += ' text-muted'
      value = '<< Hidden >>'

    inputProps =
      className: classNames
      type: 'text'
      readOnly: true
      placeholder: ''
      value: value
      style: {backgroundColor: 'white'}

    div className: 'form-group',
      div className: 'col-md-12', style:{display:'inline-block'},
        div className: 'input-group margin-bottom-lg',
          span className: 'input-group-addon',
            span style: {width: '12em', display: 'inline-block'},
            span className: 'text-monospace', 'Secret Key'
          input inputProps
          span className: 'input-group-btn',
            button
              className: 'btn btn-default text-monospace',
              onClick: this.onShow,
              if this.state.shown then 'Hide' else 'Show'


GeneratePrivateKey = React.createClass
  getInitialState: ->
    validNewKey: false
    email: ''
    password: ''

  generateKey: (event) ->
    email = this.state.email
    password = this.state.password
    private_key = credentialsToSecretKey email, password
    this.props.onGenerateKey? private_key

  render: ->
    console.log this.state
    newIdentityButtonProps =
      className: 'btn btn-success pull-right text-monospace'
      onClick: this.generateKey
    if not this.state.validNewKey
      newIdentityButtonProps.disabled = '1'

    div className: 'row',
      div className: 'col-md-12',
        form className: 'form-horizontal',
          div className: "row",
            div className: "col-md-12",
              h3 className: "text-monospace", "Generate keys"
              p className: "text-monospace",
              "Your email and password are used to generate a " +
              "unique pair of keys."
              p className: "text-monospace",
              "The credentials do not leave your device."
          div style: {marginTop: "1em"},
            InputField
              type: 'text'
              label: span className: 'text-monospace', 'Email address'
              inputClass: 'text-monospace'
              onChange: ((email) -> this.setState email: email).bind this
            InputField
              type: 'password',
              label: span className: 'text-monospace', 'Password'
              onChange: ((password) ->
                this.setState password: password).bind this
          div className: 'form-group',
            div className: 'col-md-12 ',
              button className: 'btn btn-default pull-right text-monospace',
              onClick: this.generateKey, 'Generate Keys'
          div className: "row",
            div className: "col-md-12",
              h3 className: 'text-monospace',
              "New to curvech.at? Or just want a new identity?"
              p className: 'text-monospace',
                "Your password together with your email are used to
                 generate a unique pair of keys. "
              p className: 'text-monospace',
                "This happens in your browser, but it is important
                that it cannot be brute forced easily. Your password
                needs to have high entropy to generate high quality
                keys."
          VerifyPassword {password: this.state.password,
          onUpdate: ((valid) -> this.setState validNewKey: valid).bind(this)}
          div className: 'form-group',
            div className: 'col-md-12 ',
              button newIdentityButtonProps, 'Generate New Keys'


VerifyPassword = React.createClass
  getInitialState: () ->
    verifyPassword: ''

  componentDidUpdate: () ->
    console.log this.validPassword
    this.props.onUpdate this.validPassword

  shouldComponentUpdate: (nextProps, nextState) ->
    not(nextState.verifyPassword == this.state.verifyPassword and \
      nextProps.password == this.props.password)

  render: () ->
    passwordStats = zxcvbn this.props.password

    this.validPassword = true
    newKeyMessageClass = ''
    newKeyMessage = ''
    if passwordStats.entropy < MINIMUM_PASSWORD_ENTROPY_BITS
      this.validPassword = false
      newKeyMessage = "Your password is not strong enough, it must to have at" +
      " least #{MINIMUM_PASSWORD_ENTROPY_BITS} bits of entropy."
      newKeyMessageClass = "text-danger"
    else if passwordStats.entropy < 110
      newKeyMessageClass = "text-warning"
    else
      newKeyMessageClass = "text-success"
    entropyClass = newKeyMessageClass + " password-entropy"

    if this.props.password != this.state.verifyPassword
      if newKeyMessage == ''
        this.validPassword = false
        newKeyMessageClass = "text-danger"
        newKeyMessage = 'Passwords do not match.'
    else if newKeyMessage == ''
      newKeyMessage = 'Everything is OK'

    div null,
      div className: "row",
        div className: "col-md-12",
          div className: 'text-monospace password-entropy',
          style: {display:'inline-block'}, "Entropy: "
            span className: entropyClass, "#{passwordStats.entropy} bits"
      div style: {marginBottom: "1em"},
        InputField
          type: 'password',
          label: span className: 'text-monospace', 'Verify Password'
          onChange: ((password) ->
            this.setState verifyPassword: password).bind this
      div className: 'row',
        div className: 'col-md-12 text-monospace large-bottom',
          p className: newKeyMessageClass, newKeyMessage


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
      div className: 'col-md-12', style:{display:'inline-block'},
        div className: 'input-group margin-bottom-lg',
          span className: 'input-group-addon',
            span style: {width: '12em', display: 'inline-block'},
            this.props.label
          input inputProps


React.renderComponent DisturbeApp(), document.getElementById('app')
