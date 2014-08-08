{a, br, button, div, form, hr, h1, h2, h3, h4, h5, h6, i, input,
  label, li, p, option, select, span, strong, textarea, ul} = React.DOM


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


### Encryption Constants ###

CIPHER_VERSION = 1

CIPHER_VERSION_FIELD = 'version'
CIPHER_TRANSIENT_PKEY_FIELD = 'transient_pkey'
CIPHER_DECRYPT_INFO_FIELD = 'decrypt_info'
CIPHER_MESSAGE_FIELD = 'message'

DECRYPT_INFO_SENDER_FIELD = 'sender'
DECRYPT_INFO_MESSAGE_INFO_FIELD = 'message_info_box'

MESSAGE_INFO_KEY_FIELD = 'message_key'
MESSAGE_INFO_NONCE_FIELD = 'message_nonce'


### Key Derivation Constants ###

SCRYPT_N = Math.pow(2, 14)
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_L = 32

MINIMUM_PASSWORD_ENTROPY_BITS = 5


BOX_NONCE_BYTES = 24
KEY_BASE64_BYTES = 44


nacl = nacl_factory.instantiate()
scrypt = scrypt_module_factory()
{encode_utf8, decode_utf8} = nacl

# $.fn.editable.defaults.mode = 'inline';


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


toHex = (arr) ->
  hexEncode = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  'A', 'B', 'C', 'D', 'E', 'F'];
  buf = ''
  for elem in arr
    buf += hexEncode[(elem & 0xf0) >> 4]
    buf += hexEncode[(elem & 0x0f)]
  buf


sendHello = (transientKeys, success, error) ->
  serverPublicKey = b64decode SERVER_PUBLIC_KEY
  zeros = new Uint8Array(HELLO_PADDING_BYTES)
  nonce = nacl.crypto_box_random_nonce()
  zerosBox = nacl.crypto_box zeros, nonce, serverPublicKey, transientKeys.boxSk
  noncedZerosBox = concatBuffers nonce, zerosBox

  payload = {}
  payload[HELLO_CLIENT_TRANSIENT_PKEY_FIELD] = b64encode transientKeys.boxPk
  payload[HELLO_PADDING_FIELD] = b64encode new Uint8Array(HELLO_PADDING_BYTES)
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
    error: error
    success: (data, status, xhr) ->
      response_box = b64decode data.response
      response_box_nonce = response_box.subarray 0, BOX_NONCE_BYTES
      response_box_cipher = response_box.subarray BOX_NONCE_BYTES
      response = decode_utf8 nacl.crypto_box_open(
        response_box_cipher, response_box_nonce,
        serverTPKey, transientKeys.boxSk)
      success response


sendMessage = (userKeys, message, success, error) ->
  transientKeys = nacl.crypto_box_keypair()
  serverPublicKey = b64decode SERVER_PUBLIC_KEY
  sendHello transientKeys,
    (serverTPKey, cookie) ->
      sendInitiate(userKeys, transientKeys, serverTPKey,
        cookie, message, success, error)
    error


validPublicKey = (key) ->
  valid = false
  try
    if typeof key == 'string'
      key = b64decode(key)
    if key.length == nacl.crypto_box_PUBLICKEYBYTES
      valid = true
  catch error
    valid = false
  valid


encryptMessage = (senderKeys, recipientPublicKeys, message) ->
  secretToRecipient = (transientKeys, senderKeys,
    recipientPublicKey, messageInfo) ->
    nonce = nacl.crypto_box_random_nonce()
    messageInfoBox = nacl.crypto_box(
      messageInfo, nonce, recipientPublicKey, senderKeys.boxSk)

    decryptInfo = {}
    decryptInfo[DECRYPT_INFO_SENDER_FIELD] = b64encode senderKeys.boxPk
    decryptInfo[DECRYPT_INFO_MESSAGE_INFO_FIELD] = b64encode messageInfoBox
    decryptInfo = encode_utf8 JSON.stringify decryptInfo
    decryptInfoBox = nacl.crypto_box(
      decryptInfo, nonce, recipientPublicKey, transientKeys.boxSk)
    {nonce, decryptInfoBox}

  transientKeys = nacl.crypto_box_keypair()
  if typeof message == 'string'
    message = encode_utf8 message

  messageHash = nacl.crypto_hash message
  messageNonce = nacl.crypto_secretbox_random_nonce()
  messageKey = nacl.random_bytes nacl.crypto_secretbox_KEYBYTES
  messageBox = nacl.crypto_secretbox message, messageNonce, messageKey

  messageInfo = {}
  messageInfo[MESSAGE_INFO_KEY_FIELD] = b64encode messageKey
  messageInfo[MESSAGE_INFO_NONCE_FIELD] = b64encode messageNonce
  messageInfo = encode_utf8 JSON.stringify messageInfo

  cipher = {}
  cipher[CIPHER_VERSION_FIELD] = CIPHER_VERSION
  cipher[CIPHER_TRANSIENT_PKEY_FIELD] = b64encode transientKeys.boxPk
  cipher[CIPHER_MESSAGE_FIELD] = b64encode messageBox
  decryptInfo = {}
  cipher[CIPHER_DECRYPT_INFO_FIELD] = decryptInfo
  for recipientPublicKey in recipientPublicKeys
    if recipientPublicKey.length != nacl.crypto_box_PUBLICKEYBYTES
      throw new Error(
        "#{b64encode recipientPublicKey} is not valid public key")
    {nonce, decryptInfoBox} = secretToRecipient(
      transientKeys, senderKeys, recipientPublicKey, messageInfo)
    decryptInfo[b64encode(nonce)] = b64encode decryptInfoBox
  JSON.stringify cipher


decryptMessage = (userKeys, cipherText) ->
  GENERIC_ERROR = 'Could not decrypt message.'
  cipher = JSON.parse cipherText

  transientPublicKey = b64decode cipher[CIPHER_TRANSIENT_PKEY_FIELD]
  decryptInfo = null
  decryptInfoNonce = null
  for nonceBase64, box of cipher[CIPHER_DECRYPT_INFO_FIELD]
    try
      decryptInfoNonce = b64decode(nonceBase64)
      decryptInfo = nacl.crypto_box_open(
        b64decode(box), decryptInfoNonce, transientPublicKey, userKeys.boxSk)
      break
    catch error
      # Could not decrypt it, try the next one
  if not (decryptInfo? and decryptInfoNonce?)
    throw GENERIC_ERROR

  decryptInfo = JSON.parse decode_utf8 decryptInfo
  senderPublicKey = b64decode decryptInfo[DECRYPT_INFO_SENDER_FIELD]

  messageInfoBox = b64decode decryptInfo[DECRYPT_INFO_MESSAGE_INFO_FIELD]
  messageInfo = nacl.crypto_box_open(
      messageInfoBox, decryptInfoNonce, senderPublicKey, userKeys.boxSk)
  messageInfo = JSON.parse decode_utf8 messageInfo
  console.log messageInfo
  messageKey = b64decode messageInfo[MESSAGE_INFO_KEY_FIELD]
  messageNonce = b64decode messageInfo[MESSAGE_INFO_NONCE_FIELD]

  plaintext =
    sender: b64encode senderPublicKey
    message: nacl.crypto_secretbox_open(
      b64decode(cipher[CIPHER_MESSAGE_FIELD]), messageNonce, messageKey)


DisturbeApp = React.createClass
  getInitialState: ->
    userKeys: null
    userData: null

  setPrivateKey: (privateKey) ->
    userKeys = nacl.crypto_box_keypair_from_raw_sk privateKey
    this.setState userKeys: userKeys

  setUserData: (userData) -> this.setState userData: {}

  onLogin: (event) ->
    sendMessage this.state.userKeys,
      {'method': 'get_userdata'}
      ((response) ->
        this.setUserData response).bind(this),
      (xhr) -> alert xhr.responseText

  render: ->
    div null,
      h1 className: 'text-monospace large-bottom', 'curvech.at'
      if this.state.userKeys?
        div null,
          div className: 'row',
            div className: 'col-md-12 large-bottom',
              h3 className: 'text-monospace', 'Keys'
              p className: 'text-monospace',
              'Anyone who has your public key can send
              messages that only you can decrypt.'
              p className: 'text-monospace',
                'Spread your public key wide. The secret key you
                should keep, um, secret.'
          KeyCabinet userKeys: this.state.userKeys
          if not this.state.userData?
            div className: 'row',
              div className: 'col-md-12 large-bottom',
                button className:'btn btn-success pull-right',
                onClick:this.onLogin, 'Sign in with your public key'
          else
            div className: 'row',
              div className: 'col-md-12 large-bottom',
                span className: 'text-monospace text-muted',
                'Successfully retrieved your public key profile.'
          div className: 'row',
            div className: 'col-md-12',
              hr null,
          # if this.state.userData?
          #   div className: 'row',
          #     div className: 'col-md-12',
          #       KeyProfile publicKey: this.state.userKeys.boxPk
          #       hr null
          div className: 'row',
            div className: 'col-md-12 large-bottom',
              h3 className: 'text-monospace', 'Compose message'
              p className: 'text-monospace',
              'Compose a message and encrypt it. Only the owners of
              the public keys you specify will be able to decrypt it.'
            div className: 'col-md-12 large-bottom',
            EncryptMessage userKeys: this.state.userKeys
      else
        GeneratePrivateKey onGenerateKey: this.setPrivateKey


KeyProfile = React.createClass
  getInitialState: ->
    name: 'anonymous'
    email: ''
    social: ''

  componentDidMount: () ->
    this.renderIdenticon this.refs.identicon.getDOMNode()

  renderIdenticon: (elem) -> $(elem).identicon5 size: 80

  render: ->
    div null,
      h3 className: 'media-heading text-monospace',
      'Public Key Profile'
      div className: 'media',
        span className: 'pull-left', href: '#',
          div className: 'media-object', ref: 'identicon',
          toHex nacl.crypto_hash this.props.publicKey
        div className: 'media-body',
          KeyProfileItem name: 'Key', value: b64encode(this.props.publicKey),
          iconClass: 'fa-key', editable: false
          KeyProfileItem name: 'Name', value: this.state.name,
          iconClass: 'fa-user', editable: true
          KeyProfileItem name: 'Email', value: this.state.email,
          iconClass: 'fa-envelope-o', editable: true
          KeyProfileItem name: 'Social', value: this.state.social,
          iconClass: 'fa-share-alt', editable: true


KeyProfileItem = React.createClass
  componentDidMount: () ->
    editable = if this.props.editable? then this.props.editable else false
    if editable
      $(this.refs[this.props.name].getDOMNode()).editable
        type: 'text'
        pk1: 1,
        title: 'enter name'
        showbuttons: false

  render: () ->
    icon = ''
    if this.props.iconClass?
      icon = i className: "fa #{this.props.iconClass} fa-fw text-muted"
    valueClass = ''
    if this.props.editable
      valueClass = 'editable editable-click'
    div className: 'user-profile-item',
      icon
      span className: 'text-monospace', "#{this.props.name}: "
      span className: valueClass, ref: this.props.name, href: '#',
      this.props.value


EncryptMessage = React.createClass
  getInitialState: () ->
    recipients: []
    message: ''
    recipients: []

  getInvalidRecipientKeys: () ->
    invalid = []
    for recipient in this.state.recipients
      if not recipient.valid
        invalid.push recipient.key
    invalid

  componentDidMount: () ->
    recipientsNode = $ this.refs.recipients.getDOMNode()
    recipientsNode.tagsinput
      tagClass: ((key) ->
        recipients = this.state.recipients.slice 0
        recipient = key: key
        if validPublicKey key
          labelClass = 'label label-primary'
          recipient.valid = true
        else
          labelClass = 'label label-danger'
          recipient.valid = false
        recipients.push recipient
        this.setState recipients: recipients
        labelClass
        ).bind(this)
      trimValue: true
    recipientsNode.on 'itemRemoved', ((event) ->
      index = -1
      for recipient, index in this.state.recipients
        if recipient.key == event.item then break
      if index != -1
        recipients = this.state.recipients.slice 0
        recipients.splice index, 1
        this.setState recipients: recipients
      ).bind(this)

    $(recipientsNode.tagsinput 'input').addClass 'form-control'

  changeMessage: (event) ->
    this.setState message: event.target.value

  encryptMessage: (event) ->
    event.preventDefault()
    recipientNode = $(this.refs.recipients.getDOMNode())
    recipientKeys =
      for key in $(recipientNode).val().split(',')
        b64decode key
    try
      cipher = encryptMessage(
        this.props.userKeys, recipientKeys, this.state.message)
      this.setState message: cipher
    catch error
      console.log error

  decryptMessage: (event) ->
    event.preventDefault()
    try
      plaintext = decryptMessage this.props.userKeys, this.state.message
      plaintext.message = decode_utf8 plaintext.message
      {sender, message} = plaintext
      this.setState message: JSON.stringify plaintext
    catch error
      console.log error

  render: ->
    error = null
    invalidRecipients = this.getInvalidRecipientKeys()
    if invalidRecipients.length > 0
      invalidJoined = "#{invalidRecipients.join(', ')}"
      if invalidRecipients.length == 1
        error = "#{invalidJoined} is not a valid public key"
      else
        error = "#{invalidJoined} are not valid public keys"

    encryptButtonProps =
      className: 'btn btn-default'
      onClick: this.encryptMessage
    if error? or this.state.recipients.length == 0
      encryptButtonProps.disabled = 'true'

    form className: 'form-horizontal',
      if error?
        div className: 'form-group',
          div className: 'col-xs-12',
            span className: 'text-monospace text-danger', error
      div className: 'form-group',
        div className: 'col-xs-12', style: {display:'inline-block'},
          label className: 'text-monospace control-label', 'Recipients'
          input className: 'form-control', type: 'text', defaultValue: '',
          ref: 'recipients'
      div className: 'form-group',
        div className: 'col-xs-12', style: {display:'inline-block'},
          label className: 'text-monospace control-label', 'Message'
          textarea className: 'form-control', value: this.state.message,
          placeholder: 'Type your message..', onChange: this.changeMessage,
      div className: 'row',
        div className: 'col-md-12 large-bottom',
          div className: 'pull-right',
            button style: {marginRight: '1em'},
            className:'btn btn-default',
            onClick: this.decryptMessage, 'Decrypt'
            button encryptButtonProps,
              i className: 'fa fa-fw fa-lg fa-lock'
              'Encrypt'


KeyCabinet = React.createClass
  render: ->
    form className: 'form-horizontal',
        PublicKeyField publicKey: this.props.userKeys.boxPk
        SecretKeyField secretKey: this.props.userKeys.boxSk


PublicKeyField = React.createClass
  getInitialState: () -> shown: false

  componentDidMount: () ->
    clipboardButton = $ this.refs.clipboardButton.getDOMNode()
    this.zeroClipboard = new ZeroClipboard(clipboardButton)
    this.zeroClipboard.on 'copy', this.onCopyPublicKey

  onCopyPublicKey: (event) ->
    clipboard = event.clipboardData
    clipboard.setData "text/plain", b64encode this.props.publicKey

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
      div className: 'col-xs-12', style:{display:'inline-block'},
        div className: 'input-group margin-bottom-lg',
          span className: 'input-group-addon',
            span style: {width: '12em', display: 'inline-block'},
            span className: 'text-monospace', 'Public Key'
          input inputProps
          span className: 'input-group-btn',
            button
              className: 'btn btn-default text-monospace',
              onClick: (event) -> event.preventDefault(),
              ref: 'clipboardButton',
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
      div className: 'col-xs-12', style:{display:'inline-block'},
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
    event.preventDefault()
    email = this.state.email
    password = this.state.password
    private_key = credentialsToSecretKey email, password
    this.props.onGenerateKey? private_key

  render: ->
    newIdentityButtonProps =
      className: 'btn btn-success pull-right text-monospace'
      onClick: this.generateKey
    if not this.state.validNewKey
      newIdentityButtonProps.disabled = 'true'

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
      div className: 'col-xs-12', style:{display:'inline-block'},
        div className: 'input-group margin-bottom-lg',
          span className: 'input-group-addon',
            span style: {width: '12em', display: 'inline-block'},
            this.props.label
          input inputProps



$ () -> React.renderComponent DisturbeApp(), document.getElementById('app')
