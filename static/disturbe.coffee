require.config
  baseUrl: 'static',
  paths:
    base64: 'base64'
    bootstrap: 'components/bootstrap/dist/js/bootstrap.min'
    bootstrapTags: 'components/bootstrap-tagsinput/dist/bootstrap-tagsinput.min'
    bs58: 'bs58'
    bytebuffer: 'components/bytebuffer/dist/ByteBufferAB.min'
    identicon5: 'jquery.identicon5.packed'
    jquery: 'components/jquery/dist/jquery.min'
    Long: 'components/long/dist/Long.min'
    nacl: 'nacl'
    ProtoBuf: 'components/protobuf/dist/ProtoBuf.min'
    react: 'components/react/react-with-addons'
    scrypt: 'scrypt'
    zxcvbn: 'components/zxcvbn/zxcvbn'
  shim:
    bootstrap:
      deps: ['jquery']
    bootstrapTags:
      deps: ['bootstrap']
    bops:
      exports: 'bops'
    bytebuffer:
      deps: ['Long']
    identicon5:
      deps: ['jquery']
    jquery:
      deps: []
      exports: '$'
    ProtoBuf:
      deps: ['bytebuffer', 'Long']
      exports: 'ProtoBuf'
    react:
       deps: ['jquery']
      exports: 'React'
    zxcvbn:
      exports: 'zxcvbn'
    waitSeconds: 0


`require(['jquery', 'react', 'ProtoBuf', 'zxcvbn', 'bootstrap',
  'bootstrapTags', 'identicon5', 'nacl', 'scrypt', 'bs58', 'base64'],
  function($, React, ProtoBuf, zxcvbn) {`

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

MINIMUM_PASSWORD_ENTROPY_BITS = 0
STRONG_PASSWORD_ENTROPY_BITS = 100


BOX_NONCE_BYTES = 24
KEY_BASE64_BYTES = 44


DISTURBE_PROTO = "
package disturbe;

message File {
  optional string name = 1;
  optional bytes contents = 2;
}

message Message {
  optional string text = 1;
  optional bytes sender = 2;
  repeated File files = 3;
}
"

nacl = nacl_factory.instantiate()
scrypt = scrypt_module_factory()
{encode_utf8, decode_utf8} = nacl


disturbePb = ProtoBuf.loadProto(DISTURBE_PROTO).build 'disturbe'

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
  asString = ''
  for byte in arr
    asString += String.fromCharCode byte
  base64Str = btoa asString
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
      key = b58decode(key)
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
    decryptInfo[DECRYPT_INFO_SENDER_FIELD] = b58encode senderKeys.boxPk
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
  cipher[CIPHER_TRANSIENT_PKEY_FIELD] = b58encode transientKeys.boxPk
  cipher[CIPHER_MESSAGE_FIELD] = b64encode messageBox
  decryptInfo = {}
  cipher[CIPHER_DECRYPT_INFO_FIELD] = decryptInfo
  for recipientPublicKey in recipientPublicKeys
    if recipientPublicKey.length != nacl.crypto_box_PUBLICKEYBYTES
      throw new Error "#{b58encode recipientPublicKey} is not valid public key"
    {nonce, decryptInfoBox} = secretToRecipient(
      transientKeys, senderKeys, recipientPublicKey, messageInfo)
    decryptInfo[b64encode(nonce)] = b64encode decryptInfoBox
  JSON.stringify cipher


decryptMessage = (userKeys, cipherText) ->
  GENERIC_ERROR = 'Could not decrypt message.'
  cipher = JSON.parse cipherText

  transientPublicKey = b58decode cipher[CIPHER_TRANSIENT_PKEY_FIELD]
  decryptInfo = null
  decryptInfoNonce = null
  for nonceBase64, box of cipher[CIPHER_DECRYPT_INFO_FIELD]
    try
      decryptInfoNonce = b64decode nonceBase64
      decryptInfo = nacl.crypto_box_open(
        b64decode(box), decryptInfoNonce, transientPublicKey, userKeys.boxSk)
      break
    catch error
      # Could not decrypt it, try the next one
  if not (decryptInfo? and decryptInfoNonce?)
    throw GENERIC_ERROR

  decryptInfo = JSON.parse decode_utf8 decryptInfo
  senderPublicKey = b58decode decryptInfo[DECRYPT_INFO_SENDER_FIELD]

  messageInfoBox = b64decode decryptInfo[DECRYPT_INFO_MESSAGE_INFO_FIELD]
  messageInfo = nacl.crypto_box_open(
      messageInfoBox, decryptInfoNonce, senderPublicKey, userKeys.boxSk)
  messageInfo = JSON.parse decode_utf8 messageInfo
  messageKey = b64decode messageInfo[MESSAGE_INFO_KEY_FIELD]
  messageNonce = b64decode messageInfo[MESSAGE_INFO_NONCE_FIELD]

  plaintext =
    sender: senderPublicKey
    message: nacl.crypto_secretbox_open(
      b64decode(cipher[CIPHER_MESSAGE_FIELD]), messageNonce, messageKey)


bytesToSize = (bytes, precision = 1) ->
  kilobyte = 1024
  megabyte = kilobyte * 1024
  gigabyte = megabyte * 1024
  terabyte = gigabyte * 1024

  if bytes >= 0 and bytes < kilobyte
    bytes + ' B'
  else if bytes >= kilobyte and bytes < megabyte
    (bytes / kilobyte).toFixed(precision) + ' KiB'
  else if bytes >= megabyte and bytes < gigabyte
    (bytes / megabyte).toFixed(precision) + ' MiB'
  else if bytes >= gigabyte and bytes < terabyte
    (bytes / gigabyte).toFixed(precision) + ' GiB'
  else if bytes >= terabyte
    (bytes / terabyte).toFixed(precision) + ' TiB'
  else
    bytes + ' B'


DisturbeApp = React.createClass
  getInitialState: ->
    userKeys: null
    userData: null
    selectedTab: TAB_ENCRYPT

  setPrivateKey: (privateKey) ->
    window.scrollTo 0, 0
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
      if this.state.userKeys?
        div null,
          h1 className: 'large-bottom', 'curvech.at'
          div className: 'row',
            div className: 'col-md-12',
              h3 null, 'Curve Profile'
          div className: 'row',
            div className: 'col-md-12 large-bottom',
              p null,
              'Anyone who has your curve ID can send messages that
              only you can decrypt.'
              p null,
              'Spread your curve ID wide. The secret key you should
              never reveal.'
          CurveProfile userKeys: this.state.userKeys
          CryptoTabPicker userKeys: this.state.userKeys
      else
        div className: 'row',
          div className: 'col-md-8 col-md-offset-2 large-bottom',
            h1 className: 'large-bottom', 'curvech.at'
            GeneratePrivateKey onGenerateKey: this.setPrivateKey


TAB_ENCRYPT = 'encrypt'
TAB_DECRYPT = 'decrypt'
TAB_CLOUD = 'cloud'

CryptoTabPicker = React.createClass
  getInitialState: -> selectedTab: TAB_ENCRYPT

  changeTab: (tab, event) ->
    event.stopPropagation()
    event.preventDefault()
    if tab != this.state.selectedTab then this.setState selectedTab: tab

  render: ->
    activeIf = ((tab) ->
      "#{if this.state.selectedTab == tab then 'active' else ''}").bind this
    changeTabTo = ((tab) -> this.changeTab.bind(this, tab)).bind this
    hiddenIfNot = ((tab) ->
      if this.state.selectedTab == tab then '' else 'hidden').bind this

    div null,
      div className: 'row',
        div className: 'col-md-12',
          ul className: 'nav nav-tabs nav-justified', role: 'tablist',
          style: {marginTop: '2em', marginBottom: '1.2em', width: '100%'},
            li className: activeIf(TAB_ENCRYPT),
              a href: "##{TAB_ENCRYPT}", onClick: changeTabTo(TAB_ENCRYPT),
                i className: 'fa fa-lock nav-icon'
                div className: 'nav-label', 'Encrypt'
            li className: activeIf(TAB_DECRYPT),
              a href: "##{TAB_DECRYPT}", onClick: changeTabTo(TAB_DECRYPT),
                i className: 'fa fa-unlock-alt nav-icon'
                div className: 'nav-label', 'Decrypt'
            li className: activeIf(TAB_CLOUD),
              a href: "##{TAB_CLOUD}", onClick: changeTabTo(TAB_CLOUD),
                i className: 'fa fa-cloud nav-icon'
                div className: 'nav-label', 'Cloud'
      div className: hiddenIfNot(TAB_ENCRYPT),
        EncryptMessage userKeys: this.props.userKeys
      div className: hiddenIfNot(TAB_DECRYPT),
        DecryptMessage userKeys: this.props.userKeys
      div className: hiddenIfNot(TAB_CLOUD), ''


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
      h3 className: 'media-heading',
      'Public Key Profile'
      div className: 'media',
        span className: 'pull-left', href: '#',
          div className: 'media-object', ref: 'identicon',
          toHex nacl.crypto_hash this.props.publicKey
        div className: 'media-body',
          KeyProfileItem name: 'Key', value: b58encode this.props.publicKey,
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
      span null, "#{this.props.name}: "
      span className: valueClass, ref: this.props.name, href: '#',
      this.props.value


EncryptMessage = React.createClass
  getInitialState: -> ciphertext: null

  clear: -> this.setState this.getInitialState()

  render: ->
    div null,
      div className: 'row',
        div className: 'col-md-12 large-bottom',
          h3 null, 'Compose an encrypted message'
          p null,
          'Only the owners of the curve IDs you specify will be able
            to decrypt it.'
      if not this.state.ciphertext?
        ComposeMessage userKeys: this.props.userKeys,
        onEncrypt: ((ciphertext) ->
          this.setState ciphertext: ciphertext).bind this
      else
        div null,
          CipherTextarea ciphertext: this.state.ciphertext
          div className: 'row',
              div className: 'col-md-12',
                p null, 'Compose a ',
                  a onClick: this.clear, style: {cursor: 'pointer'},
                  'new message'


ComposeMessage = React.createClass
  getInitialState: () ->
    recipients: []
    message: ''
    files: []

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

    innerInput = $(recipientsNode.tagsinput 'input')
    innerInput.addClass 'form-control'
    innerInput.css width: ''

    $(this.refs.inputFiles.getDOMNode()).on 'change', this.updateFiles

  changeMessage: (event) -> this.setState message: event.target.value

  encryptMessage: (event) ->
    event.preventDefault()
    recipientNode = $(this.refs.recipients.getDOMNode())
    recipientKeys =
      for key in $(recipientNode).val().split(',')
        b58decode key
    try
      if this.props.onEncrypt?
        message = new disturbePb.Message text: this.state.message
        message.files = []
        for file in this.state.files
          fileReader = new FileReader()
          fileReader.onloadend = ((file, reader) ->
            message.files.push
              name: file.name
              contents: reader.result

            if message.files.length == this.state.files.length
              try
                plaintext = new Uint8Array message.toArrayBuffer()
                ciphertext = encryptMessage(
                  this.props.userKeys, recipientKeys, plaintext)
                this.props.onEncrypt ciphertext
              catch error
                console.log error
          ).bind(this, file, fileReader)
          fileReader.readAsArrayBuffer file
    catch error
      console.log error

  updateFiles: (event) ->
    # fileReader = new FileReader()
    # fileReader.onloadend = (() ->
    #   this.setState message: fileReader.result).bind this
    files = this.state.files.slice 0
    for file in event.target.files then files.push file
    this.setState files: files
#      fileReader.readAsText f

  render: ->
    error = null
    invalidRecipients = this.getInvalidRecipientKeys()
    if invalidRecipients.length > 0
      invalidJoined = "#{invalidRecipients.join(', ')}"
      if invalidRecipients.length == 1
        error = "#{invalidJoined} is not a valid curve ID"
      else
        error = "#{invalidJoined} are not valid curve IDs"

    encryptButtonProps =
      className: 'btn btn-lg btn-success'
      onClick: this.encryptMessage
    if error? or this.state.recipients.length == 0
      encryptButtonProps.disabled = 'true'

    div null,
      form className: 'form-horizontal',
        if error?
          div className: 'form-group',
            div className: 'col-xs-12',
              span className: 'text-danger', error
        div className: 'form-group',
          div className: 'col-xs-12', style: {display:'inline-block'},
            label className: 'control-label', 'Recipients'
            input className: 'form-control', type: 'text', defaultValue: '',
            ref: 'recipients'
        div className: 'form-group',
          div className: 'col-xs-12', style: {display:'inline-block'},
            label className: 'control-label', 'Message'
            textarea className: 'form-control', value: this.state.message,
            placeholder: 'Type your message..', onChange: this.changeMessage,
            rows: 10
        if this.state.files.length > 0
          div className: 'form-group',
            div className: 'col-md-12',
              for file in this.state.files
                span className: 'label label-default attached-file',
                  span null, file.name
                  span null, " [#{bytesToSize file.size}] "
                  i className: 'fa fa-fw fa-lg fa-times dismiss-icon',
                  onClick: ((file) ->
                    files = this.state.files.slice 0
                    index = files.indexOf file
                    files.splice index, 1
                    this.setState files: files
                  ).bind(this, file)
        div className: 'form-group',
          div className: 'col-md-12 large-bottom',
            input style: {display: 'none'}, type: 'file', ref: 'inputFiles',
            multiple: 'true'
            a className: 'control-label', style: {cursor: 'pointer'},
            onClick: ((event) ->
              event.preventDefault()
              $(this.refs.inputFiles.getDOMNode()).trigger 'click'
              ).bind(this),
              i className: 'fa fa-fw fa-lg fa-plus'
              'Add files'
            div className: 'pull-right',
              button encryptButtonProps,
                  i className: 'fa fa-fw fa-lock'
                  span null, 'Encrypt'


CipherTextarea = React.createClass
  render: ->
    form className: 'form-horizontal',
      div className: 'form-group large-bottom',
        div className: 'col-xs-12', style: {display:'inline-block'},
          label className: 'control-label', 'Scrambled message'
          textarea className: 'form-control', value: this.props.ciphertext,
          placeholder: 'Type your message..', readOnly: true, rows: 10,
          style: {backgroundColor: 'white', cursor: 'auto'}


DecryptMessage = React.createClass
  getInitialState: () ->
    ciphertext: ''
    error: null
    message: null

  clear: -> this.setState this.getInitialState()

  changeCiphertext: (event) -> this.setState ciphertext: event.target.value

  decryptMessage: (event) ->
    event.preventDefault()
    try
      plaintext = decryptMessage this.props.userKeys, this.state.ciphertext
      message = disturbePb.Message.decode plaintext.message
      message.sender = plaintext.sender
      this.setState message: message
    catch error
      this.setState error: error.toString()
      console.log error

  render: ->
    div null,
      div className: 'row',
        div className: 'col-md-12 large-bottom',
          h3 null, 'Decrypt a message'
          p null,
          'You can only decrypt a message that was encrypted for your
          curve ID.'
      if not this.state.message?
        form className: 'form-horizontal',
          if this.state.error?
            div className: 'form-group',
              div className: 'col-xs-12',
                span className: 'text-danger', this.state.error
          div className: 'form-group',
            div className: 'col-xs-12', style: {display:'inline-block'},
              label className: 'control-label', 'Scrambled message'
              textarea className: 'form-control', value: this.state.message,
              placeholder: 'Copy paste the scrambled message',
              onChange: this.changeCiphertext, rows: 10
          div className: 'row',
            div className: 'col-md-12 large-bottom',
              button className:'btn btn-lg btn-success pull-right',
              onClick: this.decryptMessage,
                i className: 'fa fa-fw fa-lg fa-unlock-alt'
                span null,  'Decrypt'
      else
        div null,
          MessageView message: this.state.message
          div className: 'row',
            div className: 'col-md-12',
              p null, 'Decrypt ',
                a onClick: this.clear, style: {cursor: 'pointer'},
                'another message'


MessageView = React.createClass
  render: ->
    form className: 'form-horizontal',
      div className: 'form-group',
        div className: 'col-xs-12', style: {display:'inline-block'},
          label className: 'control-label', 'From'
          input className: 'form-control',
          value: b58encode this.props.message.sender, readOnly: true,
          style: {backgroundColor: 'white', cursor: 'auto'}
      div className: 'form-group',
        div className: 'col-xs-12', style: {display:'inline-block'},
          label className: 'control-label', 'Message'
          textarea className: 'form-control', value: this.props.message.text,
          readOnly: true, rows: 10,
          style: {backgroundColor: 'white', cursor: 'auto'}
      div className: 'form-group',
        div className: 'col-md-12',
          for file in this.props.message.files
            {buffer, offset, limit} = file.contents
            blob = new Blob [buffer.slice(offset, limit)]
            url = (window.webkitURL || window.URL).createObjectURL blob
            span className: 'label label-default attached-file',
              span null, file.name
              span null, " [#{bytesToSize limit - offset}] "
              a href: url, download: file.name,
                i className: 'fa fa-fw fa-lg fa-download dismiss-icon',
              onClick: ((file) ->
              ).bind(this, file)


CurveProfile = React.createClass
  SIZE_COLLAPSED: 60
  SIZE_EXPANDED: 120
  getInitialState: ->
    collapsed: false

  componentDidMount: () ->
    this.renderIdenticon this.refs.identicon.getDOMNode()

  renderIdenticon: (elem) ->
    size = if this.state.collapsed then this.SIZE_COLLAPSED
    else this.SIZE_EXPANDED

    $(elem).identicon5 size: size

  render: ->
    div null,
      div className: 'row',
        div className: 'col-sm-2 hidden-xs',
          span className: '', href: '#',
            span className: 'text-muted', 'Fingerprint'
            div ref: 'identicon', style: {marginTop: '1em'},
            toHex nacl.crypto_hash this.props.userKeys.boxPk
        div className: 'col-sm-10',
          PublicKeyField publicKey: this.props.userKeys.boxPk
          SecretKeyField secretKey: this.props.userKeys.boxSk


PublicKeyField = React.createClass
  getInitialState: () -> shown: false

  componentDidMount: () ->
    this.renderIdenticon this.refs.identicon.getDOMNode()

  renderIdenticon: (elem) -> $(elem).identicon5 size: 28

  onCopyPublicKey: (event) ->
    inputNode = this.refs.inputPublicKey.getDOMNode()
    inputNode.focus()
    inputNode.setSelectionRange 0, inputNode.value.length

  onTweet: (event) ->
    event.preventDefault()
    tweet_text = "cryptch.at is zero knowledge messaging with end to end " +
    "encryption. My public key is #{b58encode this.props.publicKey}"
    window.open("https://twitter.com/intent/tweet?text=#{tweet_text}")

  render: ->
    inputProps =
      type: 'text'
      readOnly: true
      className: 'form-control text-monospace'
      placeholder: ''
      value: b58encode this.props.publicKey
      style: {backgroundColor: 'white', cursor: 'auto'}
      ref: 'inputPublicKey'
      onClick: this.onCopyPublicKey

    div style: {paddingBottom: '1em'},
      label className: 'control-label',
      style: {fontSize: '1.3em', marginTop: '0em'}, "Curve ID"
      div className: 'input-group input-group-lg',
        span className: 'input-group-btn hidden-sm hidden-md hidden-lg',
          button className: 'btn btn-default',
            span ref: 'identicon', toHex nacl.crypto_hash this.props.publicKey
        input inputProps
        span className: 'input-group-btn',
          button
            className: 'btn btn-default',
            onClick: this.onCopyPublicKey,
            ref: 'clipboardButton',
            i className: 'fa fa-copy fa-lg'
        span className: 'input-group-btn',
          button
            className: 'btn btn-default',
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
      value = b58encode this.props.secretKey
    else
      classNames += ' text-muted'
      value = '<< Hidden >>'

    inputProps =
      className: classNames
      type: 'text'
      readOnly: true
      placeholder: ''
      value: value
      style: {backgroundColor: 'white', cursor: 'auto'}

    div style: {paddingBottom: '1em'},
      label className: 'control-label',
      style: {fontSize: '1.3em'}, 'Secret Key'
      div className: 'input-group input-group-lg',
        input inputProps
        span className: 'input-group-btn',
          button
            className: 'btn btn-default',
            onClick: this.onShow,
            if this.state.shown then 'Hide' else 'Show'


GeneratePrivateKey = React.createClass
  getInitialState: ->
    email: ''
    password: ''
    validPassword: false

  generateKey: (event) ->
    event.preventDefault()
    email = this.state.email
    password = this.state.password
    private_key = credentialsToSecretKey email, password
    this.props.onGenerateKey? private_key

  render: ->
    deriveButtonProps =
      className: 'btn btn-lg btn-success pull-right'
      onClick: this.generateKey
    if not this.state.validPassword
      deriveButtonProps.disabled = 'true'

    div className: 'row',
      div className: 'col-md-12',
        form className: 'form-horizontal',
          div className: 'row',
            div className: 'col-md-12',
              h3 null, 'Derive your curve ID'
              p null,
              'Your email and password are used to generate a unique
              pair of keys.'
              p null,
              'The credentials do not leave your device and are never
              stored.'
          div style: {marginTop: '1em'},
            InputField
              type: 'text'
              label: 'Email'
              placeholder: 'Your email address'
              onChange: ((email) -> this.setState email: email).bind this
            InputField
              type: 'password',
              label: 'Password'
              placeholder: 'Your strong password'
              onChange: ((password) ->
                this.setState password: password).bind this
          div className: 'row',
            div className: 'col-md-12',
            VerifyPassword {password: this.state.password,
            onUpdate: ((valid) ->
              this.setState validPassword: valid).bind(this)}
          div className: 'form-group',
            div className: 'col-md-12 ',
              button deriveButtonProps, 'Derive your curve ID'


VerifyPassword = React.createClass
  getInitialState: () -> verifyPassword: ''

  componentDidUpdate: () -> this.props.onUpdate this.validPassword

  shouldComponentUpdate: (nextProps, nextState) ->
    not(nextState.verifyPassword == this.state.verifyPassword and \
      nextProps.password == this.props.password)

  render: () ->
    passwordStats = zxcvbn this.props.password

    this.validPassword = true
    messageClass = ''
    message = ''
    if passwordStats.entropy < MINIMUM_PASSWORD_ENTROPY_BITS
      this.validPassword = false
      message = 'Your password is not strong enough, it must to have at' +
      " least #{MINIMUM_PASSWORD_ENTROPY_BITS} bits of entropy."
      messageClass = 'text-danger'
    else if passwordStats.entropy < STRONG_PASSWORD_ENTROPY_BITS
      messageClass = 'text-warning'
    else
      messageClass = 'text-success'
    entropyClass = messageClass + ' password-entropy'

    if this.state.verifyPassword.length > 0 and
       this.props.password != this.state.verifyPassword
      if message == ''
        this.validPassword = false
        messageClass = 'text-danger'
        message = 'Passwords do not match.'
    else if message == ''
      message = 'Everything is OK'

    div null,
      div className: 'row',
        div className: 'col-md-12',
          div className: 'password-entropy',
          style: {display:'inline-block'}, 'Entropy: ',
            span className: entropyClass, "#{passwordStats.entropy} bits"
      div className: "row",
        div className: "col-md-12",
          p null,
          "Your password needs to have high entropy to generate
          high quality keys."
      div style: {marginBottom: "1em"},
        InputField
          type: 'password',
          label: 'Check (optional)'
          onChange: ((password) ->
            this.setState verifyPassword: password).bind this
          placeholder: 'Retype password (optional)'
      div className: 'row',
        div className: 'col-md-12 large-bottom',
          p className: messageClass, message


InputField = React.createClass
  onChange: (event) -> this.props.onChange? event.target.value

  render: ->
    inputProps =
      type: this.props.type
      placeholder: this.props.placeholder
      value: this.props.value
      className: 'form-control input-lg'
      onChange: this.onChange
    if this.props.value? then inputProps.value = this.props.value
    if this.props.inputClass?
      inputProps.className += ' ' + this.props.inputClass

    div className: 'form-group',
      div className: 'col-xs-12', style:{display:'inline-block'},
        label className: 'control-label', this.props.label
        input inputProps


$ () ->
  $('#loader').hide()
  React.renderComponent DisturbeApp(), document.getElementById('app')

`});`  # end the require.js callback that wraps everything
