{a, br, button, div, form, hr, h1, h2, h3, h4, h5, h6, i, input,
  label, li, p, option, select, span, strong, ul} = React.DOM

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

b64encode = (x) ->
  btoa String.fromCharCode.apply(null, x)


DisturbeApp = React.createClass
  getInitialState: ->
    userKeys: null

  setPrivateKey: (privateKey) ->
    userKeys = nacl.crypto_box_keypair_from_raw_sk(privateKey)
    this.setState userKeys: userKeys

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
            value: b64encode(this.props.userKeys.boxPk)
          InputField
            type: 'text'
            label: span className: 'text-monospace', 'Secret Key'
            value: b64encode(this.props.userKeys.boxSk)


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
            onChange: ((email) -> this.setState email: email).bind this
          InputField
            type: 'password',
            label: span className: 'text-monospace', 'Password'
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
    console.log inputProps.value

    div className: 'form-group',
      div className: 'col-md-12',
        div className: 'input-group margin-bottom-lg',
          span className: 'input-group-addon',
            span style: {width: '12em', display: 'inline-block'},
            this.props.label
          div null,
            input inputProps


React.renderComponent DisturbeApp(), document.getElementById('app')
