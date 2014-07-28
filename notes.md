How the service is supposed to work:

1. When a user comes to the portal she is presented with a login box. The
   email/password combination is used to derive a curve25519 key pair in the
   browser. The password is first hashed using SHA-512 and then scrypt is
   applied to the hash with the email address used as the salt. The scrypt
   32-byte hash is the private key. The corresponding public key serves as the
   main form of identification on the service. It will be displayed as a base64
   string, e.g. wFJoQbtDVuOZxzyIAC0muoQYXP0lcYHPB-9DoMj7c3E= This should be
   shared through social media, email, or when meeting physically (a QR
   representation in a mobile app would be useful).
2. An AJAX request with the user public key is then made to the backend to
   retreive the user data. If the user is succesfully authenticated by the
   backend (i.e. proves that it has the corresponding private key), the user
   data is sent back.
3. In the backend, the user data is stored encrypted with a symmetric key itself
   encrypted with the user's public key. From the point of view of the storage
   backend, the user data is an opaque blob.
4. If no user data can be found, this is reported as failure to the frontend
   app. The app should make it clear how a user can sign up for the service.
5. The sign up box should ask for the email & password with a password
   confirmation input box. This should offer tips on how to choose a good
   password, as well as a warning that the credentials **cannot** be changed. It
   should also have a password "entropy" indicator and it should reject
   passwords that are too weak.
6. The sign up process is just a convenience as alternatively the service could
   create accounts on the fly for any public keys it had not seen
   before. However, this may prove confusing for a user who mistypes their email
   or password and thus logs in to an empty account. Also, having a dedicated
   sign up box allows to validate the password and provide tips to the user on
   how to make the most of the service.
7. Once the user data is retrieved from the backend, it is decrypted in the
   browser and the user home page can be rendered. In particular, the user data
   blob contains:
   - A **user profile** with name, surname, email address, location, profile
     picture etc. There are 3 visibility settings for each one of the fields in
     the profile: _private_ (field withheld at all times), _network_ (only
     visible by a selection of groups from the user's network), _public_
     (everyone on the internet can see the field). By default everything is
     private.
   - A list of groups of public keys. This defines the user's network. The
     groups are similar to Google+ circles, it allows to organise the contacts
     semantically as well as to share extended profile information with selected
     groups.
8. The actions a visitor who's not signed in can take are:
   - Search for a user by public key or any other profile data.
   - Sign in
   - Sign up
9. The actions a signed in user can take are as follows:
   - Search for a user by public key or any other profile data.
   - Create/delete/rename groups of users as well as add/remove users from
     already existing groups.
   - The user can post to any of the groups as well as to a particular user (in
     which case we say the user sent a private message). A post consists of text
     and attached images.
   - The user can encrypt a file for a list of users to be saved locally as well
     as decrypt a local file.
   - The user can mark another user as trusted (see section 11 below).
   - Sign out - nothing to do on the backend, just delete the session data
     locally in the browser.
   - Delete account - delete the all data that the backend knows to be
     associated with the given public key.
10. Search functionality should be built into the service. At a minimum, one can
    search by a public key + any other public information from a user
    profile. Searching in one's groups will be implemented in the browser (the
    backend does have access to a user's network). The minimum information
    returned by search for a user that does not share any profile information is
    the public key with an identicon computed from the key used as the default
    profile picture.
11. **Web of trust** - a trust relation between users will be implemented such
    that:
    - User A can trust user B. The trust relation is unidirectional and it
      amounts to user A signing user B's profile. The keys a user trusts are
      made public such that when looking at a user's profile, the chain of trust
      can be visualised. An alternative would be for the trust relation to be
      represented by signing only the key, such that a user can change her
      profile without losing all signatures. It's not clear if this version is
      more vulnerable to key theft as the attacker may have no incentive to
      change the profile data anyway. Discuss.
    - The semantics of the trust relation is that the identity of the user was
      verified through a trusted channel. This is another way of saying that the
      user is really who they say they are. Example of trusted channels are
      exchanging the public key in person or via another online channel the user
      already trusts (email or twitter for example, although beware).
    - When logged in and looking at a user's profile, there shall be a "Trust"
      button.
