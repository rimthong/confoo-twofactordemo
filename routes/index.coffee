https = require('https')
base32 = require('base32')
Crypto = (require 'cryptojs').Crypto
_ = require 'underscore'

module.exports = (app)->
  @users = [
    {
      user: "admin"
      password: "password"
      yubico_identity: "ccccccbggtft"
      googleCode: "JBSWY3DPEHPK3PXP"
    },
    {
      user: "schmuck"
      password: "password"
      yubico_identity: "fifjgjgkhcha"
      googleCode: "JBSWY3DPEHPK3PXX"
    }
  ]
  app.get '/', (req, res )->
    res.render 'index', { title: 'Confoo Demo' }
  app.post '/verify', (req, res )->
    #Check if user exists
    user =_.find @users, (user) ->
      user.user  is  req.body.user
    #Check if old style password works
    if user && user.password  is  req.body.password
      #Check if key format Yubikey or Google
      key = req.body.key
      if 32 <= key.length <= 48
        identity = extractYubicoIdentity key
        #Check to make sure identity matches
        if user.yubico_identity  is  identity
          #Call yubico HQ
          verifyYubicode key , user, res
        else
          res.render 'fail', {title: 'Confoo Demo' , reason: 'Unknown Yubico identity.' }
      else
        #Try to derive the same key with code and time
        otp = computeOTP(user.googleCode)
        if otp is key
          res.render 'authenticated', {title: 'Confoo Demo' , user: user.user }
        else
          res.render 'fail', {title: 'Confoo Demo' , reason: 'Bad Key.' }
    else
      res.render 'fail', {title: 'Confoo Demo' , reason: 'Wrong Username/Password' }
  app.get '/register', (req, res )->
    res.render 'register', { title: 'Confoo Demo' }
  app.post '/do_register', (req, res )->
    #Save user, generate key
    code = generateBase32Code()
    user =
      user: req.body.user
      password: req.body.password
      yubico_identity: extractYubicoIdentity req.body.yubicode
      googleCode: code
    @users.push user
    res.render 'do_register', { title: 'Confoo Demo', user:user.user, code:user.googleCode }

verifyYubicode = (code, user, response)->
  clientId = process.env['YUBIKEY_CLIENT'] || 1
  secretKey = process.env['YUBIKEY_SECRET']
  otp = code
  #You would probably use a better random here.
  nonce = Crypto.util.bytesToHex Crypto.util.randomBytes 20
  req = https.get "https://api2.yubico.com/wsapi/2.0/verify?id=#{clientId}&otp=#{otp}&nonce=#{nonce}", (res)->
    data = ""
    res.setEncoding('utf8')

    res.on 'data', (chunk) ->
      data = data + chunk

    res.on 'end', () ->
      lines = data.split "\n"
      result = {}
      #Create a friendlier object
      for line in lines
        line = line.split "="
        result[line[0]] = line[1]?.replace(/^\s+|\s+$/g, '')
      #restore stripped =
      result.h = result.h + "="
      #Check status
      if result.status  is  "OK"
        #Check nonce
        if result.nonce  is  nonce
          #Check same OTP
          if result.otp  is  otp
            #If we haven't changed our clientId we'll skip hashing
            if clientId  is  1 || !secretKey
                console.log "Warning: No hash configuration"
                response.render 'authenticated', {title: 'Confoo Demo' , user: user.user }
            else
              #Combine all parameters except  hash, in a single string no new line
              #Separate params with &, then HMAC-SHA1 it using private key
              message = "nonce=#{result.nonce}&otp=#{result.otp}&sl=#{result.sl}&status=#{result.status}&t=#{result.t}"
              key = Crypto.util.base64ToBytes secretKey
              hmac = Crypto.HMAC(Crypto.SHA1, message, key, null)
              computedHash = Crypto.util.hexToBytes hmac
              computedHash = Crypto.util.bytesToBase64 computedHash
              #Compare the hash
              if result.h  is  computedHash
                response.render 'authenticated', {title: 'Confoo Demo' , user: user.user }
              else
                response.render 'fail', {title: 'Confoo Demo' , reason: "Yubico responded with a bad signature hash, impersonator?" }
          else
            response.render 'fail', {title: 'Confoo Demo' , reason: "Yubico responded with a different otp, copy-paste attack?" }
        else
          response.render 'fail', {title: 'Confoo Demo' , reason: "Yubico responded with a different nonce, copy-paste attack?" }
      else
        response.render 'fail', {title: 'Confoo Demo' , reason: "Yubico responded with status: #{result.status}." }
        
    
  req.on 'error', (e)->
    console.log('problem with request: ' + e.message)
    response.render 'fail', {title: 'Confoo Demo' , reason: 'Unknown Yubico identity.' }

extractYubicoIdentity = (code) ->
  #the key is always 32 chars, the rest is identity
  code.slice 0,-32

#Below conversion and OTP code inspired by TOPT Draft http://tools.ietf.org/id/draft-mraihi-totp-timebased-06.html
#And JS implementation at http://blog.tinisles.com/2011/10/google-authenticator-one-time-password-algorithm-in-javascript/
#Provides a working example, will refactor for readability and eventually migrate components to external lib.

generateBase32Code = ()->
  #Granted, you'll want something a little more advanced than this
  base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  key = ""
  for i in [1..16]
    key = key + base32chars.charAt(Math.floor(Math.random()*(base32chars.length-1)))
  key
  
dec2hex = (s) ->
  return (if s < 15.5 then '0' else '') + Math.round(s).toString(16)

hex2dec = (s) ->
  return parseInt s, 16

base32tohex = (base32) ->
  base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  bits = ""
  hex = ""

  for char, index in base32.split ''
    val = base32chars.indexOf(char.toUpperCase())
    bits += leftpad(val.toString(2), 5, '0')

  for char, index in bits.split ''
    if index%4 is 0 && index < bits.length - 1
      chunk = bits.substr(index, 4)
      hex = hex + parseInt(chunk, 2).toString(16)
  hex

leftpad = (str, len, pad) ->
  if (len + 1 >= str.length)
    str = Array(len + 1 - str.length).join(pad) + str
  str

computeOTP = (seed)->
  key = base32tohex seed
  epoch = Math.round(new Date().getTime() / 1000.0)
  time = leftpad(dec2hex(Math.floor(epoch / 30)), 16, '0')
  bytesTime = Crypto.util.hexToBytes time
  bytesKey = Crypto.util.hexToBytes key
  hmac = Crypto.HMAC(Crypto.SHA1, bytesTime, bytesKey, null)
  offset = hex2dec(hmac.substr(hmac.length - 1))
  otp = (hex2dec(hmac.substr(offset * 2, 8)) & hex2dec('7fffffff')) + ''
  otp = otp.substr(otp.length - 6, 6)
  otp
