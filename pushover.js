var Push = require( 'pushover-notifications' )

module.exports.send = function send(message,title) {
var p = new Push( {
  user: 'u467tiism7rzcdpowdy5uz6fsmbgqz',
  token: 'azmh3r4rqpohjb7vqqf3q2r37m2o22',
})

var msg = {
  // These values correspond to the parameters detailed on https://pushover.net/api
  // 'message' is required. All other values are optional.
  message: message,
  title: title,
  sound: 'magic',
  device: 'devicename',
  priority: 1
}

p.send( msg, function( err, result ) {
  if ( err ) {
    throw err
  }

  console.log( result )
})

}
