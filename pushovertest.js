const pushover = require('./pushover.js');

let msg =`

Hello There!

This is a test message to pushover

`
pushover.send(msg,"this is a test")
