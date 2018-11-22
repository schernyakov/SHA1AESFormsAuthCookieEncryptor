# SHA1AESFormsAuthCookieEncryptor
Node.js sha1/aes cookie encryptor for .net forms authentication with double sign.

## Setup

Encryptor configuration:

- `vk` (string) hex encoded validation key (system.web => machineKey, validationKey attr from your web.config ) 
- `dk` (string) hex encoded decryption key  (system.web => machineKey, decryptionKey attr from your web.config ) 

Ticket object:

```js
var ticket = {
  ticketVersion: 2,
  issueDate : new Date(),
  expirationDate : null,
  isPersistent : false,
  name : null,
  customData : '',
  cookiePath : '/'
}
```

## Example

```js
const vk = 'VALIDATION_KEY';
const dk = 'DECRYPTION_KEY';

// ticket required fields
var ed =  new Date( Date.now() + 86400000 );
var name = '1024';

// config
var encryptor = require("./encryptor") (vk , dk);

// generate encrypted cookie buffer
var tkb = encryptor.encrypt({expirationDate : ed, name : name});
var tiket = tkb.toString("hex");
```

