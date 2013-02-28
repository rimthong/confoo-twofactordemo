confoo-twofactordemo
====================
Run with:

    export YUBIKEY_SECRET=<Your secret key>
    export YUBIKEY_CLIENT=<Your client ID>
    npm install
    node app

Note that the envars are optional, but if set, they will allow you to check Yubico's response hash.

The interesting part is in routes/index.litcoffee 
