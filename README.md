# simplenoteserver

A very simple server implementing the SimpleNote API. It consists of a Cherrypy application, which allows storage of notes through the SimpleNote API. If finished and tested it could be used to host a server to synchronise notes with less privacy issues.

Currently it supports the following features:
- CRUD notes
- Tags
- Move notes to the trash
- Versioning

There is no database as all notes are mapped into text files. An JSON index keeps the metadata available for faster access.

Authentication is based on the existence of a folder and the contents of a token file. This token contains a salt and a secret computed with the password and the salt (sha1, 100x times).

## Requirements

- Python libs: Cherrypy 3.5, hashlib, json, urlparse, ...


## Disclaimer

 __Consider this software to be an hack, not a full blown SimpleNote server. Do not sync any important notes with this software. This is for testing purposes only! There are many validations missing, many failure modes that are simply ignored and really bad coding decisions all over the place. This was the result of a couple of hours learning the API.__

__For real notes please use the official SimpleNote service from Automatic. It's simple and extremely robust. This software and myself are in no way affiliated with Automatic.__
