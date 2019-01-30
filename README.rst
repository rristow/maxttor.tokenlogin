====================
maxttor.tokenlogin
====================

Plugin for Plone CMF 

The general concept behind a token-based authentication system is simple. Allow users to enter their username and password in order to obtain a token which allows them to fetch a specific resource - without using their username and password. Once their token has been obtained, the user can offer the token, which offers access to a specific resource for a time period, to the remote site.

Control Panel - options

Expiration-date - After this date the token will expires

IP Range safeguard (optional) - The token will be for these IP ranges.
