certbot-dns-loopia
=====================

Loopia_ DNS Authenticator plugin for Certbot based on the ISPConfig DNS plugin

This plugin automates the process of completing a ``dns-01`` challenge by
creating, and subsequently removing, TXT records using the Loopia XML-RPC API.

.. _Loopia: https://www.loopia.com/
.. _certbot: https://certbot.eff.org/

Installation
------------

::

    pip install certbot-dns-loopia


Named Arguments
---------------

To start using DNS authentication for loopia, pass the following arguments on
certbot's command line:

============================================================= ==============================================
``--authenticator certbot-dns-loopia:dns-loopia``          select the authenticator plugin (Required)

``--certbot-dns-loopia:dns-loopia-credentials``         loopia Remote User credentials
                                                              INI file. (Required)

``--certbot-dns-loopia:dns-loopia-propagation-seconds`` | waiting time for DNS to propagate before asking
                                                              | the ACME server to verify the DNS record.
                                                              | (Default: 10, Recommended: >= 600)
============================================================= ==============================================

(Note that the verbose and seemingly redundant ``certbot-dns-loopia:`` prefix
is currently imposed by certbot for external plugins.)


Credentials
-----------

An example ``credentials.ini`` file:

.. code-block:: ini

   certbot_dns_loopia:dns_loopia_username = myremoteuser
   certbot_dns_loopia:dns_loopia_apikey = verysecureapikey
   certbot_dns_loopia:dns_loopia_endpoint = https://localhost:8080/remote/json.php

The path to this file can be provided interactively or using the
``--certbot-dns-loopia:dns-loopia-credentials`` command-line argument. Certbot
records the path to this file for use during renewal, but does not store the
file's contents.

**CAUTION:** You should protect these API credentials as you would the
password to your loopia account. Users who can read this file can use these
credentials to issue arbitrary API calls on your behalf. Users who can cause
Certbot to run using these credentials can complete a ``dns-01`` challenge to
acquire new certificates or revoke existing certificates for associated
domains, even if those domains aren't being managed by this server.

Certbot will emit a warning if it detects that the credentials file can be
accessed by other users on your system. The warning reads "Unsafe permissions
on credentials configuration file", followed by the path to the credentials
file. This warning will be emitted each time Certbot uses the credentials file,
including for renewal, and cannot be silenced except by addressing the issue
(e.g., by using a command like ``chmod 600`` to restrict access to the file).


Examples
--------

To acquire a single certificate for both ``example.com`` and
``*.example.com``, waiting 900 seconds for DNS propagation:

.. code-block:: bash

   certbot certonly \
     --authenticator certbot-dns-loopia:dns-loopia \
     --certbot-dns-loopia:dns-loopia-credentials /etc/letsencrypt/.secrets/domain.tld.ini \
     --certbot-dns-loopia:dns-loopia-propagation-seconds 900 \
     --server https://acme-v02.api.letsencrypt.org/directory \
     --agree-tos \
     --rsa-key-size 4096 \
     -d 'example.com' \
     -d '*.example.com'
