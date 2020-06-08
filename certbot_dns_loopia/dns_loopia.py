"""DNS Authenticator for Loopia."""
import logging
import xmlrpc.client
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Loopia

    This Authenticator uses Loopias XML-RPC API to fulfill a dns-01 challenge.
    """

    description = "Obtain certificates using a DNS TXT record (if you are using Loopia for DNS)."
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=120
        )
        add("credentials", help="Loopia credentials INI file.")

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return (
            "This plugin configures a DNS TXT record to respond to a dns-01 challenge using "
            + "Loopias XML-RPC API."
        )

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            "credentials",
            "Loopia credentials INI file",
            {
                "endpoint": "URL of the Loopia API.",
                "username": "Username for Loopia API.",
                "apikey": "API key for Loopia API.",
            },
        )

    def _perform(self, domain, validation_name, validation):
        self._get_loopia_client().add_txt_record(
            domain, validation_name, validation, self.ttl
        )

    def _cleanup(self, domain, validation_name, validation):
        self._get_loopia_client().del_txt_record(
            domain, validation_name
        )

    def _get_loopia_client(self):
        return _LoopiaClient(
            self.credentials.conf("endpoint"),
            self.credentials.conf("username"),
            self.credentials.conf("apikey"),
        )


class _LoopiaClient(object):
    """
    Encapsulates all communication with the Loopia XML-RPC API.
    """

    def __init__(self, endpoint, username, apikey):
        logger.debug("creating loopiaclient")
        self.endpoint = 'https://api.loopia.se/RPCSERV'
        self.username = username
        self.apikey = apikey
        self.client = xmlrpc.client.ServerProxy(
            uri=self.endpoint,
            encoding='utf-8',
            verbose=False
        )

    def add_txt_record(self, domain, record_name, record_content, record_ttl):
        txt = {
            'type': 'TXT',
            'ttl': record_ttl,
            'priority': 0,
            'rdata': record_content,
            'record_id': 999
        }
        zone_name = self._find_managed_zone(domain, record_name)
        record_name = record_name.replace(zone_name, "")[:-1]
        response = self.client.addZoneRecord(self.username, self.apikey, zone_name, record_name, txt)
        if not response == 'OK':
            raise errors.PluginError("Failed to add TXT Record")

    def del_txt_record(self, domain, record_name):
        zone_name = self._find_managed_zone(domain, record_name)
        record_name = record_name.replace(zone_name, "")[:-1]
        response = self.client.removeSubdomain(self.username, self.apikey, zone_name, record_name)
        if not response == 'OK':
            raise errors.PluginError("Failed to remove TXT Record")

    def _find_managed_zone(self, domain, record_name):
        zone_dns_name_guesses = [record_name] + dns_common.base_domain_name_guesses(domain)
        return zone_dns_name_guesses[-2]
