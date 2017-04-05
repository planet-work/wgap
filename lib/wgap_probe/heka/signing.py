import hmac
import hashlib
from collections import namedtuple

from .message_pb2 import Header


SignerConfig = namedtuple('Signer', ('name', 'version', 'key', 'hash'))


HASH_NAME_TO_VALUE = {
    'sha1': Header.SHA1,
    'md5': Header.MD5,
}

HASH_NAME_TO_FUNCTION = {
    'sha1': hashlib.sha1,
    'md5': hashlib.md5,
}


def sign_header(header, payload, signer_config):
    """
    Sign a header with the given payload and cofiguration.

    """
    header.hmac_signer = signer_config.name
    header.hmac_key_version = signer_config.version
    header.hmac_hash_function = HASH_NAME_TO_VALUE[signer_config.hash]
    header.hmac = hmac.new(
        signer_config.key.encode(),
        payload,
        HASH_NAME_TO_FUNCTION[signer_config.hash]
    ).digest()
