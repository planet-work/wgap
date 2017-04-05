import struct

from .message_pb2 import Header

from . import signing


RECORD_SEPARATOR = 0x1e
UNIT_SEPARATOR = 0x1f

MAX_HEADER_LENGTH = 255


def frame(payload, signer_config=None):
    """
    Frame, optionally sign and return the payload.

    """
    if isinstance(payload, str):
        payload = payload.encode('utf-8')
    payload_length = len(payload)
    header = Header(message_length=payload_length)

    # Sign header if config given.
    if signer_config is not None:

        # Only allow type signing.SignerConfig.
        if not isinstance(signer_config, signing.SignerConfig):
            raise RuntimeError('signer must be an instance of heka.signing.SignerConfig: got {}'.format(signer_config))

        signing.sign_header(header, payload, signer_config)

    header_data = header.SerializeToString()
    header_length = len(header_data)

    # Sanity check since header length is 1 byte.
    if header_length > MAX_HEADER_LENGTH:
        raise RuntimeError("Header is too long")

    return struct.pack(
        '!bb{}sb{}s'.format(header_length, payload_length),
        RECORD_SEPARATOR,
        header_length,
        header_data,
        UNIT_SEPARATOR,
        payload
    )
