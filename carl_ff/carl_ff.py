from __future__ import annotations

import re
import base64
import struct
import pathlib
import datetime

from cryptography import x509


class ClientAuthRememberList:
    '''
    Firefox stores mTLS auth decisions within a file called ClientAuthRememberList.bin.
    This class basically represents the contents of this file.
    '''

    def __init__(self) -> None:
        '''
        Initializes an empty ClientAuthRememberList object.

        Parameters:
            None

        Returns:
            None
        '''
        self.entries_allowed = []
        self.entries_blocked = []

    def __str__(self) -> str:
        '''
        Print a formatted version of the ClientAuthRememberList.

        Parameters:
            None

        Returns:
            formatted list.
        '''
        ctr = 0
        buf = '[+] ClientAuthRememberList:\n'
        buf += '[+]\n'
        buf += '[+]\tAllowed Entries:\n'

        for  entry in self.entries_allowed:
            
            if entry.cert is not None:

                buf += f'[+]\t\t{ctr}.) {entry}\n'
                ctr += 1

        buf += '[+]\n'
        buf += '[+]\tBlocked Entries:\n'

        for entry in self.entries_blocked:

            if entry.cert is None:

                buf += f'[+]\t\t{ctr}.) {entry}\n'
                ctr += 1

        return buf[:-1]

    def add_entry(self, entry: ClientAuthRememberListEntry) -> None:
        '''
        Add a new entry to the list.

        Parameters:
            entry           the entry to add

        Returns:
            None
        '''
        if entry.cert is None:
            self.entries_blocked.append(entry)

        else:
            self.entries_allowed.append(entry)

    def remove_entry(self, position: int) -> None:
        '''
        Remove the entry at the spcified position.

        Parameters:
            position        position of the entry to remove

        Returns:
            None
        '''
        if position < len(self.entries_allowed):
            del self.entries_allowed[position]

        else:
            del self.entries_blocked[position - len(self.entries_allowed)]

    def to_bytes(self) -> bytes:
        '''
        Transform the list to bytes. This creates the contents of ClinetAuthRememberList.bin.

        Parameters:
            None

        Returns:
            bytes as used in Firefox ClientAuthRememberList
        '''
        buf = b''

        for entry in self.entries_allowed + self.entries_blocked:

            slot_buf = b''
            slot_buf += struct.pack('>H', 1)

            last_modify_days = (entry.last_modified - datetime.datetime(1970, 1, 1)).days
            slot_buf += struct.pack('>H', last_modify_days)

            checksum = 1 ^ last_modify_days
            entry_bytes = entry.to_bytes()

            ctr = 0

            while ctr < len(entry_bytes):

                checksum ^= struct.unpack_from('>H', entry_bytes, ctr)[0]
                slot_buf += entry_bytes[ctr:ctr + 2]

                ctr += 2

            slot_buf = struct.pack('>H', checksum) + slot_buf
            buf += slot_buf

        return buf

    def to_file(self, path: pathlib.Path) -> None:
        '''
        Write the ClientAuthRememberList to a file.

        Parameters:
            path            path to write to

        Returns:
            None
        '''
        path.write_bytes(self.to_bytes())

    def from_file(path: pathlib.Path) -> ClientAuthRememberList:
        '''
        Parse the ClientAuthRememberList.bin file.

        Parameters:
            path        path of ClientAuthRememberList.bin

        Returns:
            None
        '''
        data = path.read_bytes()
        client_list = ClientAuthRememberList()

        if len(data) == 0:
            return client_list

        if len(data) % (ClientAuthRememberListEntry.ENTRY_LENGTH + 6) != 0:
            raise ValueError(f'Length mismatch: {len(data)} % {ClientAuthRememberListEntry.ENTRY_LENGTH + 6} != 0')

        slots = len(data) // (ClientAuthRememberListEntry.ENTRY_LENGTH + 6)

        for ctr in range(slots):

            try:
                start = (ClientAuthRememberListEntry.ENTRY_LENGTH + 6) * ctr
                end = start + ClientAuthRememberListEntry.ENTRY_LENGTH + 6

                entry_data = data[start:end]
                (checksum, static, last_modified_rel) = struct.unpack('>HHH', entry_data[0:6])

                last_modified = datetime.datetime(1970, 1, 1) + datetime.timedelta(days=last_modified_rel)
                entry = ClientAuthRememberListEntry.from_bytes(entry_data[6:], last_modified)

                client_list.add_entry(entry)

            except Exception as e:
                pass

        return client_list


class ClientAuthRememberListEntry:
    '''
    Represents a single entry within the ClientAuthRememberList.bin.
    '''
    KEY_LENGTH = 0x100
    ENTRY_LENGTH = 0x500
    
    def __init__(self, host: str, cert: ClientCert, port: int = None, scheme: str = 'https', last_modified: datetime = None) -> None:
        '''
        Create a new entry with all necessay values.

        Parameters:
            host                host the mTLS decision belongs to
            cert                certificate to use for the host
            port                port of the service
            scheme              scheme of the service
            last_modified       timestamp of last modification

        Returns:
            None
        '''
        self.host = host
        self.cert = cert

        self.port = port
        self.scheme = scheme
        self.last_modified = last_modified
        self.tld = '.'.join(host.split('.')[-2:])
    
        if last_modified is None:
            self.last_modified = datetime.datetime.now()

    def to_bytes(self) -> bytes:
        '''
        Transform the entry to bytes. This creates the format used in ClientAuthRememberList.bin.

        Parameters:
            None

        Returns:
            Byte form of the entry
        '''
        buf = self.host.encode('ascii')
        buf += b',,^partitionKey=%28'
        buf += self.scheme.encode('ascii')
        buf += b'%2C'
        buf += self.tld.encode('ascii')

        if self.port is not None:
            buf += b'%2C'
            buf += str(self.port).encode('ascii')

        buf += b'%29'

        while len(buf) < ClientAuthRememberListEntry.KEY_LENGTH:
            buf += b'\x00'

        if self.cert is not None:

            cert_buf = b'\x00\x00\x00\x00' # module ID
            cert_buf += b'\x00\x00\x00\x00' # entry ID

            cert_buf += struct.pack('>I', self.cert.get_serial_len())
            cert_buf += struct.pack('>I', self.cert.get_issuer_len())

            cert_buf += self.cert.get_serial_bytes()
            cert_buf += self.cert.issuer

            buf += base64.b64encode(cert_buf)

        else:

            cert_buf = b'no client certificate'
            buf += cert_buf

        while len(buf) < ClientAuthRememberListEntry.ENTRY_LENGTH:
            buf += b'\x00'

        return buf

    def from_bytes(data: bytes, last_modified: datetime) -> ClientAuthRememberListEntry:
        '''
        Parse a ClientAuthRememberListEntry from byte data.

        Parameters:
            data            byte data to parse from
            last_modified   time of last modification

        Returns:
            ClientAuthRememberListEntry
        '''
        host, remaining = data.split(b',,', 1)
        host = host.decode()

        regex = re.compile(b'%28(\\w+)%2C([a-zA-Z0-9.-]+)(:?%2C(\\d+))?%29')
        match = regex.search(remaining)

        scheme = match.group(1).decode()
        domain = match.group(2).decode()
        port = match.group(3)

        cert_data = data[ClientAuthRememberListEntry.KEY_LENGTH:].rstrip(b'\x00')
        cert = None

        if cert_data != b'no client certificate':

            cert_data = base64.b64decode(cert_data)
            serial_len, issuer_len = struct.unpack('>II', cert_data[8:16])

            serial_bytes = cert_data[16:16 + serial_len]
            issuer_bytes = cert_data[16 + serial_len: 16 + serial_len + issuer_len]

            cert = ClientCert(int.from_bytes(serial_bytes, 'big'), issuer_bytes)

        return ClientAuthRememberListEntry(host, cert, port, scheme, last_modified)

    def __str__(self) -> str:
        '''
        Creates a string representation.

        Parameters:
            None

        Returns:
            None
        '''
        if self.port is not None:
            return f'{self.scheme}://{self.host}:{self.port}'

        return f'{self.scheme}://{self.host}'


class ClientCert:
    '''
    Stripped down version of x509 certificate that only contains the required values.
    '''

    def __init__(self, serial_number: int, issuer: bytes):
        '''
        Create a new ClientCert.

        Parameters:
            serial_number           serial_number of the certificate
            issuer                  DER encoded issuer of the cert

        Returns:
            None
        '''
        self.issuer = issuer
        self.serial_number = serial_number

    def get_serial_bytes(self) -> int:
        '''
        Return serial number as bytes.

        Parameters:
            None

        Returns:
            serial number as bytes
        '''
        return (self.serial_number).to_bytes(20).lstrip(b'\x00')

    def get_serial_len(self) -> int:
        '''
        Return the byte length of the serial number.

        Parameters:
            None

        Returns:
            byte count necessary to store the serial number.
        '''
        return len(self.get_serial_bytes())

    def get_issuer_len(self) -> int:
        '''
        Return the byte length of the DER encoded issuer name.

        Parameters:
            None

        Returns:
            byte count necessary to store the issuer name.
        '''
        return len(self.issuer)

    def from_file(path: pathlib.Path) -> ClientCert:
        '''
        Create a ClientCert from a x509 file.

        Parameters:
            path            path to the x509 cert

        Returns:
            None
        '''
        data = path.read_bytes()
        cert = x509.load_pem_x509_certificate(data)

        return ClientCert(cert.serial_number, cert.issuer.public_bytes())
