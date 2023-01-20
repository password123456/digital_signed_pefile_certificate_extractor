__author__ = 'https://github.com/password123456/'
__version__ = '1.0.0-230120'

import os
import pefile

from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

_home_path = f'{os.getcwd()}'


def get_signature_info(_file_name):
    # Open the executable file
    pe = pefile.PE(_file_name)
    if hex(pe.DOS_HEADER.e_magic) == '0x5a4d':
        address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]].VirtualAddress
        size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]].Size

        if address == 0:
            _result = '** No Digital-Signed File **'
        else:
            with open(_file_name, 'rb') as fh:
                fh.seek(address)
                thesig = fh.read(size)

            signature = cms.ContentInfo.load(thesig[8:])
            i = 0
            for cert in signature['content']['certificates']:
                i = i + 1
                x509_pem_cert = x509.load_der_x509_certificate(cert.dump(), default_backend())
                if x509_pem_cert.signature_hash_algorithm.name.lower() == 'sha256':
                    if 'code signing' in x509_pem_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value.lower():
                        subject_name = x509_pem_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                        issuer_name = x509_pem_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                        signature_hash_algorithm = x509_pem_cert.signature_hash_algorithm.name
                        thumbprint = x509_pem_cert.fingerprint(hashes.SHA256()).hex()
                        serial_number = hex(x509_pem_cert.serial_number)[2:].zfill(32)

                        print(f'- FileName: {_file_name}')
                        print(f'- Digest Algorithm: {signature_hash_algorithm}')
                        print(f'- Certificate Issuer: {issuer_name}')
                        print(f'- Certificate Subject: {subject_name}')
                        print(f'- Serial_Number: {serial_number}')
                        print(f'- Thumbprint: {thumbprint}')

                        _export_certificate = '%s/1_%s.der' % (_home_path, i)
                        with open(_export_certificate, 'wb+') as f:
                            f.write(cert.dump())


if __name__ == '__main__':
    get_signature_info(f"{_home_path}/test/PCHunter32.exe")
