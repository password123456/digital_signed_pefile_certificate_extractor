__author__ = 'https://github.com/password123456/'
__version__ = '1.0.0-230120'

import os
import sys
import pefile
import argparse

from datetime import datetime
from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes


class Bcolors:
    Black = '\033[30m'
    Red = '\033[31m'
    Green = '\033[32m'
    Yellow = '\033[33m'
    Blue = '\033[34m'
    Magenta = '\033[35m'
    Cyan = '\033[36m'
    White = '\033[37m'
    Endc = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def get_signature_info(_file_name):
    # Open the executable file
    pe = pefile.PE(_file_name)
    if hex(pe.DOS_HEADER.e_magic) == '0x5a4d':
        address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]].VirtualAddress
        size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]].Size

        if address == 0:
            print(f'- FileName: {_file_name}\n- Result: ** No Digital-Signed File **')
        else:
            with open(_file_name, 'rb') as fh:
                fh.seek(address)
                thesig = fh.read(size)

            signature = cms.ContentInfo.load(thesig[8:])
            for cert in signature['content']['certificates']:
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
                        print(f'- Serial Number: {serial_number}')
                        print(f'- Thumbprint: {thumbprint}')

                        _export_certificate = f'{os.getcwd()}/{datetime.today().strftime("%Y%m%d%H%M%S")}_{serial_number}.der'
                        print(_export_certificate)
                        with open(_export_certificate, 'wb+') as f:
                            f.write(cert.dump())


def main():
    print(f'\n')
    print(f'{Bcolors.Green}▌║█║▌│║▌│║▌║▌█║ {Bcolors.Red}py cerificate extractor {Bcolors.White}v{__version__}{Bcolors.Green} ▌│║▌║▌│║║▌█║▌║█{Bcolors.Endc}\n')
    opt = argparse.ArgumentParser()
    opt.add_argument('--file', help='ex) /home/download/pefile.exe')

    if len(sys.argv) < 1:
        opt.print_help()
        sys.exit(1)
    else:
        options = opt.parse_args()
        print(f'- Run time: {datetime.today().strftime("%Y-%m-%d %H:%M:%S")}')
        print(f'- For questions contact {__author__}')

        if options.file:
            if os.path.exists(options.file):
                print(f'{Bcolors.Green}------------------------------------->{Bcolors.Endc}\n')
                get_signature_info(options.file)
            else:
                print(f'{Bcolors.Red}------------------------------------->{Bcolors.Endc}\n')
                print(f'- FileName: {options.file}')
                print(f'- Result: {options.file} is not a file or exists.')
                sys.exit(1)
        else:
            opt.print_help()
            sys.exit(1)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print(f'{Bcolors.Yellow}- ::Exception:: Func:[{__name__.__name__}] Line:[{sys.exc_info()[-1].tb_lineno}] [{type(e).__name__}] {e}{Bcolors.Endc}')
