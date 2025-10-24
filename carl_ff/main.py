import pathlib
import argparse

from carl_ff import ClientAuthRememberList, ClientAuthRememberListEntry, ClientCert

parser = argparse.ArgumentParser(description='carl - parse and modify the Firefox ClientAuthRememberList')
parser.add_argument('--list', help='path to the ClientAuthRememberList.bin file')

subparsers = parser.add_subparsers(dest='cmd')

parser_list = subparsers.add_parser('list', help='list the current ClientAuthRememberList (default)')

parser_del = subparsers.add_parser('del', help='delete entries from the ClientAuthRememberList')
parser_del.add_argument('id', type=int, help='id of the entry to remove')

parser_add = subparsers.add_parser('add', help='add new entries to the ClientAuthRememberList')
parser_add.add_argument('--cert', type=argparse.FileType('r'), help='certificate to use for authentication')
parser_add.add_argument('--blocked', action='store_true', help='block client auth for the specified host')
parser_add.add_argument('--host', help='host to add')
parser_add.add_argument('--port', default=None, help='port to add (default: None)')
parser_add.add_argument('--scheme', default='https', help='scheme to add (default: https)')
parser_add.add_argument('--from-file', type=argparse.FileType('r'), help='file to add hosts from')


def confirm(prompt: str) -> bool:
    '''
    Ask the user for confirmation.

    Parameters:
        prompt      the prompt to display

    Returns:
        True if confirmed. False otherwise.
    '''
    result = input(prompt + ' [y/N] ')

    if result.lower() in ['y', 'yes', 'Y', 'Yes']:
        return True

    return False


def main():
    '''
    Main method :)
    '''
    args = parser.parse_args()

    if args.list is not None:
        remember_list = pathlib.Path(args.list)

    else:

        moz = pathlib.Path('~').expanduser() / '.mozilla' / 'firefox'
        remember_lists = list(moz.rglob('ClientAuthRememberList.bin'))

        if len(remember_lists) == 0:

            print('[-] Unable to auto-detect ClientAuthRemeberList.')
            print('[-] Use --list to specify the desired path.')
            return

        elif len(remember_lists) > 1:

            print('[-] Found multiple ClientAuthRememberLists.')
            print('[-] Use --list to specify the desired path.')
            print('[-] Found lists:')

            for entry in remember_lists:
                print(f'[-] \t{entry}')

            return

        else:
            remember_list = remember_lists[0]

    if not remember_list.is_file():
        remember_list.touch()

    client_list = ClientAuthRememberList.from_file(remember_list)

    if args.cmd in [None, 'list']:

        print(client_list)
        return

    if args.cmd in ['del']:

        try:
            client_list.remove_entry(args.id)

        except IndexError:
            print('[-] Error: The specified index does not exist!')
            return

        print(client_list)

        if confirm('Write changes?'):
            client_list.to_file(remember_list)

    if args.cmd in ['add']:

        if args.cert:
            cert = ClientCert.from_file(pathlib.Path(args.cert.name))

        elif args.blocked:
            cert = None

        else:
            print('[-] Error! Either --cert or --blocked needs to be used.')
            return

        if args.host:

            entry = ClientAuthRememberListEntry(args.host, cert, args.port, args.scheme)
            client_list.add_entry(entry)

        elif args.from_file:

            for line in args.from_file.readlines():

                line = line.strip()

                if line != '':

                    entry = ClientAuthRememberListEntry(line, cert)
                    client_list.add_entry(entry)

        else:
            print('[-] Error! No host(s) specified.')
            return

        print(client_list)

        if confirm('Write changes?'):
            client_list.to_file(remember_list)
