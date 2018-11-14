#!/usr/bin/python3 -tt
import sys
import os
import argparse
import getpass
from crypt import CryptCipher


def parse_arguments():
    parser = argparse.ArgumentParser(description='Encrypts your files.')
    parser.add_argument('file', help='file to encrypt')
    parser.add_argument('operation', choices=['e', 'd'],
        help='e - encrypt or d - decrypt file')

    return parser.parse_args()



def get_key(confirmation=True):
    try:
        while True:
            key = getpass.getpass('Key: ')
            if confirmation is False:
                break
            elif len(key) > 0 and key == getpass.getpass('Confirm Key: '):
                break
            else:
                print('Sorry, try again')
    except:
        print('\nKeyboardInterrupt')
        sys.exit(1)

    return key



def read_file(file, mode):
    try:
        f = open(file, mode)
    except IOError as e:
        print(e.args[1])
        sys.exit(e.args[0])
    else:
        try:
            data = f.read()
        finally:
            f.close()

    return data



def write_file(file, data, mode):
    try:
        f = open(file, mode)
    except IOError as e:
        print(e.args[1])
        sys.exit(e.args[0])
    else:
        try:
            f.write(data)
        finally:
            f.close()



if __name__ == '__main__':
    args = parse_arguments()
    cipher = CryptCipher()

    if args.operation == 'e':
        data = read_file(args.file, 'r')
        key = get_key()
        data = cipher.encrypt(data, key)
        write_file((args.file + '.encr') ,data, 'wb')
    else:
        data = read_file(args.file, 'rb')
        key = get_key(False)
        try:
            data = cipher.decrypt(data, key)
        except Exception as e:
            print(e.args[0])
            sys.exit(-1)
        write_file('a.out' ,data, 'w')

