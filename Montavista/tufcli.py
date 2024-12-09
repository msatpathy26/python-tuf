#!/usr/bin/env python3
# Copyright Montavista Software LLC.
"""
TUF command line utility

This module interacts with the underlying application code for:
* key management
* Repository management

Add/Remove/modify any CLI command using this module only

For details on using CLI run: python3 tufcli.py --help

"""
import argparse
import cmd_handler

# Create the argument parser
parser = argparse.ArgumentParser(
    description="Manage keys and repo configurations")


# Add primary subparsers for 'generatekey'
subparsers = parser.add_subparsers(dest='command')

# 'create' subparser
genkey_parser = subparsers.add_parser('generatekey', help="Generates a new key pair",
                                        description="Generates a new keypair")
# Adding a required 'role' argument with choices
genkey_parser.add_argument('-r', '--role', choices=['root', 'targets', 'timestamp', 'snapshot'],
                             help="Select a role")
# Adding a required key-type argument with choices
genkey_parser.add_argument('-t', '--type', choices=['rsa', 'ecdsa', 'ed25519'],
                             help="Select encryption algorithm")
# Adding an optional key-size argument, defaulting to 2048 if not provided
genkey_parser.add_argument('-s', '--size', type=int, choices=[1024, 2048, 3072, 4096],
                             help="An optional key size")
# Adding an optional 'key-name' argument, defaulting to an empty string if not provided
genkey_parser.add_argument('-n', '--name', type=str,
                             help="An optional key name")
# Adding an optional 'key-directory' argument, defaulting to an empty string
genkey_parser.add_argument('-d', '--dir', type=str,
                             help="An optional directory path")
# Adding an optional 'password' argument (flag), defaulting to False if not provided
genkey_parser.add_argument('-p', '--password', action='store_true',
                             help="An optional flag for password")
genkey_parser.add_argument('-c', '--config', type=str, default='', help="Yaml config file for holding\
                           parameters for key generation.Any individual parameter value will override it if passed \
                           alongside.")
genkey_parser.set_defaults(func=cmd_handler.handle_generatekey)




args = parser.parse_args()

if args.command == "generatekey":
    if ((args.role and args.type) or (args.config)):
        args.func(**vars(args))
    else:
        genkey_parser.print_usage()
else:
    parser.print_usage()