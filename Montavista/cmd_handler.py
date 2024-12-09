#!/usr/bin/env python3
# Copyright Montavista Software LLC.
"""
TUF command handler

Contains functions to process the command line inputs and
call underlying functions for repository and key management.
Not designed for direct execution.
"""

from key.rsa import RSAkeyGenerator
from log import print_warning
from log import exit_with_error
from pathlib import Path
import yaml

def parse_config(yaml_cfg_file: str):
    """
    Parses command line options and passes those as parameters to key generation method

    Args: ( A dictionary of following arguments )
        { 'role' : str,
          'type' :str,
          'name' :str,
          'dir' :str,
          'size' :int,
          'password' :bool,
          'config' :str
        }
    """

    if not Path(yaml_cfg_file).is_file():
        print_warning("Config file path doesn't exist!!. Ignoring..")
        return None
    try:
        with open(yaml_cfg_file,"r") as _config_file:
            config = yaml.safe_load(_config_file)
    except Exception as e:
        # Handle the exception and print the error message
        exit_with_error(f"Error in loading config file: {e}")
    return config

def handle_generatekey(**args):
    """
    Parses command line options and passes those as parameters to key generation method

    Args: ( A dictionary of following arguments )
        { 'role' : str,
          'type' :str,
          'name' :str,
          'dir' :str,
          'size' :int,
          'password' :bool,
          'config' :str
        }
    """
    # read from yaml config
    cfg_file = args.pop('config', None)
    cfgfile_params = None
    if cfg_file:
        cfgfile_params = parse_config(cfg_file)

    repo_parameters = dict.fromkeys(args.keys())
    #Initialize available params from the config file first
    if cfgfile_params:
        for cfg in cfgfile_params:
            repo_parameters.update({cfg:cfgfile_params[cfg]})

    #overwrite with available options passed explicitly
    for p in args:
        if args[p]:
            repo_parameters[p] = args[p]

    #Check for valid role
    if repo_parameters['role'] not in ("root", "targets", "timestamp", "snapshot"):
        exit_with_error(f"Invalid role name:{repo_parameters['role']}")

    #Truncate keyfile names to 32 chars max
    if repo_parameters['name']:
        if len(repo_parameters['name']) > 32:
            repo_parameters['name'] = repo_parameters['name'][:32]
    else:
        repo_parameters['name'] = ""

    if repo_parameters['size'] not in (1024, 2048, 3072, 4096):
        repo_parameters['size'] = 2048

    if not repo_parameters["dir"]:
        repo_parameters["dir"] = "./keys/"

    if repo_parameters['type'].upper() == 'RSA':
        RSAkeyGenerator(role = repo_parameters["role"],
                        key_size = repo_parameters["size"],
                        key_name = repo_parameters["name"],
                        key_dir = repo_parameters["dir"],
                        password = False
                        ).generate()
    else:
        exit_with_error(f"Encryption type {repo_parameters['type']} is not supported")
