#!/usr/bin/env python3
import os.path
import sys
import traceback
from pathlib import Path
from typing import Generic

from colorama import init as colorama_init
from colorama import Fore
from colorama import Style
from enum import Enum
import inspect

class DebugLevel(Enum):
    INFO = 0
    WARN = 1
    ERROR = 2

def print_info(message):
    frame = inspect.currentframe()
    info = inspect.getframeinfo(frame)
    colorama_init()
    print(f"INFO::{Path(info.filename).name}:{info.lineno}:"
          f"{Fore.YELLOW}{message}{Style.RESET_ALL}")

def print_traceback(e :Exception, message: str):
    tb = traceback.extract_tb(e.__traceback__)
    filename, lineno, funcname, _ = tb[0]
    filename = Path(filename).name
    colorama_init()
    print(f'ERROR: {Fore.RED} {filename} Line:{lineno} Function:{funcname}\n"{message}"{Style.RESET_ALL}')
    sys.exit()

def exit_with_error(message :str):
    colorama_init()
    print(f"ERROR: {Fore.RED}{message}{Style.RESET_ALL}")
    sys.exit()

def print_warning(message):
    colorama_init()
    print(f"WARNING: {Fore.YELLOW}{message}{Style.RESET_ALL}")