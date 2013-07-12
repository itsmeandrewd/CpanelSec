#!/usr/bin/env python
# Injection removal tool
# Andrew D.

from optparse import OptionParser
import sys
import re
import shutil
import signal
import sre_constants
import platform

class InjectCleaner:

    def __init__(self, options, args):
        self.force = options.force
        self.backup = options.backup
        self.listfile = options.listfile
        self.args = args
        try:
            self.regex = re.compile(args[0], re.MULTILINE | re.DOTALL)
        except re.error:
            print "\nInvalid regular expression! (check your syntax)"
            sys.exit(1)

    def listMode(self):
        return self.listfile

    def __red(self, text):
        if platform.system() == "Windows":
            return text
        return '\033[91m' + text + '\033[0m'

    def removeInjections(self, fname = None):
        if fname == None:
            fname = self.args[1]
        buffer = open(fname).read()

        if not self.force:
            print "\nFILE:  " + fname
            self.__confirm(buffer)

        if self.backup:
            shutil.copyfile(fname, fname + '.ibak')

        buffer = self.regex.sub('', buffer)

        output = open(fname, 'w')
        output.write(buffer)
        output.close()

    def __confirm(self, buffer):
        print "\nThe following text will be matched:\n"

        matches = self.regex.findall(buffer)
        if matches:
            for match in matches:
                print self.__red(match) + "\n"
        else:
            print self.__red("*** No match ***\n")

        choice = None
        while choice == None:
            try:
                choice = raw_input("Is this ok? (Y)es, (N)o, (A)lways confirm  ").lower()
            except EOFError:
                sys.exit(0)

            if choice == 'y':
                self.force = False
            elif choice == 'n':
                sys.exit(0)
            elif choice == 'a':
                self.force = True
            else:
                choice = None


def signal_handler(signal, frame):
    sys.exit(1)


def main():
    signal.signal(signal.SIGINT, signal_handler)

    parser = OptionParser(usage='usage: %prog [options] REGEX FILE')
    parser.add_option("-l", "--list-file", action='store_const', dest='listfile', const=True, default=False, help="use a list file")
    parser.add_option("-b", "--backup", action='store_const', dest='backup', const=True, default=False, help="make backup files")
    parser.add_option("-f", "--force", action='store_const', dest='force', const=True, default=False, help="supress confirmation notice")

    (options, args) = parser.parse_args()

    if len(args) != 2:
        parser.print_help()
        sys.exit(1)

    pyCleaner = InjectCleaner(options, args)

    try:
        if pyCleaner.listMode():
            for line in open(args[1]).readlines():
                pyCleaner.removeInjections(line.strip())
        else:
            pyCleaner.removeInjections()
    except IOError:
        print "\nFile " + args[1] + " not found!"
        sys.exit(1)

    print "\nRemoved injections (hopefully)."


if __name__ == "__main__":
    main()

