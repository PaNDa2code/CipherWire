from .gui import Display
import argparse
from .caeser_cipher import CaesarCipher
from .playfair import Playfair

parser = argparse.ArgumentParser(
            prog="cipher_wire", 
            description="light wight python encryption utls",
            epilog="Stay safe." + chr(0x1F609)
        )

parser.add_argument("input", nargs="?",default=None, help="Input string")
parser.add_argument("-o", "--output", help="output of the program", required=False)
parser.add_argument("-f", "--file", help="input file of the program", required=False)
parser.add_argument("-k", "--key", help="provide the encryption key")
parser.add_argument("--method", help="the encryption method", choices=["ceaser_cipher", "playfiar"])
parser.add_argument("--gui", help="Starts the gui app", action="store_true")

args = parser.parse_args()


if args.gui:
    display = Display()
    exit(0)
if args.key is None:
    print(parser.format_usage())
    exit(0)

if args.input is not None:
    plan_text = args.input
elif args.file is not None:
    with open(args.file, "r") as file:
        plan_text = file.read()
else:
    print(parser.format_usage())
    exit(0)

match args.method:
    case "ceaser_cipher":
        cipher_text = CaesarCipher.encrypt(plan_text, args.key)
    case "playfair":
        cipher_text = Playfair.encrypt(plan_text, args.key)
    case _:
        exit()

print(cipher_text)
