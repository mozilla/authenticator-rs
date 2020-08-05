from rich.console import Console
from rich.logging import RichHandler

import argparse
import logging
import requests

console = Console()
log = logging.getLogger("webdriver-driver")

parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(help="sub-command help")

parser.add_argument(
    "--verbose", "-v", help="Be more verbose", action="count", default=0
)
parser.add_argument(
    "--url",
    default="http://localhost:8080/webauthn/authenticator",
    help="webdriver url",
)


def device_add(args):
    data = {
        "protocol": args.protocol,
        "transport": args.transport,
        "hasResidentKey": args.residentkey in ["true", "yes"],
        "isUserConsenting": args.consent in ["true", "yes"],
        "hasUserVerification": args.uv in ["available", "verified"],
        "isUserVerified": args.uv in ["verified"],
    }
    console.print("Adding new device: ", data)
    rsp = requests.post(args.url, json=data)
    console.print("Device ID: ", rsp.text)


parser_add = subparsers.add_parser("add", help="Add a device")
parser_add.set_defaults(func=device_add)
parser_add.add_argument(
    "--consent",
    choices=["yes", "no", "true", "false"],
    default="true",
    help="consent automatically",
)
parser_add.add_argument(
    "--residentkey",
    choices=["yes", "no", "true", "false"],
    default="no",
    help="indicate a resident key",
)
parser_add.add_argument(
    "--uv",
    choices=["no", "available", "verified"],
    default="no",
    help="indicate user verification",
)
parser_add.add_argument(
    "--protocol", choices=["ctap1/u2f", "ctap2"], default="ctap1/u2f", help="protocol"
)
parser_add.add_argument("--transport", default="usb", help="transport type(s)")


def device_delete(args):
    rsp = requests.delete(f"{args.url}/{args.delete}")
    console.print(rsp.text)


parser_delete = subparsers.add_parser("delete", help="Delete a device")
parser_delete.set_defaults(func=device_delete)
parser_delete.add_argument("id", type=int, help="device ID to delete")


def main():
    args = parser.parse_args()

    loglevel = logging.INFO
    if args.verbose > 0:
        loglevel = logging.DEBUG
    logging.basicConfig(
        level=loglevel, format="%(message)s", datefmt="[%X]", handlers=[RichHandler()]
    )

    try:
        args.func(args)
    except requests.exceptions.ConnectionError as ce:
        log.error(f"Connection refused to {args.url}: {ce}")


if __name__ == "__main__":
    main()
