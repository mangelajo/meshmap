"""Command-line interface for meshmap."""

import argparse
import asyncio
import json
import sys

from meshmap.scanner import MeshScanner


async def async_main(args: argparse.Namespace) -> int:
    """Async main function."""
    try:
        # Create scanner and connect
        scanner = MeshScanner(args.serial_port, debug=args.debug)
        await scanner.connect()

        # If showing all contacts, dump them as JSON and exit
        if args.all_contacts:
            contacts = await scanner.get_all_contacts()
            print("\n" + "="*50)
            print(f"All contacts ({len(contacts)} total):")
            print("="*50)
            print(json.dumps(contacts, indent=2, sort_keys=True))
            await scanner.disconnect()
            return 0

        # If packet sniffer requested, sniff and decode packets
        if args.sniff:
            # Load private key if provided
            private_key_hex = None
            if args.decrypt:
                try:
                    with open(args.decrypt, 'r') as f:
                        private_key_hex = f.read().strip()
                    # Validate it's hex and correct length (128 chars = 64 bytes)
                    if len(private_key_hex) != 128:
                        print(
                            f"Error: Invalid private key length. "
                            f"Expected 128 hex chars, got {len(private_key_hex)}",
                            file=sys.stderr
                        )
                        return 1
                    if not all(c in '0123456789abcdefABCDEF' for c in private_key_hex):
                        print("Error: Invalid private key format. Must be hexadecimal.", file=sys.stderr)
                        return 1
                    print(f"🔑 Loaded private key from {args.decrypt}")
                except FileNotFoundError:
                    print(f"Error: Private key file not found: {args.decrypt}", file=sys.stderr)
                    return 1
                except Exception as e:
                    print(f"Error loading private key: {e}", file=sys.stderr)
                    return 1

            # Parse channel names if provided
            channel_names = []
            if args.channels:
                channel_names = [ch.strip() for ch in args.channels.split(',')]
                print(f"📻 Will attempt to decrypt {len(channel_names)} channel(s): {', '.join(channel_names)}")

            await scanner.sniff_packets(
                duration=args.sniff,
                private_key_hex=private_key_hex,
                channel_names=channel_names,
                show_hexdump=args.hexdump
            )
            await scanner.disconnect()
            return 0

        # If RF discovery requested, listen for RF activity
        if args.rf_discovery:
            results = await scanner.discover_by_rf_activity(duration=args.rf_discovery)
            print("\n" + "="*50)
            print("RF Discovery Results:")
            print("="*50)
            print(json.dumps(results, indent=2, sort_keys=True, default=str))
            await scanner.disconnect()
            return 0

        # If guest login requested, login to specified contact
        if args.guest_login:
            contacts = await scanner.get_all_contacts()

            # Find the contact by name or public key prefix
            target_contact = None
            for pk, contact in contacts.items():
                name = contact.get('adv_name', '')
                if (args.guest_login.lower() in name.lower() or
                    args.guest_login.lower() in pk.lower()):
                    target_contact = contact
                    break

            if not target_contact:
                print(f"\n✗ Contact '{args.guest_login}' not found in contact list.")
                print("Available contacts:")
                for pk, contact in contacts.items():
                    print(f"  - {contact.get('adv_name')} ({pk[:16]}...)")
                await scanner.disconnect()
                return 1

            # Guest login and get neighbors
            result = await scanner.guest_login_and_get_neighbors(target_contact)

            if result:
                print("\n" + "="*50)
                print(f"Guest login results:")
                print("="*50)
                print(json.dumps(result, indent=2, sort_keys=True, default=str))

            await scanner.disconnect()
            return 0

        # Scan for 0-hop nodes
        nodes = await scanner.scan_zero_hop_nodes()

        # Print summary
        print("\n" + "="*50)
        print(f"Scan complete! Found {len(nodes)} 0-hop node(s).")
        print("="*50)

        if args.verbose and nodes:
            print("\nNode details:")
            for node in nodes:
                print(f"\n  Node: {node['name']}")
                print(f"    Type: {node['type']}")
                print(f"    Public Key: {node['public_key'][:16]}...")
                print(f"    Out Path Length: {node['out_path_len']}")
                print(f"    Last Advert: {node['last_advert']}")
                print(f"    Lat/Lon: {node['lat']}, {node['lon']}")

        # Disconnect
        await scanner.disconnect()
        return 0

    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        return 130
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


def main() -> int:
    """Main entry point for the meshmap CLI."""
    parser = argparse.ArgumentParser(
        description="Scan and map meshcore network graphs"
    )
    parser.add_argument(
        "serial_port",
        help="Serial port to connect to (e.g., /dev/ttyUSB0 or COM3)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--debug", "-d",
        action="store_true",
        help="Enable debug logging from meshcore"
    )
    parser.add_argument(
        "--all-contacts", "-a",
        action="store_true",
        help="Show all contacts in JSON format (including unknown paths)"
    )
    parser.add_argument(
        "--guest-login", "-g",
        type=str,
        metavar="NAME",
        help="Guest login to a contact and get its neighbor list (search by name or key)"
    )
    parser.add_argument(
        "--rf-discovery", "-r",
        type=int,
        metavar="SECONDS",
        help="Discover nearby nodes by listening to RF activity for N seconds"
    )
    parser.add_argument(
        "--sniff", "-s",
        type=int,
        metavar="SECONDS",
        help="Sniff and decode RF packets for N seconds (detailed packet analysis)"
    )
    parser.add_argument(
        "--decrypt",
        type=str,
        metavar="KEYFILE",
        help="Path to private key file for decrypting packets (use with --sniff)"
    )
    parser.add_argument(
        "--channels",
        type=str,
        metavar="NAMES",
        help="Comma-separated list of channel names to decrypt (e.g., '#general,#public')"
    )
    parser.add_argument(
        "--hexdump", "-x",
        action="store_true",
        help="Show hexdump of decrypted payloads (use with --sniff)"
    )
    parser.add_argument(
        "--baudrate", "-b",
        type=int,
        default=115200,
        help="Serial port baud rate (default: 115200)"
    )

    args = parser.parse_args()

    # Run the async main function
    return asyncio.run(async_main(args))


if __name__ == "__main__":
    sys.exit(main())
