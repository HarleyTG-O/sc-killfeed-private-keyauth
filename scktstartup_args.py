import os
from pathlib import Path
import argparse

# Path to the startup args file
BASE_PATH = Path("C:/Program Files/Harley's Studio/Star Citizen Kill Tracker")
ARGS_FILE = BASE_PATH / "startup_args.txt"

# Allowed flags
ALLOWED_FLAGS = {
    "fastload": "Enable fast loading (skip splash, skip checks)",
    "dev": "Developer mode (extra logging, debug UI)",
    "guest": "Guest mode (no user registration required)",
    "disableoverlay": "Disable the DeathLog overlay window",
    "disablediscordrpc": "Disable Discord Rich Presence integration",
    "disablewebhook": "Disable Discord webhooks/relays",
}

def write_startup_args(flags):
    """Write multiple startup flags to the startup_args.txt file."""
    flags = [flag.strip().lower() for flag in flags if flag.strip().lower() in ALLOWED_FLAGS]
    if not flags:
        raise ValueError(f"No valid flags provided. Allowed: {', '.join(ALLOWED_FLAGS.keys())}")
    BASE_PATH.mkdir(parents=True, exist_ok=True)
    with open(ARGS_FILE, "w") as f:
        f.write("\n".join(flags))
    print(f"Startup flags written to {ARGS_FILE}: {', '.join(flags)}")

def read_startup_args():
    """Read all startup flags from the startup_args.txt file."""
    if not ARGS_FILE.exists():
        return []
    with open(ARGS_FILE, "r") as f:
        flags = [line.strip().lower() for line in f if line.strip()]
    return [flag for flag in flags if flag in ALLOWED_FLAGS]

def get_flag_description(flag: str):
    return ALLOWED_FLAGS.get(flag, "Unknown flag")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Manage startup flags for SC Kill Tracker.")
    for flag in ALLOWED_FLAGS:
        parser.add_argument(f"--{flag}", action="store_true", help=f"Set the '{flag}' startup flag")
    # No positional arguments!

    args = parser.parse_args()

    # Collect all flags set via --flag
    selected_flags = [flag for flag in ALLOWED_FLAGS if getattr(args, flag, False)]

    if selected_flags:
        try:
            write_startup_args(selected_flags)
        except Exception as e:
            print(f"Error: {e}")
    else:
        # Read mode
        flags = read_startup_args()
        if flags:
            print("Startup flags set:")
            for flag in flags:
                print(f"  {flag} - {get_flag_description(flag)}")
        else:
            print("No valid startup flags set.")