"""
python -m chamberenv.chamberenv --help
"""

import logging
import os
import stat
import shutil
import sys
import re
import functools

import requests
from requests.exceptions import RequestException

logging.basicConfig()
logger = logging.getLogger("ChamberEnv")
logger.setLevel(logging.INFO)

CHAMBER_URL = "https://github.com/segmentio/chamber/releases/download/{version}/chamber-{version}{arch}"
ARCHS = {
    "darwin": "-darwin-amd64",
    "linux": "-linux-amd64",
    "windows": "-windows-amd64.exe",
    #     "deb": "_amd64.deb",
    #     "rpm": "_amd64.rpm",
}
SHA256_SUMS = ".sha256sums"

# # Example
# VERSION = "v2.8.0"
# ARCH = ARCHS["linux"]
# SHA256_SUM = "4a47bd9f7fb46ba4a3871efbb60931592defe7c954bd10b4e92323aa30874fc1"

GITHUB_API_URL = "https://api.github.com/repos/{repo}/{endpoint}"
ENDPOINT_RELEASES = "releases"
ENDPOINT_LATEST_RELEASE = "releases/latest"

HOME_DIR = os.path.expanduser("~")
CONFIG_FOLDER = "chamberenv"
CONFIG_PATH = os.path.join(os.path.join(HOME_DIR, ".config"), CONFIG_FOLDER)
if not os.path.exists(CONFIG_PATH):
    os.makedirs(CONFIG_PATH)
LOCAL_BIN_PATH = os.path.join(os.path.join(f"{HOME_DIR}", ".local"), "bin")


def exec_in_path(func):
    """Decorator to check PATH variable.
    """

    @functools.wraps(func)
    def wrapped(*args, **kwargs):
        result = func(*args, **kwargs)

        paths = os.getenv("PATH", None)
        if not paths or LOCAL_BIN_PATH not in paths:
            logger.warning(
                f"Please add '{CONFIG_PATH}' to you 'PATH' variable."
            )

        return result

    return wrapped


def cleanup(version, arch=ARCHS["linux"], tool="chamber", also_exec=False):
    """Delete downloaded files.

    Used when uninstalling a version.
    """
    file_path = os.path.join(CONFIG_PATH, f"{tool}-{version}{arch}")
    logger.debug(f"Deleting '{file_path}'.")
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"Removed chamber version '{version}'.")
    except (OSError) as e:
        logger.warning(f"Could not delete '{file_path}': {str(e)}.")

    if also_exec:
        file_path = os.path.join(LOCAL_BIN_PATH, tool)
        logger.debug(f"Deleting '{file_path}'.")
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"Removed chamber executable '{version}'.")
        except (OSError) as e:
            logger.warning(f"Could not delete '{file_path}': {str(e)}.")


def valid_hash(version, arch=ARCHS["linux"], file_path=""):
    """Get and check the hash for the downloaded file.
    """

    if not version:
        logger.error("Missing version.")
        return False

    if not file_path:
        logger.error("Missing file path.")
        return False

    import hashlib

    url = CHAMBER_URL.format(version=version, arch=SHA256_SUMS)
    logger.debug(f"Getting {url}.")

    response = None
    try:
        response = requests.get(url=url, timeout=5)
    except (RequestException) as e:
        logger.error(f"Cannot get the sha256sum file from {url}: {str(e)}")

    if response is None:
        logger.error("Could not retrieve the sha256sum.")
        return False

    sha_sum_expected = ""
    logger.debug(f"Searching hash for: {version}{arch}")
    p = re.compile(f".*{version}{arch}.*")
    for hash_ in response.text.split("\n"):
        logger.debug(f"Checking: '{hash_}'")
        match = p.search(hash_)
        if match:
            try:
                logger.debug(match)
                logger.debug(match[0])
                sha_sum_expected = match[0].split()[0]
                logger.debug(f"Found sha256 match: {sha_sum_expected}")
                break
            except (KeyError) as e:
                logger.waring(
                    f"Wrong format in sha256sum file: '{match}': {str(e)}"
                )
    else:
        logger.error(
            f"Could not find donwloaded version '{version}{arch}' in sha256sum file."
        )
        return False

    data = None
    try:
        with open(file_path, "rb") as data_file:
            data = data_file.read()
    except (FileNotFoundError) as e:
        logger.error(f"Could not load the downloaded file: {str(e)}")
        return False

    if not data:
        logger.error("Could not load the downloaded file.")
        return False

    sha_sum_file = hashlib.sha256(data).hexdigest()

    return sha_sum_file == sha_sum_expected


@exec_in_path
def get_version(version=None, arch=ARCHS["linux"], tool="chamber"):
    """Download new chamber version.

    Including sha256sum file.
    """

    if not version:
        logger.error("Missing version.")
        return False

    file_path = os.path.join(CONFIG_PATH, f"{tool}-{version}{arch}")

    if not os.path.exists(file_path):
        url = CHAMBER_URL.format(version=version, arch=arch)
        logger.debug(f"Getting {url}.")

        response = None
        try:
            response = requests.get(url=url, timeout=5)
        except (RequestException) as e:
            logger.error(
                f"Could not get {tool} version {version}{arch} from {url}: {str(e)}"
            )

        if response is None:
            logger.error(
                f"Could not get {tool} version {version}{arch} from {url}."
            )
            return False

        logger.debug(f"Store downloaded file in: {file_path}.")
        with open(file_path, "wb") as data_file:
            data_file.write(response.content)

        print(f"Downloaded {tool} version '{version}'.")

    else:
        logger.info(f"Using previously downloaded file: '{file_path}'.")

    if valid_hash(version=version, arch=arch, file_path=file_path):
        logger.info("CHECKSUM OK.")
        return True
    else:
        logger.error("CHECKSUM NOT OK.")
        return False


@exec_in_path
def activate_version(version=None, arch=ARCHS["linux"], tool="chamber"):
    if not version:
        logger.error("Missing version.")
        return False

    file_path_source = os.path.join(CONFIG_PATH, f"{tool}-{version}{arch}")
    if not os.path.exists(file_path_source):
        logger.error(f"Cannot find the file; {file_path_source}.")
        return False

    # Make exectuable.
    logger.debug(f"Make '{file_path_source}' executable.")
    os.chmod(
        file_path_source,
        stat.S_IRWXU
        | stat.S_IRGRP
        | stat.S_IWGRP
        | stat.S_IROTH
        | stat.S_IWOTH,
    )

    file_path_target = os.path.join(LOCAL_BIN_PATH, tool)
    logger.debug(f"Copy '{file_path_source}' to '{file_path_target}'.")
    # Copy file.
    shutil.copy2(file_path_source, file_path_target)
    # # Move file.
    # os.replace(file_path_source, file_path_target)

    file_path_active = os.path.join(CONFIG_PATH, "version")
    with open(file_path_active, "w") as active_file:
        active_file.write(version)

    print(f"Using {tool} version '{version}' now.")

    return True


def get_active_version():
    file_path_active = os.path.join(CONFIG_PATH, "version")
    if not os.path.exists(file_path_active):
        logger.error("Chamber is not managed by chamberenv.")
        return ""
    version = ""
    with open(file_path_active, "r") as active_file:
        version = active_file.read()
    if not version:
        logger.error(
            "The version '{version}' of chamber is not managed by chamberenv."
        )
        return ""
    return version


def gather_versions(tool="chamber"):
    p = re.compile(f"{tool}-(.*)-.*-.*")
    versions = []
    for f in os.listdir(CONFIG_PATH):
        if os.path.isfile(os.path.join(CONFIG_PATH, f)) and f.startswith(tool):
            match = p.search(f)
            if match:
                version = match.groups()[0]
                versions.append(version)

    return versions


def gather_remote_versions(
    repo="segmentio/chamber", endpoint=ENDPOINT_RELEASES
):
    versions = []
    response = None
    url = GITHUB_API_URL.format(repo=repo, endpoint=endpoint)
    try:
        response = requests.get(url=url, timeout=5)
        releases = response.json()
        for release in releases:
            versions.append(release["tag_name"])
    except (RequestException) as e:
        logger.error(f"Cannot get the sha256sum file from {url}: {str(e)}")

    if response is None:
        logger.error(f"Could not retrieve remote versions for '{repo}'.")

    return versions


def print_versions(versions, active_version=-1, sort=True):
    if sort:
        # String comparison is sufficient.
        versions.sort(reverse=True)
        # Sort versions, only considering digits.
        # key=lambda x: int(re.sub("\D", "", x[:x.find("-") if x.find("-") > 0 else len(x)])), reverse=True  # noqa: W605

    logger.debug(versions)

    if not versions:
        print(f"No chamber versions found.")
        return False

    for version in versions:
        if active_version == version:
            print(
                f"* {version} (set by {os.path.join(CONFIG_PATH, 'version')})"
            )
        else:
            if active_version == -1:
                print(f"{version}")
            else:
                print(f"  {version}")

    return True


def show_versions(active_version=-1, tool="chamber"):
    versions = gather_versions(tool=tool)
    return print_versions(versions=versions, active_version=active_version)


def show_remote_versions(
    active_version=-1, repo="segmentio/chamber", endpoint=ENDPOINT_RELEASES
):
    versions = gather_remote_versions(repo=repo, endpoint=endpoint)
    return print_versions(versions=versions, active_version=active_version)


def main():
    from ._version import __version__
    import argparse

    parser = argparse.ArgumentParser(
        description="Manage chamber environments.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        allow_abbrev=False,
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s {version}".format(version=__version__),
    )

    # subparsers
    subparsers = parser.add_subparsers(help="Sub commands.", dest="subcommand")
    subparsers.required = True

    # Install a specfic version of chamber.
    install = subparsers.add_parser(
        "install",
        # parents=[config],
        help="Install a specific version of chamber.",
        description="Install a specific version of chamber.",
        # formatter_class=argparse.RawTextHelpFormatter,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        # epilog=__complete__,
        allow_abbrev=False,
    )
    install_required = install.add_argument_group("required arguments")
    install_optional = install.add_argument_group("optional arguments")
    install_required.add_argument(
        "--chamber-version", required=True, type=str, help="Chamber version.",
    )
    install_optional.add_argument(
        "--arch",
        type=str,
        # default=ARCHS["linux"],
        choices=ARCHS.keys(),
        help="System architecture.",
    )

    # Uninstall a specfic version of chamber.
    uninstall = subparsers.add_parser(
        "uninstall",
        # parents=[config],
        help="Uninstall a specific version of chamber.",
        description="Uninstall a specific version of chamber.",
        # formatter_class=argparse.RawTextHelpFormatter,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        # epilog=__complete__,
        allow_abbrev=False,
    )
    uninstall_required = uninstall.add_argument_group("required arguments")
    uninstall_optional = uninstall.add_argument_group("optional arguments")
    uninstall_required.add_argument(
        "--chamber-version", required=True, type=str, help="Chamber version.",
    )
    uninstall_optional.add_argument(
        "--arch",
        type=str,
        # default=ARCHS["linux"],
        choices=ARCHS.keys(),
        help="System architecture.",
    )

    # List versions of chamber.
    list_versions = subparsers.add_parser(
        "list",
        # parents=[config],
        help="List installed versions of chamber.",
        description="List installed versions of chamber.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        allow_abbrev=False,
    )

    # List remote versions of chamber.
    list_remote_versions = subparsers.add_parser(
        "list-remote",
        # parents=[config],
        help="List installable versionss of chamber.",
        description="List installable versions of chamber.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        allow_abbrev=False,
    )

    # Use a specific version of chamber.
    use_version = subparsers.add_parser(
        "use",
        # parents=[config],
        help="Use a specific version of chamber.",
        description="Use a specific version of chamber.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        allow_abbrev=False,
    )
    use_version_required = use_version.add_argument_group("required arguments")
    use_version_optional = use_version.add_argument_group("optional arguments")
    use_version_required.add_argument(
        "--chamber-version", required=True, type=str, help="Chamber version.",
    )
    use_version_optional.add_argument(
        "--arch",
        type=str,
        # default=ARCHS["linux"],
        choices=ARCHS.keys(),
        help="System architecture.",
    )

    parser.add_argument(
        "--debug", action="store_true", help="Show debug info."
    )

    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
        stream_handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(f"%(lineno)s: {logging.BASIC_FORMAT}")
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)
        logger.propagate = False
    else:
        logger.setLevel(logging.INFO)

    install_chamber = False
    uninstall_chamber = False
    list_versions = False
    list_remote_versions = False
    use_version = False

    if args.subcommand in ("install", "uninstall", "use"):
        if args.subcommand == "install":
            install_chamber = True
        elif args.subcommand == "uninstall":
            uninstall_chamber = True
        elif args.subcommand == "use":
            use_version = True
        chamber_version = args.chamber_version
        logger.info(f"Chamber version: {chamber_version}")
        arch = args.arch
        if not arch:
            import platform

            arch = platform.system().lower()
            if not arch:
                logger.error(
                    "Could not determine architecture. Try '--arch linux' or --help."
                )
                return 1
        arch = ARCHS[arch]
        logger.debug(f"System architecture: {arch}")
    elif args.subcommand == "list":
        list_versions = True
    elif args.subcommand == "list-remote":
        list_remote_versions = True

    error = False
    if install_chamber:
        downloaded = True
        activated = True
        downloaded = get_version(version=chamber_version, arch=arch)
        if downloaded:
            activated = activate_version(version=chamber_version, arch=arch)
            if not activated:
                logger.error(
                    f"Error while activating chamber: {chamber_version}{arch}."
                )
        else:
            logger.error(
                f"Error while getting the chamber files: {chamber_version}{arch}."
            )

        error = not downloaded or not activated
    elif uninstall_chamber:
        allow_uninstall = True
        active_version = True

        active_version = get_active_version()
        if active_version:
            # If the last version is uninstalled
            # also remove the executable.
            last_version = len(gather_versions(tool="chamber")) == 1
            allow_uninstall = last_version or chamber_version != active_version
            if allow_uninstall:
                cleanup(
                    version=chamber_version, arch=arch, also_exec=last_version
                )
            else:
                logger.error(
                    "Not uninstalling the active chamber version. Switch first using 'use'."
                )
        else:
            logger.error(f"Error while getting active chamber version.")

        error = not active_version or not allow_uninstall
    elif list_versions:
        show = True

        active_version = get_active_version()
        if not active_version:
            logger.warning(f"Error while getting active chamber version.")
            active_version = -1
        show = show_versions(active_version=active_version)

        error = not show
    elif list_remote_versions:
        show = True

        active_version = get_active_version()
        if not active_version:
            logger.warning(f"Error while getting active chamber version.")
            active_version = -1
        show = show_remote_versions(active_version=active_version)

        error = not show
    elif use_version:
        activated = True
        active_version = True

        active_version = get_active_version()
        if active_version != chamber_version:
            activated = activate_version(version=chamber_version, arch=arch)
            if not activated:
                logger.error(
                    f"Error while activating chamber: {chamber_version}{arch}."
                )
        else:
            logger.warning(f"Already using this version: '{active_version}'.")

        error = not active_version or not activated

    return 1 if error else 0


if __name__ == "__main__":
    sys.exit(main())
