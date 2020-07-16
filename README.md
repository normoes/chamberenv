# Manage chamber environments

This project is inspired by [`tfenv`](https://github.com/tfutils/tfenv).

It's supposed to be a helper tool, that easily installs, removes, list and switches different versions of chamber.

It downloads the different versions of `chamber` from the github release page: https://github.com/segmentio/chamber/releases.

It creates the configuration folder: `~/.config/chamberenv`.

It manages the executable files in: `~/.local/bin`, so make sure this is in your `PATH` variable.

**_Note_**:
* This is work in progress.
* I only tested it with `linux`, downloading and running `chamber` versions like `chamber-v2.8.2-linux-amd64`.

## How to
* Get help
  - `chamberenv --help`
* Get the tool version
  - `chamberenv --version`
* General usage
  - List managed versions of chamber:
      ```
          chamberenv list
          # Result:
          * v2.8.2 (set by /home/norman/.config/chamberenv/version)
            v2.8.0
      ```
  - Install a specific version of chamber.
      ```
          chamberenv install --chamber-version v2.7.5
          # Result:
          INFO:ChamberEnv:Chamber version: v2.7.5
          INFO:ChamberEnv:CHECKSUM OK.
          Downloaded chamber version 'v2.7.5'.
          Using chamber version 'v2.7.5' now.

          chamber version
          # Result:
          chamber v2.7.5
      ```
      + The version of chamber will be downloaded if necessary.
      + The given version will be activated as well.
   - Use a specific version of chamber:
      ```
          chamberenv use --chamber-version v2.8.2
          # Result:
          INFO:ChamberEnv:Chamber version: v2.8.2
          Using chamber version 'v2.8.2' now.

          chamber version
          # Result:
          chamber v2.8.2
      ```
      + Nothing is downloaded.
      + The given version will be activated.
  - Uninstall a specific version of chamber.
      ```
          chamberenv uninstall --chamber-version v2.7.5
          # Result:
          INFO:ChamberEnv:Chamber version: v2.7.5
          Removed chamber version 'v2.7.5'.
      ```
      + The downloaded files for this version of chamber will be removed.
      + You cannot uninstall the active version of chamber.
          ```
              chamber version
              # Result:
              chamber v2.8.2

              chamberenv uninstall --chamber-version v2.7.5
              # Result:
              INFO:ChamberEnv:Chamber version: v2.8.2
              ERROR:ChamberEnv:Not uninstalling the active chamber version. Switch first using 'use'.
          ```
* The option `--debug` shows debug information.

See:
* `chamberenv --help`.
* `chamberenv install --help`
* ...

## requirements.txt vs. setup.py

According to these sources:
* [python documentation](https://packaging.python.org/discussions/install-requires-vs-requirements/)
* [stackoverflow - second answer by jonathan Hanson](https://stackoverflow.com/questions/14399534/reference-requirements-txt-for-the-install-requires-kwarg-in-setuptools-setup-py)

I try to stick to:
* `requirements.txt` lists the necessary packages to make a deployment work.
* `setup.py` declares the loosest possible dependency versions.

### Creating `requirements.txt`

You won't ever need this probably - This is helpful when developing the `chamberenv`.

`pip-tools` is used to create `requirements.txt`.
* There is `requirements.in` where dependencies are set and pinned.
* To create the `requirements.txt`, run `update_requirements.sh` which basically just calls `pip-compile`.

**_Note_**:
* There also is `build_requirements.txt` which only contains `pip-tools`. I found, when working with virtual environments, it is necessary to install `pip-tools` inside the virtual environment as well. Otherwise `pip-sync` would install outside the virtual environment.

A development environment can be created like this:
```
    # Create a virtual environment 'venv'.
    python -m venv venv
    # Activate the virtual environment 'venv'.
    . /venv/bin/activate
    # Install 'pip-tools'.
    pip install --upgrade -r build_requirements.txt
    # Install dependencies.
    pip-sync requirements.txt
    ...
    # Deactivate the virtual environment 'venv'.
    deactivate
```

## Executable
If installed using `pip`, a system executable will be installed as well.
This way, you can just use the tool like every executable on your system.
```
chamberenv --help
```
