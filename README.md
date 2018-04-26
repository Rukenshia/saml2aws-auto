# saml2aws-auto

This is a CLI that uses [saml2aws](https://github.com/Versent/saml2aws) to manage multiple AWS account credentials
at the same time. Accounts are organised in groups, which can be refreshed using one command.

## Installation

The [GitHub Releases](https://github.com/Rukenshia/saml2aws-auto/releases) page includes archives for all major platforms.
Download the release for your platform and make sure `saml2aws-auto` is in your PATH variable.

**This tool relies on `saml2aws` (it really is just dumb and executes the binary for you.) to be in your PATH. Download and install it before trying to deal with `saml2aws-auto`.**

## Features

* Group management (add, list, delete)
* Refreshing multiple accounts at once
* Refreshing is skipped when the credentials are still valid

## Usage

```plain
saml2aws-auto 0.1.4
Jan Christophersen <jan@ruken.pw>
A wrapper around saml2aws allowing you to refresh multiple AWS credentials at the same time

USAGE:
    saml2aws-auto [FLAGS] [OPTIONS] <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information
    -v               Sets the level of verbosity

OPTIONS:
    -c, --config <FILE>    Sets a custom config file

SUBCOMMANDS:
    groups     Manage role groups
    help       Prints this message or the help of the given subcommand(s)
    refresh    Refreshes all credentials for a group
```

### Group Management

```plain
saml2aws-auto-groups
Manage role groups

USAGE:
    saml2aws-auto groups <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    add       Adds a group with one or more roles
    delete    Deletes a group
    help      Prints this message or the help of the given subcommand(s)
    list      Lists all configured groups
```