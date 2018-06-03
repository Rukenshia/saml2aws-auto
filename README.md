# saml2aws-auto

This is a CLI used to manage multiple AWS account credentials when authenticating via SAML
at the same time. Accounts are organised in groups, which can be refreshed using one command.

## Installation

The [GitHub Releases](https://github.com/Rukenshia/saml2aws-auto/releases) page includes archives for all major platforms.
Download the release for your platform and make sure `saml2aws-auto` is in your PATH variable.

## Features

* Retrieving AWS Credentials when authenticating via SAML (only Keycloak supported at the moment, MFA is mandatory)
* Management of multiple accounts organised in groups
* Token expiration time is taken into account (they will not be refreshed if they are still valid)

## Getting Started

After you've downloaded and installed `saml2aws-auto`, you can add a new group using this command:

```bash
$ saml2aws-auto groups add my-accounts --prefix my-accounts --role Administrator

Welcome to saml2aws-auto. It looks like you do not have a configuration file yet.
Currently, only Keycloak is supported as Identity Provider. When setting the
IDP URL, please note that you will have to pass the exact path to the saml client of Keycloak.
```

You will be asked a few questions:

```
? IDP URL [localhost]: https://my.idp/realms/myrealm/protocol/saml/clients/aws
? IDP Username: my.username@company.com
? IDP Password []: my.password

All set!

? MFA Token [000000]: 123456
```

Please note that your password will be saved in plaintext in a configuration file at `$HOME/.saml2aws-auto.yml`.

After you've entered your MFA Token, the group will be configured for you:

```
Listing allowed roles for your account          SUCCESS

my-accounts:
        my-accounts-staging: arn:aws:iam::1234567890:role/Administrator
        my-accounts-prod: arn:aws:iam::1234567891:role/Administrator

Group configuration updated
```

The only thing left to do now is refreshing your credentials:

```bash
$ saml2aws-auto refresh my-accounts

? MFA Token [000000]: 123456
Refreshing my-accounts-staging  SUCCESS
Refreshing my-accounts-prod     SUCCESS

Refreshed group my-accounts. To use them in the AWS cli, apply the --profile flag with the name of the account.

Example:

        aws --profile my-accounts-staging s3 ls
```

## Usage

You can interactively explore the tool by typing `saml2aws-auto help`. This also works for any of the sub commands.