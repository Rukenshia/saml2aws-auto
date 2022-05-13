# saml2aws-auto

This is a CLI used to manage multiple AWS account credentials when authenticating via SAML
at the same time. Accounts are organised in groups, which can be refreshed using one command.

## Installation

```bash
brew install rukenshia/repo/saml2aws-auto
```

The [GitHub Releases](https://github.com/Rukenshia/saml2aws-auto/releases) page includes archives for all major platforms.
Download the release for your platform and make sure `saml2aws-auto` is in your PATH variable.

If you have rust installed, you can use the following command

```bash
cargo install saml2aws-auto
```

### Linux

If you are on Linux, you will need to set up a secret tool before running saml2aws-auto. You can find more information in the troubleshooting section.

## Features

- Retrieving AWS Credentials when authenticating via SAML (only Keycloak supported at the moment, MFA is mandatory)
- Management of multiple accounts organised in groups
- Token expiration time is taken into account (they will not be refreshed if they are still valid)

## Getting Started

After you've downloaded and installed `saml2aws-auto`, you can add a new group using this command:

```bash
$ saml2aws-auto groups add my-accounts --prefix my-accounts --role Administrator

Welcome to saml2aws-auto. It looks like you do not have a configuration file yet.
Currently, only Keycloak is supported as Identity Provider. When setting the
IDP URL, please note that you will have to pass the exact path to the saml client of Keycloak.
```

Let's break the command down into a few pieces:

- `saml2aws-auto groups add` tells the CLI to add a new group.
- `my-accounts` tells the CLI what name you want to use for the group. This can be anything.
- `--prefix my-accounts` tells it that all the accounts you want to target start with `my-accounts`.
  In our example, we have two accounts: `my-accounts-staging` and `my-accounts-prod`. That means that the prefix will capture both of these accounts. If you also have `my-other-accounts-staging` and `my-other-accounts-prod` but want all four accounts in the same group, you can use the prefix `my-`.
- `--role Administrator` identifies which role to use for all accounts.

If you want to add new accounts to an existing group later, you can use the `--append` flag. Also if you want to target specific accounts, you can pass in `--accounts [account names,]`. Use `saml2aws-auto groups add --help` for more info.

Next, you will be asked a few questions:

```
? IDP URL [localhost]: https://my.idp/realms/myrealm/protocol/saml/clients/aws
? IDP Username: my.username@company.com
? IDP Password []: my.password

All set!

? MFA Token [000000]: 123456
```

Your password will be stored with the native credentials manager of your platform.

After you've entered your MFA Token, the group will be configured for you:

```
Listing allowed roles for your account          SUCCESS

my-accounts:
        my-accounts-staging: arn:aws:iam::1234567890:role/Administrator
        my-accounts-prod: arn:aws:iam::1234567891:role/Administrator

Group configuration updated
```

The only thing left to do now is refresh your credentials:

```bash
$ saml2aws-auto refresh my-accounts

? MFA Token [000000]: 123456
Refreshing my-accounts-staging  SUCCESS
Refreshing my-accounts-prod     SUCCESS

Refreshed group my-accounts. To use them in the AWS cli, apply the --profile flag with the name of the account.

Example:

        aws --profile my-accounts-staging s3 ls
```

## Changing Password / Username / Other Configuration

You can use `saml2aws-auto configure` to reconfigure your details.
If you have several IDPs that you need to connect to, you can use the `--config` option to provide
a path to a separate config file for saml2aws-auto.

## Usage

You can interactively explore the tool by typing `saml2aws-auto help`. This also works for any of the sub commands.

## Troubleshooting

## I am behind a proxy

If you are using a proxy, you need to set up the common environment variables for proxy usage.

- `http_proxy` - routes all HTTP traffic through the given proxy (e.g. `http://user:password@localhost:1234`)
- `https_proxy` - routes all HTTPS traffic through the given proxy (e.g. `http://user:password@localhost:1234`)

**for `saml2aws-auto`, all requests are usually made to HTTPS endpoints, therefore configuring the `https_proxy` is advised.**

## My password can't be stored

Some users have reported issues with the credentials management. If your password can't be stored properly, you can use the `--skip-password-manager` flag combined with the `--password` flag with the `groups add`
and `refresh` commands to circumvent this.

Example:

```sh
saml2aws-auto --skip-password-manager groups add example --role Administrator --prefix example --password "my password"
```

## `The name org.freedesktop.secrets was not provided by any .service files (org.freedesktop.DBus.Error.ServiceUnknown)))`

This is an error specific to linux and tells you that you currently don't have any secret manager implementing the Freedesktop Secret Service set up. Usually, a keyring app such as GNOME-Keyring or another tool is pre-installed. Open that up and configure both your master password and the default vault for your secrets and try rerunning saml2aws-auto. [Another link to what apps provide this API](https://specifications.freedesktop.org/secret-service/)
