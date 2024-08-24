use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    /// Sets the level of verbosity
    #[arg(short, long)]
    pub verbose: bool,

    /// Sets a custom config file
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<String>,

    /// Skip using the password manager (for unsupported platforms)
    #[arg(long)]
    pub skip_password_manager: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Configure saml2aws-auto
    Configure,

    /// Manage groups
    Groups {
        #[command(subcommand)]
        command: GroupCommands,
    },

    /// Refresh credentials for a group
    Refresh(RefreshArgs),

    /// Print version info and exit
    Version,
}

#[derive(Subcommand)]
pub enum GroupCommands {
    /// Add a new group
    Add(AddGroupArgs),

    /// Delete a group
    Delete {
        /// Name of the group to delete
        group: String,
    },

    /// List all groups
    List,
}

#[derive(Args)]
pub struct AddGroupArgs {
    /// Name of the group
    pub name: String,

    /// AWS Role name to assume
    #[arg(short, long)]
    pub role: String,

    /// Prefix of AWS account names to add to the group
    #[arg(short, long)]
    pub prefix: Option<String>,

    /// Specific AWS accounts to add to the group
    #[arg(short, long, num_args = 1..)]
    pub accounts: Option<Vec<String>>,

    /// Append accounts to an existing group
    #[arg(long)]
    pub append: bool,

    /// Session duration in seconds
    #[arg(short = 'd', long)]
    pub session_duration: Option<i64>,

    /// STS endpoint to use
    #[arg(long)]
    pub sts_endpoint: Option<String>,

    /// IDP Username
    #[arg(short, long)]
    pub username: Option<String>,

    /// IDP Password
    #[arg(short = 'P', long)]
    pub password: Option<String>,

    /// MFA Token
    #[arg(short, long)]
    pub mfa: Option<String>,
}

#[derive(Args)]
pub struct RefreshArgs {
    /// Groups to refresh
    pub groups: Vec<String>,

    /// Force refresh of credentials
    #[arg(short, long)]
    pub force: bool,

    /// IDP Username
    #[arg(short, long)]
    pub username: Option<String>,

    /// IDP Password
    #[arg(short = 'P', long)]
    pub password: Option<String>,

    /// MFA Token
    #[arg(short, long)]
    pub mfa: Option<String>,
}
