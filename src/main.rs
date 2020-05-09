use structopt::StructOpt;
use dialoguer::Password;
use serde_json::to_writer_pretty;
use std::io::stdout;

use cse_query::*;

/// A command to query LDAP for user details
#[derive(StructOpt)]
struct Args {
    /// Authenticate with a different zID than the query
    #[structopt(short = "u", long = "user")]
    auth_zid: Option<String>,
    /// Password to use to authenticate (rather than prompting)
    #[structopt(short, long)]
    password: Option<String>,
    /// UNSW zID to query
    zid: String,
}

fn main() -> Result<()> {
    let args = Args::from_args();

    let auth_user = args.auth_zid.as_ref().unwrap_or(&args.zid);
    let password = args.password.map(Ok).unwrap_or_else(|| {
        let mut password = Password::new();
        password.with_prompt("Enter LDAP password");
        password.interact()
    })?;

    let user = User::query_other(auth_user, password, &args.zid)?;

    to_writer_pretty(stdout(), &user)?;

    println!();

    Ok(())
}
