mod fxa;

use std::io;

use anyhow::Error;
use fxa::LoginManager;
use url::Url;

fn main() -> Result<(), Error> {
    let mut lm = LoginManager::init()?;
    let (url, _) = lm.login();
    println!("go to: {url}");
    let stdin = io::stdin();
    let mut line = String::new();
    stdin.read_line(&mut line)?;
    let cb_url = Url::parse(&line)?;
    let mut query = cb_url.query_pairs();
    let code = query.find(|(k, _)| k == "code");
    let code = code.unwrap().1;
    let (user, token) = lm.callback(code.to_string())?;
    println!("{}", serde_json::to_string_pretty(&user)?);
    println!("{token}");
    Ok(())
}
