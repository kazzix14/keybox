use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::process;

use dialoguer::{Confirm, Input, Password, Select};
use dirs;
use sha3::{digest::*, Shake256};
use structopt::StructOpt;
use toml;

use keybox_core::KeyGenerator;

#[derive(Debug, StructOpt)]
#[structopt(name = "keybox")]
struct Opt {
    #[structopt(subcommand)]
    command: Option<Command>,

    /// name of a key
    #[structopt(short, long)]
    keyname: Option<String>,
}

#[derive(Debug, StructOpt)]
enum Command {
    /// list keys
    List,

    /// update key length
    Update { keyname: Option<String> },

    /// remove a key
    Remove { keyname: Option<String> },

    /// remove password
    Reset,
}

fn main() -> std::io::Result<()> {
    let opt = Opt::from_args();
    let mut data_dir = dirs::data_dir();
    let keyname;
    let key_length;
    let mut password;

    if let Some(data_dir) = &mut data_dir {
        let data_dir = data_dir.join("keybox");
        let data_path = data_dir.join("data.toml");
        if let Ok(mut data_file) = {
            fs::create_dir_all(data_dir)?;
            fs::OpenOptions::new()
                .read(true)
                .truncate(false)
                .open(&data_path)
        } {
            let mut data_str = String::new();
            data_file.read_to_string(&mut data_str)?;
            let mut data = data_str.parse::<toml::Value>()?;
            let data = data.as_table_mut().unwrap();
            match opt.command {
                Some(Command::Reset) => {
                    let execute_reset = Confirm::new().with_prompt(
                        "Do you really want to reset password? This means all keys will be changed.",
                    ).interact().unwrap();
                    if execute_reset {
                        password = Password::new()
                            .with_prompt("password")
                            .with_confirmation("confirm password", "Password mismached.")
                            .interact()?;
                        let password_digest = {
                            let password_with_nonce = password.clone() + "this is nonce";
                            let mut hasher = Shake256::default();
                            hasher.update(password_with_nonce);
                            hasher.finalize_boxed(64)
                        }
                        .to_vec()
                        .into_iter()
                        .map(|v| v as char)
                        .collect::<String>();
                        let password_digest_stored = data.get_mut("password_digest").unwrap();
                        *password_digest_stored = toml::Value::String(password_digest);
                        let mut data_file = fs::OpenOptions::new()
                            .write(true)
                            .truncate(true)
                            .open(&data_path)?;
                        data_file.seek(SeekFrom::Start(0))?;
                        data_file
                            .write_all(toml::Value::Table(data.clone()).to_string().as_bytes())?;
                        println!("Password is reset successfuly");
                    }
                    process::exit(0);
                }
                Some(Command::Update {
                    keyname: keyname_local,
                }) => {
                    let keyinfos = data.get_mut("keyinfos").unwrap().as_table_mut().unwrap();
                    let keys = keyinfos
                        .iter()
                        .map(|(keyname, key_length)| {
                            (
                                keyname.to_string(),
                                key_length.as_integer().unwrap() as usize,
                            )
                        })
                        .collect::<std::collections::HashMap<String, usize>>();
                    keyname = keyname_local.clone().unwrap_or_else(|| {
                        let index = Select::new()
                            .with_prompt("choose key")
                            .items(&keys.keys().collect::<Vec<&String>>())
                            .default(0)
                            .interact()
                            .unwrap();
                        keys.keys().nth(index).unwrap().to_string()
                    });
                    let keyinfo = keyinfos
                        .get_mut(&keyname)
                        .expect(&format!("{} does not exists", &keyname));
                    *keyinfo = toml::Value::Integer(
                        Input::<usize>::new()
                            .with_prompt("new key length")
                            .interact()
                            .unwrap() as i64,
                    );
                    let mut data_file = fs::OpenOptions::new()
                        .write(true)
                        .truncate(true)
                        .open(&data_path)?;
                    data_file.seek(SeekFrom::Start(0))?;
                    data_file.write_all(toml::Value::Table(data.clone()).to_string().as_bytes())?;
                    println!("{} is updated successfuly", &keyname);
                    process::exit(0);
                }
                Some(Command::Remove {
                    keyname: keyname_local,
                }) => {
                    let keyinfos = data.get_mut("keyinfos").unwrap().as_table_mut().unwrap();
                    let keys = keyinfos
                        .iter()
                        .map(|(keyname, key_length)| {
                            (
                                keyname.to_string(),
                                key_length.as_integer().unwrap() as usize,
                            )
                        })
                        .collect::<std::collections::HashMap<String, usize>>();
                    keyname = keyname_local.clone().unwrap_or_else(|| {
                        let index = Select::new()
                            .with_prompt("choose key")
                            .items(&keys.keys().collect::<Vec<&String>>())
                            .default(0)
                            .interact()
                            .unwrap();
                        keys.keys().nth(index).unwrap().to_string()
                    });
                    let execute_removal = Confirm::new()
                        .with_prompt(format!("Do you really want to remove {}?", &keyname))
                        .interact()
                        .unwrap();

                    if execute_removal {
                        keyinfos.remove(&keyname).unwrap();
                        let mut data_file = fs::OpenOptions::new()
                            .write(true)
                            .truncate(true)
                            .open(&data_path)?;
                        data_file.seek(SeekFrom::Start(0))?;
                        data_file
                            .write_all(toml::Value::Table(data.clone()).to_string().as_bytes())?;
                        dbg!(toml::Value::Table(data.clone()).to_string());
                        println!("{} is removed successfuly", &keyname);
                    }
                    process::exit(0);
                }
                Some(Command::List) => {
                    let keyinfos = data.get_mut("keyinfos").unwrap().as_table_mut().unwrap();
                    let keys = keyinfos
                        .iter()
                        .map(|(keyname, key_length)| {
                            (
                                keyname.to_string(),
                                key_length.as_integer().unwrap() as usize,
                            )
                        })
                        .collect::<std::collections::HashMap<String, usize>>();
                    for key in keys.keys() {
                        println!("{}", key);
                    }
                    process::exit(0);
                }
                None => (),
            }
            let password_digest_stored = data
                .get("password_digest")
                .unwrap()
                .as_str()
                .unwrap()
                .to_string()
                .clone();

            loop {
                password = Password::new().with_prompt("password").interact()?;
                let password_digest = {
                    let password_with_nonce = password.clone() + "this is nonce";
                    let mut hasher = Shake256::default();
                    hasher.update(password_with_nonce);
                    hasher.finalize_boxed(64)
                }
                .to_vec()
                .into_iter()
                .map(|v| v as char)
                .collect::<String>();

                if password_digest == password_digest_stored {
                    break;
                } else {
                    println!("Password mismatched");
                }
            }

            let keyinfos = data.get_mut("keyinfos").unwrap().as_table_mut().unwrap();
            let keys = keyinfos
                .iter()
                .map(|(keyname, key_length)| {
                    (
                        keyname.to_string(),
                        key_length.as_integer().unwrap() as usize,
                    )
                })
                .collect::<std::collections::HashMap<String, usize>>();
            keyname = opt.keyname.clone().unwrap_or_else(|| {
                let index = Select::new()
                    .with_prompt("choose key")
                    .items(&keys.keys().collect::<Vec<&String>>())
                    .default(0)
                    .interact()
                    .unwrap();
                keys.keys().nth(index).unwrap().to_string()
            });
            let key_length_option = keys.get(&keyname).copied();
            if key_length_option.is_none() {
                key_length = Input::<usize>::new()
                    .with_prompt("key length")
                    .interact()
                    .unwrap();
                if Confirm::new()
                    .with_prompt("Do you want add this key?")
                    .interact()
                    .unwrap()
                {
                    keyinfos.insert(keyname.clone(), toml::Value::Integer(key_length as i64));
                    let mut data_file = fs::OpenOptions::new()
                        .write(true)
                        .truncate(true)
                        .open(&data_path)?;
                    data_file.seek(SeekFrom::Start(0)).unwrap();
                    data_file
                        .write_all(toml::Value::Table(data.clone()).to_string().as_bytes())
                        .unwrap();
                    println!("{} is added successfuly", keyname);
                }
            } else {
                key_length = key_length_option.unwrap();
            }
        } else {
            //
            println!("{} not found. Creating...", data_path.display());
            let mut data_file = fs::File::create(data_path)?;
            password = Password::new()
                .with_prompt("password")
                .with_confirmation("confirm password", "Password mismached.")
                .interact()?;
            let password_digest = {
                let password_with_nonce = password.clone() + "this is nonce";
                let mut hasher = Shake256::default();
                hasher.update(password_with_nonce);
                hasher.finalize_boxed(64)
            }
            .to_vec()
            .into_iter()
            .map(|v| v as char)
            .collect::<String>();
            key_length = Input::<usize>::new()
                .with_prompt("key length")
                .interact()
                .unwrap();

            let mut keyinfos = toml::map::Map::new();
            keyname = opt.keyname.unwrap_or(
                Input::<String>::new()
                    .with_prompt("keyname")
                    .interact()
                    .unwrap(),
            );
            keyinfos.insert(keyname.clone(), toml::Value::Integer(key_length as i64));
            let mut data = toml::map::Map::new();
            data.insert(
                String::from("password_digest"),
                toml::Value::String(password_digest),
            );
            data.insert(String::from("keyinfos"), toml::Value::Table(keyinfos));
            data_file.seek(SeekFrom::Start(0))?;
            data_file.write_all(toml::Value::Table(data.clone()).to_string().as_bytes())?;
        }
    } else {
        println!(
            "Couldn't find a directry to store data. Keybox will not store the keyname and length."
        );
        password = Password::new()
            .with_prompt("password")
            .with_confirmation("confirm password", "Password mismached.")
            .interact()?;
        key_length = Input::<usize>::new()
            .with_prompt("key length")
            .interact()
            .unwrap();
        keyname = opt.keyname.unwrap_or(
            Input::<String>::new()
                .with_prompt("keyname")
                .interact()
                .unwrap(),
        );
    }

    let mut key_gen = KeyGenerator::new(password);
    let key = key_gen.gen(keyname, key_length);
    println!("key: {}", key);
    Ok(())
}
