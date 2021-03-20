use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
    process,
};

use dialoguer::{Confirm, Input, Password, Select};
use dirs;
use itertools::Itertools;
use sha3::{digest::*, Shake256};
use structopt::StructOpt;
use toml;

use keybox_core::KeyGenerator;

#[derive(Debug, Clone, StructOpt)]
#[structopt(name = "keybox")]
struct Opt {
    #[structopt(subcommand)]
    command: Option<Command>,

    /// name of a key
    keyname: Option<String>,
}

#[derive(Debug, Clone, StructOpt)]
enum Command {
    /// list keys
    List,

    /// update key length
    Update { keyname: Option<String> },

    /// remove a key
    Remove { keyname: Option<String> },

    /// display data to backup
    Backup,

    /// remove password
    Reset,
}

fn read_password(data: toml::value::Table) -> String {
    let password_digest_stored = data
        .get("password_digest")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string()
        .clone();
    loop {
        let password = Password::new().with_prompt("password").interact().unwrap();
        let password_digest = gen_digest(password.clone());

        if password_digest == password_digest_stored {
            return password;
        } else {
            println!("Password mismatched");
        }
    }
}

fn read_new_password() -> (String, String) {
    let password = Password::new()
        .with_prompt("password")
        .with_confirmation("confirm password", "Password mismached.")
        .interact()
        .unwrap();

    let password_digest = gen_digest(password.clone());
    (password, password_digest)
}

fn read_keylen() -> usize {
    Input::<usize>::new()
        .with_prompt("key length")
        .interact()
        .unwrap()
}

fn read_extrachars() -> String {
    Input::<String>::new()
        .with_prompt("extra characters")
        .allow_empty(true)
        .validate_with(|input: &str| -> Result<(), &str> {
            if input.chars().counts().values().max().unwrap_or(&1) == &1 {
                Ok(())
            } else {
                Err("Do not put the same character twice.")
            }
        })
        .interact()
        .unwrap()
        .chars()
        .collect()
}

fn store_data(path: PathBuf, data: toml::value::Table) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(toml::Value::Table(data.clone()).to_string().as_bytes())
        .unwrap();
}

fn gen_digest(source: String) -> String {
    let password_with_nonce = source.clone() + "this is nonce";
    let mut hasher = Shake256::default();
    hasher.update(password_with_nonce);
    hasher
        .finalize_boxed(64)
        .to_vec()
        .into_iter()
        .map(|v| v as char)
        .collect::<String>()
}

fn select_keyname(keyinfos: &toml::map::Map<String, toml::Value>) -> String {
    let index = Select::new()
        .with_prompt("choose key")
        .items(&list_keyinfos(keyinfos.clone()))
        .default(0)
        .interact()
        .unwrap();
    keyinfos.keys().nth(index).unwrap().to_string()
}

fn read_keyname() -> String {
    Input::<String>::new()
        .with_prompt("keyname")
        .interact()
        .unwrap()
}

fn read_all(opt: Opt) -> (String, String, String, usize, String) {
    let (password, password_digest) = read_new_password();
    let keylen = read_keylen();
    let extrachars = read_extrachars();
    let keyname = opt.keyname.unwrap_or(read_keyname());
    (password, password_digest, keyname, keylen, extrachars)
}

fn build_keyinfo(keylen: usize, extrachars: String) -> toml::value::Table {
    let mut keyinfo = toml::value::Table::new();
    keyinfo.insert(String::from("keylen"), toml::Value::Integer(keylen as i64));
    keyinfo.insert(String::from("extrachars"), toml::Value::String(extrachars));
    keyinfo
}

fn build_data(
    password_digest: String,
    keyname: String,
    keylen: usize,
    extrachars: String,
) -> toml::value::Table {
    let mut keyinfos = toml::map::Map::new();
    keyinfos.insert(
        keyname.clone(),
        toml::Value::Table(build_keyinfo(keylen, extrachars.clone())),
    );
    let mut data = toml::map::Map::new();
    data.insert(
        String::from("password_digest"),
        toml::Value::String(password_digest),
    );
    data.insert(String::from("keyinfos"), toml::Value::Table(keyinfos));
    data
}

fn list_keyinfos(keyinfos: toml::value::Table) -> Vec<String> {
    keyinfos
        .iter()
        .map(|(keyname, keyinfo)| {
            format!(
                "{}: keylen = {}, extrachars = {}",
                keyname.clone(),
                &keyinfo
                    .get("keylen")
                    .unwrap()
                    .as_integer()
                    .unwrap()
                    .to_string(),
                keyinfo.get("extrachars").unwrap().as_str().unwrap()
            )
        })
        .collect::<Vec<String>>()
}

fn main() -> std::io::Result<()> {
    let opt = Opt::from_args();
    let mut data_dir = dirs::data_dir();
    let keyname;
    let keylen;
    let password;
    let extrachars;

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
                        let (_password, password_digest) = read_new_password();
                        let password_digest_stored = data.get_mut("password_digest").unwrap();
                        *password_digest_stored = toml::Value::String(password_digest);
                        store_data(data_path, data.clone());
                        println!("Password is reset successfuly");
                    }
                    process::exit(0);
                }
                Some(Command::Update {
                    keyname: keyname_local,
                }) => {
                    let keyinfos = data.get_mut("keyinfos").unwrap().as_table_mut().unwrap();
                    keyname = match keyname_local {
                        Some(keyname) => keyname,
                        None => select_keyname(keyinfos),
                    };
                    let keyinfo = keyinfos
                        .get_mut(&keyname)
                        .expect(&format!("{} does not exists", &keyname));
                    *keyinfo = toml::Value::Table(build_keyinfo(read_keylen(), read_extrachars()));
                    store_data(data_path, data.clone());
                    println!("{} is updated successfuly", &keyname);
                    process::exit(0);
                }
                Some(Command::Remove {
                    keyname: keyname_local,
                }) => {
                    let keyinfos = data.get_mut("keyinfos").unwrap().as_table_mut().unwrap();
                    keyname = match keyname_local {
                        Some(keyname) => keyname,
                        None => select_keyname(keyinfos),
                    };
                    let execute_removal = Confirm::new()
                        .with_prompt(format!("Do you really want to remove {}?", &keyname))
                        .interact()
                        .unwrap();

                    if execute_removal {
                        keyinfos.remove(&keyname).unwrap();
                        store_data(data_path, data.clone());
                        println!("{} is removed successfuly", &keyname);
                    }
                    process::exit(0);
                }
                Some(Command::Backup) => {
                    println!("{}", &data_str);
                    process::exit(0);
                }
                Some(Command::List) => {
                    let keyinfos = data.get("keyinfos").unwrap().as_table().unwrap();
                    for keyinfo in list_keyinfos(keyinfos.clone()) {
                        println!("{}", keyinfo);
                    }
                    process::exit(0);
                }
                None => {
                    password = read_password(data.clone());

                    let keyinfos = data.get_mut("keyinfos").unwrap().as_table_mut().unwrap();
                    keyname = match opt.keyname.clone() {
                        Some(keyname) => keyname,
                        None => select_keyname(keyinfos),
                    };
                    let keyinfo = keyinfos.get(&keyname).cloned();
                    if keyinfo.is_none() {
                        keylen = read_keylen();
                        extrachars = read_extrachars();
                    } else {
                        let keyinfo = keyinfo.clone().unwrap();
                        let keyinfo = keyinfo.as_table().unwrap();
                        keylen = keyinfo.get("keylen").unwrap().as_integer().unwrap() as usize;
                        extrachars = keyinfo
                            .get("extrachars")
                            .unwrap()
                            .as_str()
                            .unwrap()
                            .chars()
                            .collect();
                    }

                    if keyinfo.is_none() {
                        if Confirm::new()
                            .with_prompt("Do you want add this key?")
                            .interact()
                            .unwrap()
                        {
                            let keyinfo = build_keyinfo(keylen, extrachars.clone());
                            keyinfos.insert(keyname.clone(), toml::Value::Table(keyinfo));
                            store_data(data_path, data.clone());
                            println!("{} is added successfuly", keyname);
                        }
                    }
                }
            }
        } else {
            //
            println!("{} not found. Creating...", data_path.display());
            fs::File::create(&data_path)?;
            let (password_local, password_digest, keyname_local, keylen_local, extrachars_local) =
                read_all(opt);
            password = password_local;
            keyname = keyname_local;
            keylen = keylen_local;
            extrachars = extrachars_local;

            let mut keyinfos = toml::map::Map::new();
            keyinfos.insert(
                keyname.clone(),
                toml::Value::Table(build_keyinfo(keylen, extrachars.clone())),
            );
            let mut data = toml::map::Map::new();
            data.insert(
                String::from("password_digest"),
                toml::Value::String(password_digest.clone()),
            );
            data.insert(String::from("keyinfos"), toml::Value::Table(keyinfos));
            let data = build_data(password_digest, keyname.clone(), keylen, extrachars.clone());
            store_data(data_path, data.clone());
        }
    } else {
        println!(
            "Couldn't find a directry to store data. Keybox will not store the keyname and length."
        );
        let (password_local, _password_digest, keyname_local, keylen_local, extrachars_local) =
            read_all(opt);
        password = password_local;
        keyname = keyname_local;
        keylen = keylen_local;
        extrachars = extrachars_local;
    }

    let mut key_gen = KeyGenerator::new(password);
    let key = key_gen.gen(keyname, keylen, extrachars.chars().collect());
    println!("key: {}", key);
    Ok(())
}
