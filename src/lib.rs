use bs58;
use itertools::Itertools;
use sha3::{digest::*, Shake256};

// Bitcoin style
// 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz

pub struct KeyGenerator {
    password_digest: String,
    hasher: Shake256,
}

impl KeyGenerator {
    pub fn new(password: String) -> Self {
        let mut hasher = Shake256::default();
        hasher.update(password);
        let password_digest = hasher.finalize_boxed_reset(64);
        Self {
            password_digest: bs58::encode(password_digest.into_vec()).into_string(),
            hasher,
        }
    }

    pub fn gen(
        &mut self,
        nickname: String,
        key_length: usize,
        additional_characters: Vec<char>,
    ) -> String {
        let password_digest = &self.password_digest;
        let source = key_length.to_string() + password_digest + &nickname;
        self.hasher.update(source);
        let result = self.hasher.finalize_boxed_reset(64);
        let mut encoded = bs58::encode(result.into_vec()).into_string();
        encoded.truncate(key_length);
        let char_counts = encoded.chars().counts();
        for (from, to) in char_counts
            .into_iter()
            .sorted()
            .zip(additional_characters.into_iter())
        {
            encoded = encoded.replace(&String::from(from.0), &String::from(to));
        }
        encoded
    }
}

#[cfg(test)]
mod test {
    use crate::*;
    #[test]
    fn test_hasher() {
        let mut key_gen =
            KeyGenerator::new(String::from("My very very long rememberable password!!!!!"));
        let key_length = 16;
        let key = key_gen.gen(
            String::from("nickname of a service or something that I can remember"),
            key_length,
            vec!['!', '#'],
        );

        // source : `My very very long rememberable password!!!!!`
        // shake256 (512 bits) : `521322bc4f5f53a5b37265d7c0df3c043ddc47e885f260c2903645043e9b8d6d8efaed4bd13b2cb86569e99cb1068c0daea40ea0a77bed6d1caa984a1455a22f`
        // base58 : `2eB7XEwM9pFnRfSfy9NJXfzNn1HVmpUYVz61z8Cwd4paKw5cQVt35cihEMQ5heW5i1bn4cDy9hh6Yy1QZUwHCJog`

        // source is key_length + password_digest + nickname
        // source : `162eB7XEwM9pFnRfSfy9NJXfzNn1HVmpUYVz61z8Cwd4paKw5cQVt35cihEMQ5heW5i1bn4cDy9hh6Yy1QZUwHCJognickname of a service or something that I can remember`
        // shake256 (512 bits) : `b00050118d5b49f85808d09ce9c5953fa3905b4964539bfe5c2e4de045f37b5723a39fb9dfd7c0355abe22a321867e13dbc370c4f9ca1b0f38b7fc15812f5f4e`
        // base58 : `4X6Lbepf8fUz9Sa63aNHpGar35ptodWaAEPPxA7mFtHXzMxPcPNE6PdZ3rfmRuhb5w3h9aZbfag4dPcjiFHmRGay`

        // key is first {key_length} characters of base58
        // key : `4X6Lbepf8fUz9Sa6`
        // if additional characters are specified, characters in key is replaced from small(in ascii code) character.
        // numbers -> capital letters -> small letters
        // key : `!X#Lbepf8fUz9Sa#`

        assert_eq!(key, "!X#Lbepf8fUz9Sa#");
    }
}
