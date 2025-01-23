
// Implements From<$error> for $self
macro_rules! error_impl_from {
    ($self:ident; $( $ident:ident ),*) => {
        $(
            paste::paste! {
                impl From<[<$ident Error>]> for $self {
                    fn from(error: [<$ident Error>]) -> Self {
                        Self::$ident(error)
                    }
                }
            }
        )*
    };
}


#[cfg(test)]
#[macro_use]
mod test_util {
    macro_rules! random_private_key {
        () => {
            random_private_key!(1024)
        };
        ($bits:expr) => {{
            use rsa::RsaPrivateKey;
            RsaPrivateKey::new(&mut rand::thread_rng(), $bits).unwrap()
        }};
    }

    macro_rules! random_key_pair {
        () => {
            random_key_pair!(1024)
        };
        ($bits:expr) => {{
            use rsa::RsaPublicKey;

            let private_key = random_private_key!($bits);
            let public_key = RsaPublicKey::from(&private_key);
            (private_key, public_key)
        }};
    }

    macro_rules! random_public_key {
        () => {
            random_public_key!(1024)
        };
        ($bits:expr) => {{
            use rsa::RsaPublicKey;

            let private_key = random_private_key!($bits);
            RsaPublicKey::from(&private_key)
        }};
    }
}
