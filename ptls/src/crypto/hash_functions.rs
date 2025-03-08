use crate::crypto::{
    encryption::{Decrypt, Encrypt},
    signature::{Signing, Verifying},
    CryptoError,
};
use rsa::{
    sha2::{Sha224, Sha256, Sha384, Sha512},
    RsaPrivateKey, RsaPublicKey,
};

macro_rules! hash_enums {
    (
        $hash_functions:tt,
        [$(
            (
                $struct:ident, $new_arg:ty, $inner:ident,
                { $inherit_fn:ident, $inherit_fn_args:tt, $inherit_fn_ret:ty, $inherit_fn_call:tt }
            )
        ),*]
    ) => {
        hash_enums!(@define_hash_functions $hash_functions);

        $(
            hash_enums!(@define_hash_fields $hash_functions, $struct, $new_arg);

            paste::paste! {
                impl [<$struct Function>] {
                    hash_enums!(@define_fn_inherit $inherit_fn, $inherit_fn_ret, $inherit_fn_call, $inherit_fn_args, $hash_functions);
                }
            }

            hash_enums!(@define_fn_as_ref $inner, $new_arg, $struct, $hash_functions);
        )*

        #[allow(unused)]
        impl HashFunction {
            $(
                hash_enums!(@define_hash_to  $struct, $new_arg);
            )*
        }
    };
    (@define_hash_functions [$( ($hash_function:ident, $id:expr) ),*]) => {
        /// Hash functions supported by pTLS.
        #[allow(unused)]
        pub enum HashFunction {
            $(
                $hash_function = $id
            ),*
        }

        impl TryFrom<u8> for HashFunction {
            type Error = CryptoError;

            fn try_from(value: u8) -> Result<Self, Self::Error> {
                match value {
                    $(
                        $id => Ok(Self::$hash_function),
                    )*
                    _ => Err(Self::Error::InvalidHashFunction)
                }
            }
        }
    };

    (
        @define_hash_fields
        [$( ($hash_function:ident, $id:expr) ),*],
        $struct:ident, $new_arg:ty
    ) => {
        paste::paste! {
            #[allow(unused)]
            #[doc = "[`" $struct "`] hash functions."]
            pub enum [<$struct Function>] {
                $(
                    #[doc = "[`" $hash_function "`] hash funciton for [`" $struct "`]."]
                    $hash_function($struct<$hash_function>)
                ),*
            }

            #[allow(unused)]
            impl [<$struct Function>] {
                pub fn try_new(
                    hash_function: &HashFunction,
                    [<$new_arg:snake>]: $new_arg,
                ) -> Result<Self, CryptoError> {
                    match hash_function {
                        $(
                            HashFunction::$hash_function =>
                                $struct::<$hash_function>::try_new([< $new_arg:snake >])
                                    .map(Self::$hash_function)
                        ),*
                    }
                }

                pub fn hash_type(&self) -> HashFunction {
                    match self {
                        $(
                            Self::$hash_function(_) =>
                                HashFunction::$hash_function
                        ),*
                    }
                }
            }
        }
    };
    (
        @define_fn_as_ref
        None, $new_arg:ty, $struct:ident,
        $hash_functions: tt
    ) => {};
    (
        @define_fn_as_ref
        $inner:ident, $new_arg:ty, $struct:ident,
        $hash_functions: tt
    ) => {
        paste::paste! {
            impl AsRef<$new_arg> for [<$struct Function>] {
                fn as_ref(&self) -> &$new_arg {
                    hash_enums!(@define_fn_inner_as_ref
                        $hash_functions, self,
                        $inner
                    )
                }
            }
        }
    };
    (
        @define_fn_inner_as_ref
        [$( ($hash_function:ident, $id:expr) ),*],
        $self:ident,
        $inner:ident
    ) => {
        match $self {
            $(
                Self::$hash_function(inner) => &inner.$inner
            ),*
        }
    };
    (
        @define_fn_inherit
        $inherit_fn:ident, $inherit_fn_ret:ty, $inherit_fn_call: tt,
        ($( $ident:ident: $ty:ty ),*),
        $hash_functions: tt
    ) => {
        pub fn $inherit_fn(&self, $($ident: $ty),*) -> $inherit_fn_ret {
            hash_enums!(@define_fn_inner_inherit
                $hash_functions, self,
                $inherit_fn, $inherit_fn_call
            )
        }
    };
    (
        @define_fn_inner_inherit
        [$( ($hash_function:ident, $id:expr) ),*],
        $self:ident,
        $inherit_fn:ident, $inherit_fn_call:tt
    ) => {
        match $self {
            $(
                Self::$hash_function(inner) => inner.$inherit_fn$inherit_fn_call
            ),*
        }
    };

    (@define_hash_to $struct:ident, $new_arg:ty) => {
        paste::paste! {
            pub fn [<to_ $struct:lower>](
                &self, [<$new_arg:snake>]: $new_arg
            ) -> Result<[<$struct Function>], CryptoError> {
                [<$struct Function>]::try_new(self, [<$new_arg:snake>])
            }
        }
    }
}

hash_enums!(
    [(Sha224, 0), (Sha256, 1), (Sha384, 2), (Sha512, 3)],
    [
        (
            Encrypt, RsaPublicKey, public_key,
            {
                encrypt,
                (payload: &[u8]), Result<Vec<u8>, CryptoError>,
                (payload)
            }
        ),
        (
            Decrypt, RsaPrivateKey, private_key,
            {
                decrypt_owned,
                (payload: &mut Vec<u8>),  Result<(), CryptoError>,
                (payload)
            }
        ),
        (
            Signing, RsaPrivateKey, None,
            {
                sign,
                (msg: &[u8]), Vec<u8>,
                (msg)
            }
        ),
        (
            Verifying, RsaPublicKey, None,
            {
                verify,
                (msg: &[u8], signature: &[u8]), Result<(), CryptoError>,
                (msg, signature)
            }
        )
    ]
);
