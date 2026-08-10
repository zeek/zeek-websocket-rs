use proc_macro_error2::{abort, proc_macro_error};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Data, DeriveInput, Field, Fields, Ident, Type, parse_macro_input, spanned::Spanned};

/// # Derive macro to convert a type from and to a `zeek_websocket_types::Value`
///
/// Zeek's WebSocket API encodes Zeek `record` values as vectors. This derive macro adds support
/// for automatically converting Rust types to and from the encoding. It supports `struct`s
/// made up of fields which implement `TryFrom<Value>` and `Into<Value>`.
///
/// ```
/// # use zeek_websocket_derive::ZeekType;
/// # use zeek_websocket_types::Value;
/// #[derive(Debug, PartialEq)] // Not required.
/// #[derive(ZeekType)]
/// struct Record {
///     a: i64,
///     b: u64,
/// }
///
/// let r = Record { a: -32, b: 1024 };
///
/// let value = Value::from(r);
/// assert_eq!(
///     value,
///     Value::Vector(vec![Value::Integer(-32), Value::Count(1024)]));
///
/// let r = Record::try_from(value).unwrap();
/// assert_eq!(r, Record { a: -32, b: 1024 });
/// ```
///
/// If more than the expected number of fields are received they are silently discarded.
///
/// ```
/// # use zeek_websocket_derive::ZeekType;
/// # use zeek_websocket_types::Value;
/// # #[derive(Debug, PartialEq)] // Not required.
/// # #[derive(ZeekType)]
/// # struct Record {
/// #     a: i64,
/// #     b: u64,
/// # }
/// #
/// let v = Value::Vector(vec![Value::Integer(1), Value::Count(2), Value::Count(3)]);
/// let r: Record = v.try_into().unwrap();
/// assert_eq!(r, Record { a: 1, b: 2 });
///
/// // Unknown fields are not magically added back when encoding. This is supported by Zeek.
/// let v2 = Value::from(r);
/// assert_eq!(v2, Value::Vector(vec![Value::Integer(1), Value::Count(2)]));
/// ```
///
/// ## Optional fields
///
/// Zeek `record` fields which can be unset are marked `&optional`, e.g.,
///
/// ```zeek
/// type X: record {
///     a: count;
///     b: int &optional;
/// };
/// ```
///
/// This is used to evolve Zeek `record` types so that users do not need to be updated if
/// more fields are added.
///
/// The WebSocket API encodes unset fields as `Value::None`. To work with such types the Rust type
/// should be an `Option`, e.g.,
///
/// ```
/// # use zeek_websocket_types::Value;
/// # use zeek_websocket_derive::ZeekType;
/// #[derive(ZeekType)]
/// struct X {
///     a: u64,
///     b: Option<i64>,
/// }
/// ```
///
/// `Value::None` maps onto `Option::None`.
///
/// ```
/// # use zeek_websocket_types::Value;
/// # use zeek_websocket_derive::ZeekType;
/// # #[derive(Debug, PartialEq)] // Not required.
/// # #[derive(ZeekType)]
/// # struct X {
/// #     a: u64,
/// #     b: Option<i64>,
/// # }
/// let v = Value::Vector(vec![Value::Count(1), Value::None]);
/// let x: X = v.try_into().unwrap();
/// assert_eq!(x, X { a: 1, b: None });
/// ```
///
/// Anything else maps onto `Option::Some`.
/// ```
/// # use zeek_websocket_types::Value;
/// # use zeek_websocket_derive::ZeekType;
/// # #[derive(Debug, PartialEq)] // Not required.
/// # #[derive(ZeekType)]
/// # struct X {
/// #     a: u64,
/// #     b: Option<i64>,
/// # }
/// let v = Value::Vector(vec![Value::Count(1), Value::Integer(2)]);
/// let x: X = v.try_into().unwrap();
/// assert_eq!(x, X { a: 1, b: Some(2) });
/// ```
///
/// If no value was received for an optional field it is set to `None`. Non-`Option` fields are
/// always required.
///
/// ```
/// # use zeek_websocket_types::Value;
/// # use zeek_websocket_derive::ZeekType;
/// # #[derive(Debug, PartialEq)] // Not required.
/// # #[derive(ZeekType)]
/// # struct X {
/// #     a: u64,
/// #     b: Option<i64>,
/// # }
/// let v = Value::Vector(vec![Value::Count(1)]);
/// let x: X = v.try_into().unwrap();
/// assert_eq!(x, X { a: 1, b: None });
///
/// // Error for non-`Option` fields.
/// let x: Result<X, _> = Value::Vector(vec![]).try_into();
/// assert!(x.is_err());
/// ```
///
#[proc_macro_error]
#[proc_macro_derive(ZeekType)]
pub fn derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);

    let name = &ast.ident;

    let Data::Struct(struct_) = &ast.data else {
        abort!(ast.span(), "only structs can derive ZeekType");
    };

    let Fields::Named(fields) = &struct_.fields else {
        abort!(
            ast.span(),
            "only structs with named fields can derive ZeekType"
        );
    };
    let fields: Vec<_> = fields.named.iter().collect();

    let value_from = impl_value_from(name, &fields);
    let from_value = impl_from_value(name, &fields);

    quote! {
        #value_from

        #from_value
    }
    .into()
}

fn impl_value_from(name: &Ident, fields: &[&Field]) -> TokenStream {
    let fields = fields.iter().map(|f| {
        let Some(field_name) = &f.ident else {
            abort!(f.span(), "unsupported field name");
        };

        if looks_like_option(&f.ty) {
            let x = format_ident!("__zeek_websocket_derive__impl_value_from_{name}__{field_name}");
            quote! {
                match value.#field_name {
                    Some(#x) => ::zeek_websocket_types::Value::from(#x),
                    None => ::zeek_websocket_types::Value::None,
                }
            }
        } else {
            quote! { ::zeek_websocket_types::Value::from(value.#field_name) }
        }
    });

    quote! {
        impl From<#name> for ::zeek_websocket_types::Value {
            fn from(value: #name) -> Self {
                Self::from(::std::vec::Vec::<::zeek_websocket_types::Value>::from([#(#fields), *]))
            }
        }
    }
}

fn impl_from_value(name: &Ident, fields: &[&Field]) -> TokenStream {
    let xs = format_ident!("__zeek_websocket_derive__impl_from_value_{name}");

    // Validate that all fields are named so we can cleanly unwrap below.
    if fields.iter().any(|f| f.ident.is_none()) {
        abort!(name.span(), "unnamed fields are unsupported");
    }

    let fields = fields.iter().map(|f| {
        let field_name = f.ident.as_ref().unwrap();

        let init = quote! {
            #xs
                .next()
                .unwrap_or(::zeek_websocket_types::Value::None)
        };

        let x = format_ident!("__zeek_websocket_derive__impl_from_value_{name}__{field_name}");

        (
            field_name.clone(),
            if looks_like_option(&f.ty) {
                quote! {
                    let #field_name = match #init {
                        ::zeek_websocket_types::Value::None => None,
                        #x => Some(#x.try_into()?),
                    };
                }
            } else {
                quote! { let #field_name = #init.try_into()?; }
            },
        )
    });

    let (names, inits): (Vec<_>, Vec<_>) = fields.unzip();

    quote! {
        impl TryFrom<::zeek_websocket_types::Value> for #name {
            type Error = ::zeek_websocket_types::ConversionError;

            fn try_from(value: ::zeek_websocket_types::Value) -> Result<Self, Self::Error> {
                #[allow(non_snake_case)]
                let ::zeek_websocket_types::Value::Vector(#xs) = value else {
                    return Err(::zeek_websocket_types::ConversionError::MismatchedTypes);
                };
                let mut #xs = #xs.into_iter();

                #(#inits)*

                Ok(#name { #(#names),* })
            }
        }
    }
}

// Helper function to detect whether a type is likely an instance of `Option`.
fn looks_like_option(ty: &Type) -> bool {
    let Type::Path(p) = ty else {
        abort!(ty.span(), "unsupported type");
    };

    p.path
        .segments
        .last()
        .map(|ty| ty.ident == "Option")
        .unwrap_or_default()
}
