use proc_macro::{self, TokenStream};
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(StructTag, attributes(struct_tag))]
pub fn derive(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input);
    let ident = &input.ident;

    let tag: syn::LitInt = input
        .attrs
        .into_iter()
        .find(|attr| attr.path().is_ident("struct_tag"))
        .expect("struct_tag not found")
        .parse_args()
        .expect("Failed to parse struct_tag argument");

    let output = quote! {
        impl StructTag for #ident {
            #[inline]
            fn tag() -> u16 {
                #tag
            }
        }
    };

    output.into()
}
