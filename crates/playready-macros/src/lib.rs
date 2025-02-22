use proc_macro::{self, TokenStream};
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(StructTag, attributes(struct_tag))]
pub fn derive_struct_tag(input: TokenStream) -> TokenStream {
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
            const TAG: u16 = #tag;
        }
    };

    output.into()
}

#[proc_macro_derive(StructRawSize)]
pub fn derive_size(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input);
    let ident = &input.ident;

    let data = match input.data {
        syn::Data::Struct(data_struct) => data_struct,
        _ => unimplemented!(),
    };

    let fields = data.fields.iter().map(|field| {
        let ident = &field.ident;
        quote! { self.#ident.get_raw_size() }
    });

    quote! {
        impl StructRawSize for #ident {
            #[inline]
            fn get_raw_size(&self) -> usize {
                0 #(+ #fields)*
            }
        }
    }
    .into()
}
