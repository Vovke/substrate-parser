//! Traits for generalized metadata.
#[cfg(not(feature = "std"))]
use core::{
    any::TypeId,
    fmt::{Debug, Display},
};
#[cfg(feature = "std")]
use std::{
    any::TypeId,
    fmt::{Debug, Display},
};

use crate::std::{
    borrow::ToOwned,
    string::{String, ToString},
    vec::Vec,
};

use external_memory_tools::ExternalMemory;
use frame_metadata::{
    v14::{
        PalletMetadata as PalletMetadataV14, RuntimeMetadataV14,
        SignedExtensionMetadata as SignedExtensionMetadataV14,
    },
    v15::{
        PalletMetadata as PalletMetadataV15, RuntimeMetadataV15,
        SignedExtensionMetadata as SignedExtensionMetadataV15,
    },
    v16::{
        PalletMetadata as PalletMetadataV16, RuntimeMetadataV16,
        TransactionExtensionMetadata as TransactionExtensionMetadataV16,
    },
};
use parity_scale_codec::{Decode, Encode};
use scale_info::{
    form::PortableForm, interner::UntrackedSymbol, PortableRegistry, Type, TypeDef,
    TypeDefPrimitive, TypeParameter,
};

use crate::cards::ParsedData;
use crate::decode_all_as_type;
use crate::decoding_sci::husk_type;
use crate::error::{
    MetaStructureErrorV14, MetaVersionErrorPallets, RegistryError, RegistryInternalError,
};
use crate::propagated::Checker;
use crate::special_indicators::{SpecialtyStr, SpecialtyUnsignedInteger};

/// Metadata sufficient for parsing of signable transactions, storage data, and
/// bytes with a known type.
pub trait AsMetadata<E: ExternalMemory>: Debug + Sized {
    type TypeRegistry: ResolveType<E>;
    type MetaStructureError: Debug + Display + Eq;
    fn types(&self) -> Self::TypeRegistry;
    fn spec_name_version(&self) -> Result<SpecNameVersion, Self::MetaStructureError>;
    fn call_ty(&self) -> Result<UntrackedSymbol<TypeId>, Self::MetaStructureError>;
    fn signed_extensions(&self) -> Result<Vec<SignedExtensionMetadata>, Self::MetaStructureError>;
}

/// Metadata sufficient for parsing of unchecked extrinsics.
pub trait AsCompleteMetadata<E: ExternalMemory>: AsMetadata<E> {
    fn extrinsic_type_params(&self) -> Result<ExtrinsicTypeParams, Self::MetaStructureError>;
    fn extrinsic_version(&self) -> Result<u8, Self::MetaStructureError>;
}

/// Set of types defining unchecked extrinsic contents.
#[repr(C)]
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct ExtrinsicTypeParams {
    pub address_ty: UntrackedSymbol<TypeId>,
    pub call_ty: UntrackedSymbol<TypeId>,
    pub signature_ty: UntrackedSymbol<TypeId>,
    pub extra_ty: UntrackedSymbol<TypeId>,
}

/// Metadata of the signed extensions of an extrinsic.
#[repr(C)]
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct SignedExtensionMetadata {
    pub identifier: String,
    pub ty: UntrackedSymbol<TypeId>,
    pub additional_signed: UntrackedSymbol<TypeId>,
}

/// Transform type into [`SignedExtensionMetadata`].
macro_rules! impl_signed_extension_metadata_from {
    ($($ty: ty), *) => {
        $(
            impl From<$ty> for SignedExtensionMetadata {
                fn from(signed_extension_metadata: $ty) -> Self {
                    Self {
                        identifier: signed_extension_metadata.identifier,
                        ty: signed_extension_metadata.ty,
                        additional_signed: signed_extension_metadata.additional_signed,
                    }
                }
            }
        )*
    }
}

impl_signed_extension_metadata_from!(
    SignedExtensionMetadataV14<PortableForm>,
    SignedExtensionMetadataV15<PortableForm>
);

impl From<TransactionExtensionMetadataV16<PortableForm>> for SignedExtensionMetadata {
    fn from(ext: TransactionExtensionMetadataV16<PortableForm>) -> Self {
        Self {
            identifier: ext.identifier,
            ty: ext.ty,
            // In V16, `implicit` replaces `additional_signed` semantics.
            additional_signed: ext.implicit,
        }
    }
}

/// Metadata `spec_name` and `spec_version`.
///
/// There is a well-known Substrate type
/// [`RuntimeVersion`](https://docs.rs/sp-version/latest/sp_version/struct.RuntimeVersion.html)
/// that describes the contents of `Version` constant in `System` pallet of the
/// metadata in most chains. This `RuntimeVersion` has `spec_version` type set
/// to `u32`. However, it is not necessarily the case that all chains in all
/// versions will stick to `u32`, as the type of `Version` constant itself is
/// described in the metadata.
///
/// Thus, metadata is printed into `String`, to accomodate reasonable types
/// variation of the `spec_version`.
#[repr(C)]
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct SpecNameVersion {
    pub printed_spec_version: String,
    pub spec_name: String,
}

/// Generalized types registry. Could be addressed in external memory.
pub trait ResolveType<E: ExternalMemory> {
    fn resolve_ty(
        &self,
        id: u32,
        ext_memory: &mut E,
    ) -> Result<Type<PortableForm>, RegistryError<E>>;
}

impl<E: ExternalMemory> ResolveType<E> for PortableRegistry {
    fn resolve_ty(
        &self,
        id: u32,
        _ext_memory: &mut E,
    ) -> Result<Type<PortableForm>, RegistryError<E>> {
        match self.resolve(id) {
            Some(a) => Ok(a.to_owned()),
            None => Err(RegistryError::Internal(
                RegistryInternalError::TypeNotResolved { id },
            )),
        }
    }
}

impl<E: ExternalMemory> AsMetadata<E> for RuntimeMetadataV14 {
    type TypeRegistry = PortableRegistry;

    type MetaStructureError = MetaStructureErrorV14;

    fn types(&self) -> Self::TypeRegistry {
        self.types.to_owned()
    }

    fn spec_name_version(&self) -> Result<SpecNameVersion, Self::MetaStructureError> {
        let (value, ty) = version_constant_data_and_ty_v14(&self.pallets)?;
        match decode_all_as_type::<&[u8], (), RuntimeMetadataV14>(
            &ty,
            &value.as_ref(),
            &mut (),
            &self.types,
        ) {
            Ok(extended_data) => Ok(spec_name_version_from_runtime_version_data(
                extended_data.data,
            )?),
            Err(_) => Err(MetaStructureErrorV14::Version(
                MetaVersionErrorPallets::RuntimeVersionNotDecodeable,
            )),
        }
    }

    fn call_ty(&self) -> Result<UntrackedSymbol<TypeId>, Self::MetaStructureError> {
        let extrinsic_type_params =
            <RuntimeMetadataV14 as AsCompleteMetadata<E>>::extrinsic_type_params(self)?;
        Ok(extrinsic_type_params.call_ty)
    }

    fn signed_extensions(&self) -> Result<Vec<SignedExtensionMetadata>, Self::MetaStructureError> {
        Ok(self
            .extrinsic
            .signed_extensions
            .iter()
            .cloned()
            .map(SignedExtensionMetadata::from)
            .collect())
    }
}

impl<E: ExternalMemory> AsCompleteMetadata<E> for RuntimeMetadataV14 {
    fn extrinsic_type_params(&self) -> Result<ExtrinsicTypeParams, Self::MetaStructureError> {
        let husked_extrinsic_ty = husk_type::<(), RuntimeMetadataV14>(
            &self.extrinsic.ty,
            &self.types,
            &mut (),
            Checker::new(),
        )?;

        // check here that the underlying type is really `Vec<u8>`
        match husked_extrinsic_ty.ty.type_def {
            TypeDef::Sequence(s) => {
                let element_ty_id = s.type_param.id;
                let element_ty = self.types.resolve_ty(element_ty_id, &mut ())?;
                if let TypeDef::Primitive(TypeDefPrimitive::U8) = element_ty.type_def {
                    process_extrinsic_type_params(husked_extrinsic_ty.ty.type_params)
                } else {
                    Err(MetaStructureErrorV14::UnexpectedExtrinsicType {
                        extrinsic_ty_id: husked_extrinsic_ty.id,
                    })
                }
            }
            TypeDef::Composite(c) => {
                if c.fields.len() != 1 {
                    Err(MetaStructureErrorV14::UnexpectedExtrinsicType {
                        extrinsic_ty_id: husked_extrinsic_ty.id,
                    })
                } else {
                    let field_ty_id = c.fields[0].ty.id;
                    let field_ty = self.types.resolve_ty(field_ty_id, &mut ())?;
                    match field_ty.type_def {
                        TypeDef::Sequence(s) => {
                            let element_ty_id = s.type_param.id;
                            let element_ty = self.types.resolve_ty(element_ty_id, &mut ())?;
                            if let TypeDef::Primitive(TypeDefPrimitive::U8) = element_ty.type_def {
                                process_extrinsic_type_params(husked_extrinsic_ty.ty.type_params)
                            } else {
                                Err(MetaStructureErrorV14::UnexpectedExtrinsicType {
                                    extrinsic_ty_id: husked_extrinsic_ty.id,
                                })
                            }
                        }
                        _ => Err(MetaStructureErrorV14::UnexpectedExtrinsicType {
                            extrinsic_ty_id: husked_extrinsic_ty.id,
                        }),
                    }
                }
            }
            _ => Err(MetaStructureErrorV14::UnexpectedExtrinsicType {
                extrinsic_ty_id: husked_extrinsic_ty.id,
            }),
        }
    }

    fn extrinsic_version(&self) -> Result<u8, Self::MetaStructureError> {
        Ok(self.extrinsic.version)
    }
}

impl<E: ExternalMemory> AsMetadata<E> for RuntimeMetadataV15 {
    type TypeRegistry = PortableRegistry;

    type MetaStructureError = MetaVersionErrorPallets;

    fn types(&self) -> Self::TypeRegistry {
        self.types.to_owned()
    }

    fn spec_name_version(&self) -> Result<SpecNameVersion, Self::MetaStructureError> {
        let (value, ty) = version_constant_data_and_ty_v15(&self.pallets)?;
        match decode_all_as_type::<&[u8], (), RuntimeMetadataV15>(
            &ty,
            &value.as_ref(),
            &mut (),
            &self.types,
        ) {
            Ok(extended_data) => Ok(spec_name_version_from_runtime_version_data(
                extended_data.data,
            )?),
            Err(_) => Err(MetaVersionErrorPallets::RuntimeVersionNotDecodeable),
        }
    }

    fn call_ty(&self) -> Result<UntrackedSymbol<TypeId>, Self::MetaStructureError> {
        Ok(self.extrinsic.call_ty)
    }

    fn signed_extensions(&self) -> Result<Vec<SignedExtensionMetadata>, Self::MetaStructureError> {
        Ok(self
            .extrinsic
            .signed_extensions
            .iter()
            .cloned()
            .map(SignedExtensionMetadata::from)
            .collect())
    }
}

impl<E: ExternalMemory> AsCompleteMetadata<E> for RuntimeMetadataV15 {
    fn extrinsic_type_params(&self) -> Result<ExtrinsicTypeParams, Self::MetaStructureError> {
        Ok(ExtrinsicTypeParams {
            address_ty: self.extrinsic.address_ty,
            call_ty: self.extrinsic.call_ty,
            signature_ty: self.extrinsic.signature_ty,
            extra_ty: self.extrinsic.extra_ty,
        })
    }

    fn extrinsic_version(&self) -> Result<u8, Self::MetaStructureError> {
        Ok(self.extrinsic.version)
    }
}

/// Transform extrinsic type parameters set into [`ExtrinsicTypeParams`].
fn process_extrinsic_type_params(
    extrinsic_type_params: Vec<TypeParameter<PortableForm>>,
) -> Result<ExtrinsicTypeParams, MetaStructureErrorV14> {
    let mut found_address = None;
    let mut found_signature = None;
    let mut found_extra = None;
    let mut found_call = None;

    for param in extrinsic_type_params.iter() {
        match param.name.as_str() {
            ADDRESS_INDICATOR => found_address = param.ty,
            SIGNATURE_INDICATOR => found_signature = param.ty,
            EXTRA_INDICATOR => found_extra = param.ty,
            CALL_INDICATOR => found_call = param.ty,
            _ => (),
        }
    }

    let address_ty = found_address.ok_or(MetaStructureErrorV14::NoAddressParam)?;
    let call_ty = found_call.ok_or(MetaStructureErrorV14::NoCallParam)?;
    let extra_ty = found_extra.ok_or(MetaStructureErrorV14::NoExtraParam)?;
    let signature_ty = found_signature.ok_or(MetaStructureErrorV14::NoSignatureParam)?;

    Ok(ExtrinsicTypeParams {
        address_ty,
        call_ty,
        signature_ty,
        extra_ty,
    })
}

/// [`TypeParameter`] name for `address`.
pub const ADDRESS_INDICATOR: &str = "Address";

/// [`TypeParameter`] name for `call`.
pub const CALL_INDICATOR: &str = "Call";

/// [`TypeParameter`] name for `extra`.
pub const EXTRA_INDICATOR: &str = "Extra";

/// [`TypeParameter`] name for `signature`.
pub const SIGNATURE_INDICATOR: &str = "Signature";

/// Find `Version` constant and its type in `System` pallet.
macro_rules! version_constant_data_and_ty {
    ($(#[$attr:meta] $ty: ty, $func: ident), *) => {
        $(
            #[$attr]
            pub fn $func(pallets: &[$ty]) -> Result<(Vec<u8>, UntrackedSymbol<TypeId>), MetaVersionErrorPallets> {
                let mut runtime_version_data_and_ty = None;
                let mut system_block = false;
                for pallet in pallets.iter() {
                    if pallet.name == "System" {
                        system_block = true;
                        for constant in pallet.constants.iter() {
                            if constant.name == "Version" {
                                runtime_version_data_and_ty = Some((constant.value.to_vec(), constant.ty))
                            }
                        }
                        break;
                    }
                }
                if !system_block {
                    return Err(MetaVersionErrorPallets::NoSystemPallet);
                }
                runtime_version_data_and_ty.ok_or(MetaVersionErrorPallets::NoVersionInConstants)
            }
        )*
    }
}

version_constant_data_and_ty!(
    /// Find `Version` constant and its type in `System` pallet for `V14` metadata.
    PalletMetadataV14<PortableForm>,
    version_constant_data_and_ty_v14
);
version_constant_data_and_ty!(
    /// Find `Version` constant and its type in `System` pallet for `V15` metadata.
    PalletMetadataV15<PortableForm>,
    version_constant_data_and_ty_v15
);
version_constant_data_and_ty!(
    /// Find `Version` constant and its type in `System` pallet for `V16` metadata.
    PalletMetadataV16<PortableForm>,
    version_constant_data_and_ty_v16
);

impl<E: ExternalMemory> AsMetadata<E> for RuntimeMetadataV16 {
    type TypeRegistry = PortableRegistry;

    type MetaStructureError = MetaVersionErrorPallets;

    fn types(&self) -> Self::TypeRegistry {
        self.types.to_owned()
    }

    fn spec_name_version(&self) -> Result<SpecNameVersion, Self::MetaStructureError> {
        let (value, ty) = version_constant_data_and_ty_v16(&self.pallets)?;
        match decode_all_as_type::<&[u8], (), RuntimeMetadataV16>(
            &ty,
            &value.as_ref(),
            &mut (),
            &self.types,
        ) {
            Ok(extended_data) => Ok(spec_name_version_from_runtime_version_data(
                extended_data.data,
            )?),
            Err(_) => Err(MetaVersionErrorPallets::RuntimeVersionNotDecodeable),
        }
    }

    fn call_ty(&self) -> Result<UntrackedSymbol<TypeId>, Self::MetaStructureError> {
        // In V16, call type is exposed via outer enums
        Ok(self.outer_enums.call_enum_ty)
    }

    fn signed_extensions(&self) -> Result<Vec<SignedExtensionMetadata>, Self::MetaStructureError> {
        // In V16, extensions are versioned. Pick the highest supported
        // extrinsic format version from metadata and use its mapping.
        // If mapping is missing, fall back to full list order.
        let selected_version = *self.extrinsic.versions.iter().max().unwrap_or(&0);
        if let Some(indexes) = self
            .extrinsic
            .transaction_extensions_by_version
            .get(&selected_version)
        {
            Ok(indexes
                .iter()
                .filter_map(|idx| self
                    .extrinsic
                    .transaction_extensions
                    .get((*idx as usize))
                    .cloned())
                .map(SignedExtensionMetadata::from)
                .collect())
        } else {
            Ok(self
                .extrinsic
                .transaction_extensions
                .iter()
                .cloned()
                .map(SignedExtensionMetadata::from)
                .collect())
        }
    }
}

impl<E: ExternalMemory> AsCompleteMetadata<E> for RuntimeMetadataV16 {
    fn extrinsic_type_params(&self) -> Result<ExtrinsicTypeParams, Self::MetaStructureError> {
        Ok(ExtrinsicTypeParams {
            address_ty: self.extrinsic.address_ty,
            // In V16, call type is exposed via outer enums
            call_ty: self.outer_enums.call_enum_ty,
            signature_ty: self.extrinsic.signature_ty,
            // V16 does not provide a single `extra` type; decoding will be handled
            // as a sequence of extension types downstream for unchecked extrinsics.
            // Keep a placeholder; it won't be used directly in V16 path.
            extra_ty: self.outer_enums.call_enum_ty,
        })
    }

    fn extrinsic_version(&self) -> Result<u8, Self::MetaStructureError> {
        // Choose the highest supported version for validation (commonly 4).
        Ok(*self.extrinsic.versions.iter().max().unwrap_or(&0))
    }
}

/// Extract [`SpecNameVersion`] from parsed data.
fn spec_name_version_from_runtime_version_data(
    parsed_data: ParsedData,
) -> Result<SpecNameVersion, MetaVersionErrorPallets> {
    // Helpers to tolerate wrapping around expected values (Composite/Variant/RuntimeString).
    fn extract_text(data: &ParsedData) -> Option<String> {
        match data {
            ParsedData::Text { text, .. } => Some(text.to_owned()),
            ParsedData::Sequence(seq) => {
                if let crate::cards::Sequence::U8(bytes) = &seq.data {
                    String::from_utf8(bytes.clone()).ok()
                } else {
                    None
                }
            }
            ParsedData::Composite(fields) => {
                if fields.len() == 1 {
                    extract_text(&fields[0].data.data)
                } else {
                    None
                }
            }
            ParsedData::Variant(variant) => {
                if variant.fields.len() == 1 {
                    extract_text(&variant.fields[0].data.data)
                } else {
                    None
                }
            }
            _ => None
        }
    }

    fn extract_u128(data: &ParsedData) -> Option<u128> {
        match data {
            ParsedData::PrimitiveU8 { value, .. } => Some((*value).into()),
            ParsedData::PrimitiveU16 { value, .. } => Some((*value).into()),
            ParsedData::PrimitiveU32 { value, .. } => Some((*value).into()),
            ParsedData::PrimitiveU64 { value, .. } => Some((*value).into()),
            ParsedData::PrimitiveU128 { value, .. } => Some(*value),
            ParsedData::Composite(fields) => {
                if fields.len() == 1 {
                    extract_u128(&fields[0].data.data)
                } else {
                    None
                }
            }
            ParsedData::Variant(variant) => {
                if variant.fields.len() == 1 {
                    extract_u128(&variant.fields[0].data.data)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    let mut printed_spec_version = None;
    let mut spec_name = None;

    if let ParsedData::Composite(fields) = parsed_data {
        for field in fields.iter() {
            match &field.data.data {
                ParsedData::PrimitiveU8 {
                    value,
                    specialty: SpecialtyUnsignedInteger::SpecVersion,
                } => {
                    if printed_spec_version.is_none() {
                        printed_spec_version = Some(value.to_string())
                    } else {
                        return Err(MetaVersionErrorPallets::SpecVersionIdentifierTwice);
                    }
                }
                ParsedData::PrimitiveU16 {
                    value,
                    specialty: SpecialtyUnsignedInteger::SpecVersion,
                } => {
                    if printed_spec_version.is_none() {
                        printed_spec_version = Some(value.to_string())
                    } else {
                        return Err(MetaVersionErrorPallets::SpecVersionIdentifierTwice);
                    }
                }
                ParsedData::PrimitiveU32 {
                    value,
                    specialty: SpecialtyUnsignedInteger::SpecVersion,
                } => {
                    if printed_spec_version.is_none() {
                        printed_spec_version = Some(value.to_string())
                    } else {
                        return Err(MetaVersionErrorPallets::SpecVersionIdentifierTwice);
                    }
                }
                ParsedData::PrimitiveU64 {
                    value,
                    specialty: SpecialtyUnsignedInteger::SpecVersion,
                } => {
                    if printed_spec_version.is_none() {
                        printed_spec_version = Some(value.to_string())
                    } else {
                        return Err(MetaVersionErrorPallets::SpecVersionIdentifierTwice);
                    }
                }
                ParsedData::PrimitiveU128 {
                    value,
                    specialty: SpecialtyUnsignedInteger::SpecVersion,
                } => {
                    if printed_spec_version.is_none() {
                        printed_spec_version = Some(value.to_string())
                    } else {
                        return Err(MetaVersionErrorPallets::SpecVersionIdentifierTwice);
                    }
                }
                ParsedData::Text {
                    text,
                    specialty: SpecialtyStr::SpecName,
                } => {
                    if spec_name.is_none() {
                        spec_name = Some(text.to_owned())
                    } else {
                        return Err(MetaVersionErrorPallets::SpecNameIdentifierTwice);
                    }
                }
                // Fallback: if specialty markers are not set, match by field name explicitly.
                ParsedData::PrimitiveU8 { value, .. } => {
                    if let Some(name) = &field.field_name {
                        if name == "spec_version" {
                            if printed_spec_version.is_none() {
                                printed_spec_version = Some(value.to_string())
                            } else {
                                return Err(MetaVersionErrorPallets::SpecVersionIdentifierTwice);
                            }
                        }
                    }
                }
                ParsedData::PrimitiveU16 { value, .. } => {
                    if let Some(name) = &field.field_name {
                        if name == "spec_version" {
                            if printed_spec_version.is_none() {
                                printed_spec_version = Some(value.to_string())
                            } else {
                                return Err(MetaVersionErrorPallets::SpecVersionIdentifierTwice);
                            }
                        }
                    }
                }
                ParsedData::PrimitiveU32 { value, .. } => {
                    if let Some(name) = &field.field_name {
                        if name == "spec_version" {
                            if printed_spec_version.is_none() {
                                printed_spec_version = Some(value.to_string())
                            } else {
                                return Err(MetaVersionErrorPallets::SpecVersionIdentifierTwice);
                            }
                        }
                    }
                }
                ParsedData::PrimitiveU64 { value, .. } => {
                    if let Some(name) = &field.field_name {
                        if name == "spec_version" {
                            if printed_spec_version.is_none() {
                                printed_spec_version = Some(value.to_string())
                            } else {
                                return Err(MetaVersionErrorPallets::SpecVersionIdentifierTwice);
                            }
                        }
                    }
                }
                ParsedData::PrimitiveU128 { value, .. } => {
                    if let Some(name) = &field.field_name {
                        if name == "spec_version" {
                            if printed_spec_version.is_none() {
                                printed_spec_version = Some(value.to_string())
                            } else {
                                return Err(MetaVersionErrorPallets::SpecVersionIdentifierTwice);
                            }
                        }
                    }
                }
                ParsedData::Text { text, .. } => {
                    if let Some(name) = &field.field_name {
                        if name == "spec_name" {
                            if spec_name.is_none() {
                                spec_name = Some(text.to_owned())
                            } else {
                                return Err(MetaVersionErrorPallets::SpecNameIdentifierTwice);
                            }
                        }
                    }
                }
                ParsedData::Sequence(sequence_data) => {
                    if let Some(name) = &field.field_name {
                        if name == "spec_name" {
                            // Accept Vec<u8> and try UTF-8 to produce a String
                            if let crate::cards::Sequence::U8(bytes) = &sequence_data.data {
                                if let Ok(s) = String::from_utf8(bytes.clone()) {
                                    if spec_name.is_none() {
                                        spec_name = Some(s)
                                    } else {
                                        return Err(MetaVersionErrorPallets::SpecNameIdentifierTwice);
                                    }
                                }
                            }
                        }
                    }
                }
                // Tolerate composite/variant wrappers for both spec_name and spec_version
                ParsedData::Composite(fields) => {
                    if let Some(name) = &field.field_name {
                        if name == "spec_name" {
                            if let Some(s) = extract_text(&field.data.data) {
                                if spec_name.is_none() {
                                    spec_name = Some(s)
                                } else {
                                    return Err(MetaVersionErrorPallets::SpecNameIdentifierTwice);
                                }
                            }
                        } else if name == "spec_version" {
                            if let Some(v) = extract_u128(&field.data.data) {
                                if printed_spec_version.is_none() {
                                    printed_spec_version = Some(v.to_string())
                                } else {
                                    return Err(MetaVersionErrorPallets::SpecVersionIdentifierTwice);
                                }
                            }
                        }
                    }
                }
                ParsedData::Variant(_) => {
                    if let Some(name) = &field.field_name {
                        if name == "spec_name" {
                            if let Some(s) = extract_text(&field.data.data) {
                                if spec_name.is_none() {
                                    spec_name = Some(s)
                                } else {
                                    return Err(MetaVersionErrorPallets::SpecNameIdentifierTwice);
                                }
                            }
                        } else if name == "spec_version" {
                            if let Some(v) = extract_u128(&field.data.data) {
                                if printed_spec_version.is_none() {
                                    printed_spec_version = Some(v.to_string())
                                } else {
                                    return Err(MetaVersionErrorPallets::SpecVersionIdentifierTwice);
                                }
                            }
                        }
                    }
                }
                _ => (),
            }
        }
    } else {
        return Err(MetaVersionErrorPallets::UnexpectedRuntimeVersionFormat);
    }
    let printed_spec_version = match printed_spec_version {
        Some(a) => a,
        None => return Err(MetaVersionErrorPallets::NoSpecVersionIdentifier),
    };
    let spec_name = match spec_name {
        Some(a) => a,
        None => return Err(MetaVersionErrorPallets::NoSpecNameIdentifier),
    };
    Ok(SpecNameVersion {
        printed_spec_version,
        spec_name,
    })
}
