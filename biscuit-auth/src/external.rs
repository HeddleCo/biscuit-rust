//! Asynchronous signing without importing private keys into Biscuit.
//!
//! Prepare, sign `payload_to_sign()` in the caller, then consume the draft with
//! `attach()`. Only Ed25519 signature-v1 blocks are emitted. Existing signature
//! payload helpers and verification are reused without changing the wire format.
//!
//! A standard unsealed Biscuit contains its next private key. Non-exportable
//! keys cannot produce that proof: keep `ExternalBiscuit` with the external key
//! handles until sealing. The final sealed token is a standard Biscuit.

use prost::Message;

use crate::{
    Biscuit, PublicKey,
    builder::{Algorithm, BiscuitBuilder, BlockBuilder},
    crypto::{self, Signature},
    datalog::SymbolTable,
    error,
    format::{convert::token_block_to_proto_block, schema},
};

/// Signed blocks whose next private key remains outside the library.
#[derive(Clone)]
pub struct ExternalBiscuit {
    root: PublicKey,
    root_key_id: Option<u32>,
    authority: schema::SignedBlock,
    blocks: Vec<schema::SignedBlock>,
    symbols: SymbolTable,
}

enum Pending {
    Mint {
        root: PublicKey,
        root_key_id: Option<u32>,
    },
    Append(ExternalBiscuit),
}

/// Immutable signing request for an authority or attenuation block.
pub struct UnsignedBlock {
    pending: Pending,
    block: schema::SignedBlock,
    symbols: SymbolTable,
    signer: PublicKey,
    payload: Vec<u8>,
}

impl UnsignedBlock {
    /// Build an authority with caller-supplied root and next public keys.
    pub fn mint(
        builder: BiscuitBuilder,
        root: PublicKey,
        next: PublicKey,
    ) -> Result<Self, error::Token> {
        ed25519(&root)?;
        ed25519(&next)?;
        let (block, symbols) = encode(builder.inner, SymbolTable::new(), next)?;
        let payload = crypto::generate_authority_block_signature_payload_v1(&block.block, &next, 1);
        Ok(Self {
            pending: Pending::Mint {
                root,
                root_key_id: builder.root_key_id,
            },
            block,
            symbols,
            signer: root,
            payload,
        })
    }

    /// Exactly the bytes the caller must sign; no hashing or encoding in JS.
    pub fn payload_to_sign(&self) -> &[u8] {
        &self.payload
    }

    /// Verify the supplied signature before adding the signed block.
    pub fn attach(mut self, signature: &[u8]) -> Result<ExternalBiscuit, error::Token> {
        self.signer
            .verify_signature(&self.payload, &Signature::from_bytes(signature)?)?;
        self.block.signature = signature.to_vec();
        match self.pending {
            Pending::Mint { root, root_key_id } => Ok(ExternalBiscuit {
                root,
                root_key_id,
                authority: self.block,
                blocks: Vec::new(),
                symbols: self.symbols,
            }),
            Pending::Append(mut draft) => {
                draft.blocks.push(self.block);
                draft.symbols = self.symbols;
                Ok(draft)
            }
        }
    }
}

impl ExternalBiscuit {
    fn last(&self) -> &schema::SignedBlock {
        self.blocks.last().unwrap_or(&self.authority)
    }

    /// Prepare an attenuation using the current external next-key handle.
    pub fn prepare_append(
        self,
        builder: BlockBuilder,
        next: PublicKey,
    ) -> Result<UnsignedBlock, error::Token> {
        ed25519(&next)?;
        let previous = self.last();
        let signer = PublicKey::from_proto(&previous.next_key)?;
        let (block, symbols) = encode(builder, self.symbols.clone(), next)?;
        let payload = crypto::generate_block_signature_payload_v1(
            &block.block,
            &next,
            None,
            &Signature::from_bytes(&previous.signature)?,
            1,
        );
        Ok(UnsignedBlock {
            pending: Pending::Append(self),
            block,
            symbols,
            signer,
            payload,
        })
    }

    /// Prepare the standard final proof signature. Consumes this draft.
    pub fn prepare_seal(self) -> Result<UnsignedSeal, error::Token> {
        let last = self.last();
        let block = crypto::Block {
            data: last.block.clone(),
            next_key: PublicKey::from_proto(&last.next_key)?,
            signature: Signature::from_bytes(&last.signature)?,
            external_signature: None,
            version: 1,
        };
        let payload = crypto::generate_seal_signature_payload_v0(&block);
        Ok(UnsignedSeal {
            draft: self,
            payload,
        })
    }
}

/// An immutable request for the final proof signature, not another block.
pub struct UnsignedSeal {
    draft: ExternalBiscuit,
    payload: Vec<u8>,
}

impl UnsignedSeal {
    pub fn payload_to_sign(&self) -> &[u8] {
        &self.payload
    }

    /// Attach the final signature, then run the unchanged Biscuit verifier.
    pub fn attach(self, signature: &[u8]) -> Result<Vec<u8>, error::Token> {
        let signer = PublicKey::from_proto(&self.draft.last().next_key)?;
        signer.verify_signature(&self.payload, &Signature::from_bytes(signature)?)?;
        let wire = schema::Biscuit {
            root_key_id: self.draft.root_key_id,
            authority: self.draft.authority,
            blocks: self.draft.blocks,
            proof: schema::Proof {
                content: Some(schema::proof::Content::FinalSignature(signature.to_vec())),
            },
        };
        let bytes = wire.encode_to_vec();
        Biscuit::from(&bytes, self.draft.root)?;
        Ok(bytes)
    }
}

fn ed25519(key: &PublicKey) -> Result<(), error::Token> {
    if key.algorithm() != Algorithm::Ed25519.into() {
        return Err(error::Format::SerializationError(
            "external builder requires Ed25519 keys".to_string(),
        )
        .into());
    }
    Ok(())
}

fn encode(
    builder: BlockBuilder,
    mut symbols: SymbolTable,
    next: PublicKey,
) -> Result<(schema::SignedBlock, SymbolTable), error::Token> {
    let block = builder.build(symbols.clone());
    symbols.extend(&block.symbols)?;
    symbols.public_keys.extend(&block.public_keys)?;
    let wire = schema::SignedBlock {
        block: token_block_to_proto_block(&block).encode_to_vec(),
        next_key: next.to_proto(),
        signature: Vec::new(),
        external_signature: None,
        version: Some(1),
    };
    Ok((wire, symbols))
}
