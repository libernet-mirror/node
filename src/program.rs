use crate::libernet::wasm::{
    self, CatchElement, FuncType, ImportSection, PlainType, ProgramModule, RefType, SubType,
    TypeRefFunc, TypeSection, Version,
};
use crate::libernet::wasm::{OpCode, Operator, operator::Operator::*};
use anyhow::{Context, Result, anyhow, bail};
use sha3::Digest;

macro_rules! some {
    ($expr:expr, $pat:pat => $body:block, $msg:expr $(,)?) => {{
        match $expr {
            Some($pat) => $body,
            _ => anyhow::bail!($msg),
        }
    }};
}

trait Sha3Hash {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()>;
}

impl Sha3Hash for u32 {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        hasher.update(self.to_le_bytes());
        Ok(())
    }
}

impl Sha3Hash for u64 {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        hasher.update(self.to_le_bytes());
        Ok(())
    }
}

impl Sha3Hash for i32 {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        hasher.update(self.to_le_bytes());
        Ok(())
    }
}

impl Sha3Hash for i64 {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        hasher.update(self.to_le_bytes());
        Ok(())
    }
}

impl<T: Sha3Hash> Sha3Hash for Vec<T> {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        (self.len() as u64).sha3_hash(hasher)?;
        for elem in self {
            elem.sha3_hash(hasher)?;
        }
        Ok(())
    }
}

impl Sha3Hash for wasm::ValueType {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        let value_code = self.value_type.context("Value type is required")?;
        let plain_type = PlainType::try_from(value_code)?;
        value_code.sha3_hash(hasher)?;
        match plain_type {
            PlainType::ValueTypeI32
            | PlainType::ValueTypeI64
            | PlainType::ValueTypeF32
            | PlainType::ValueTypeF64
            | PlainType::ValueTypeV128 => {
                if self.reference_type.is_some() {
                    bail!("Reference type is set for primitive value type");
                }
                hasher.update([0]);
            }
            PlainType::ValueTypeRef => {
                let ref_code = self.reference_type.context("Reference type is required")?;
                if RefType::try_from(ref_code).is_err() {
                    bail!("Invalid reference type");
                }
                ref_code.sha3_hash(hasher)?;
            }
        };
        Ok(())
    }
}

impl Sha3Hash for wasm::block_type::BlockType {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        match self {
            wasm::block_type::BlockType::Empty(_) => hasher.update([0]),
            wasm::block_type::BlockType::ValueType(vt) => vt.sha3_hash(hasher)?,
            wasm::block_type::BlockType::TypeIndex(v) => v.sha3_hash(hasher)?,
        };
        Ok(())
    }
}

impl Sha3Hash for CatchElement {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        let catch_element = self
            .catch_element
            .ok_or(anyhow!("Catch element is required"))?;
        match catch_element {
            wasm::catch_element::CatchElement::One(one) => {
                hasher.update([0]);
                one.tag
                    .ok_or(anyhow!("One: Tag is required"))?
                    .sha3_hash(hasher)?;
                one.label
                    .ok_or(anyhow!("One: Label is required"))?
                    .sha3_hash(hasher)?;
            }
            wasm::catch_element::CatchElement::OneRef(one_ref) => {
                hasher.update([1]);
                one_ref
                    .tag
                    .ok_or(anyhow!("OneRef: Tag is required"))?
                    .sha3_hash(hasher)?;
                one_ref
                    .label
                    .ok_or(anyhow!("OneRef: Label is required"))?
                    .sha3_hash(hasher)?;
            }
            wasm::catch_element::CatchElement::All(all) => {
                hasher.update([2]);
                all.label
                    .ok_or(anyhow!("All: Label is required"))?
                    .sha3_hash(hasher)?;
            }
            wasm::catch_element::CatchElement::AllRef(all_ref) => {
                hasher.update([3]);
                all_ref
                    .label
                    .ok_or(anyhow!("AllRef: Label is required"))?
                    .sha3_hash(hasher)?;
            }
        };
        Ok(())
    }
}

impl Sha3Hash for Operator {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        let opcode_value = self.opcode.context("Opcode is required")?;
        let opcode = OpCode::try_from(opcode_value)?;
        let operator = &self.operator;

        opcode_value.sha3_hash(hasher)?;

        match opcode {
            OpCode::Unreachable
            | OpCode::Nop
            | OpCode::Else
            | OpCode::End
            | OpCode::Return
            | OpCode::Drop
            | OpCode::Select
            | OpCode::I32Eqz
            | OpCode::I32Eq
            | OpCode::I32Ne
            | OpCode::I32LtSigned
            | OpCode::I32LtUnsigned
            | OpCode::I32GtSigned
            | OpCode::I32GtUnsigned
            | OpCode::I32LeSigned
            | OpCode::I32LeUnsigned
            | OpCode::I32GeSigned
            | OpCode::I32GeUnsigned
            | OpCode::I64Eqz
            | OpCode::I64Eq
            | OpCode::I64Ne
            | OpCode::I64LtSigned
            | OpCode::I64LtUnsigned
            | OpCode::I64GtSigned
            | OpCode::I64GtUnsigned
            | OpCode::I64LeSigned
            | OpCode::I64LeUnsigned
            | OpCode::I64GeSigned
            | OpCode::I64GeUnsigned
            | OpCode::F32Eq
            | OpCode::F32Ne
            | OpCode::F32Lt
            | OpCode::F32Gt
            | OpCode::F32Le
            | OpCode::F32Ge
            | OpCode::F64Eq
            | OpCode::F64Ne
            | OpCode::F64Lt
            | OpCode::F64Gt
            | OpCode::F64Le
            | OpCode::F64Ge
            | OpCode::I32Clz
            | OpCode::I32Ctz
            | OpCode::I32Popcnt
            | OpCode::I32Add
            | OpCode::I32Sub
            | OpCode::I32Mul
            | OpCode::I32DivSigned
            | OpCode::I32DivUnsigned
            | OpCode::I32RemSigned
            | OpCode::I32RemUnsigned
            | OpCode::I32And
            | OpCode::I32Or
            | OpCode::I32Xor
            | OpCode::I32Shl
            | OpCode::I32ShrSigned
            | OpCode::I32ShrUnsigned
            | OpCode::I32Rotl
            | OpCode::I32Rotr
            | OpCode::I64Clz
            | OpCode::I64Ctz
            | OpCode::I64Popcnt
            | OpCode::I64Add
            | OpCode::I64Sub
            | OpCode::I64Mul
            | OpCode::I64DivSigned
            | OpCode::I64DivUnsigned
            | OpCode::I64RemSigned
            | OpCode::I64RemUnsigned
            | OpCode::I64And
            | OpCode::I64Or
            | OpCode::I64Xor
            | OpCode::I64Shl
            | OpCode::I64ShrSigned
            | OpCode::I64ShrUnsigned
            | OpCode::I64Rotl
            | OpCode::I64Rotr
            | OpCode::F32Abs
            | OpCode::F32Neg
            | OpCode::F32Ceil
            | OpCode::F32Floor
            | OpCode::F32Trunc
            | OpCode::F32Nearest
            | OpCode::F32Sqrt
            | OpCode::F32Add
            | OpCode::F32Sub
            | OpCode::F32Mul
            | OpCode::F32Div
            | OpCode::F32Min
            | OpCode::F32Max
            | OpCode::F32Copysign
            | OpCode::F64Abs
            | OpCode::F64Neg
            | OpCode::F64Ceil
            | OpCode::F64Floor
            | OpCode::F64Trunc
            | OpCode::F64Nearest
            | OpCode::F64Sqrt
            | OpCode::F64Add
            | OpCode::F64Sub
            | OpCode::F64Mul
            | OpCode::F64Div
            | OpCode::F64Min
            | OpCode::F64Max
            | OpCode::F64Copysign
            | OpCode::I32WrapI64
            | OpCode::I32TruncF32Signed
            | OpCode::I32TruncF32Unsigned
            | OpCode::I32TruncF64Signed
            | OpCode::I32TruncF64Unsigned
            | OpCode::I64ExtendI32Signed
            | OpCode::I64ExtendI32Unsigned
            | OpCode::I64TruncF32Signed
            | OpCode::I64TruncF32Unsigned
            | OpCode::I64TruncF64Signed
            | OpCode::I64TruncF64Unsigned
            | OpCode::F32ConvertI32Signed
            | OpCode::F32ConvertI32Unsigned
            | OpCode::F32ConvertI64Signed
            | OpCode::F32ConvertI64Unsigned
            | OpCode::F32DemoteF64
            | OpCode::F64ConvertI32Signed
            | OpCode::F64ConvertI32Unsigned
            | OpCode::F64ConvertI64Signed
            | OpCode::F64ConvertI64Unsigned
            | OpCode::F64PromoteF32
            | OpCode::I32ReinterpretF32
            | OpCode::I64ReinterpretF64
            | OpCode::F32ReinterpretI32
            | OpCode::F64ReinterpretI64
            | OpCode::SignExtI32Extend8Signed
            | OpCode::SignExtI32Extend16Signed
            | OpCode::SignExtI64Extend8Signed
            | OpCode::SignExtI64Extend16Signed
            | OpCode::SignExtI64Extend32Signed
            | OpCode::SaturatingFloatToIntExtI32TruncSatF32Signed
            | OpCode::SaturatingFloatToIntExtI32TruncSatF32Unsigned
            | OpCode::SaturatingFloatToIntExtI32TruncSatF64Signed
            | OpCode::SaturatingFloatToIntExtI32TruncSatF64Unsigned
            | OpCode::SaturatingFloatToIntExtI64TruncSatF32Signed
            | OpCode::SaturatingFloatToIntExtI64TruncSatF32Unsigned
            | OpCode::SaturatingFloatToIntExtI64TruncSatF64Signed
            | OpCode::SaturatingFloatToIntExtI64TruncSatF64Unsigned
            | OpCode::ExceptionsExtThrowRef
            | OpCode::LegacyExceptionsExtCatchAll => {
                if operator.is_some() {
                    bail!("Operator is not allowed for this opcode");
                }
                hasher.update([0]);
            }
            OpCode::Block | OpCode::Loop | OpCode::If | OpCode::LegacyExceptionsExtTry => {
                some!(operator, BlockType(block_type) => {
                    match block_type.block_type {
                        Some(block_type) => block_type.sha3_hash(hasher)?,
                        _ => bail!("Block type is required"),
                    }
                }, "Block type is required")
            }
            OpCode::Br
            | OpCode::BrIf
            | OpCode::LegacyExceptionsExtRethrow
            | OpCode::LegacyExceptionsExtDelegate => {
                some!(operator, RelativeDepth(relative_depth) => {
                    relative_depth.sha3_hash(hasher)?;
                }, "Relative depth is required")
            }
            OpCode::BrTable => {
                some!(operator, Targets(targets) => {
                    targets.default.context("Default target is required")?.sha3_hash(hasher)?;
                    targets.targets.sha3_hash(hasher)?;
                }, "Type index is required")
            }
            OpCode::Call => {
                some!(operator, FunctionIndex(function_index) => {
                    function_index.sha3_hash(hasher)?;
                }, "Function index is required")
            }
            OpCode::CallIndirect => {
                some!(operator, CallIndirect(call_indirect) => {
                    call_indirect.type_index.context("Type index is required")?.sha3_hash(hasher)?;
                    call_indirect.table_index.context("Table index is required")?.sha3_hash(hasher)?;
                }, "Type index and table index are required")
            }
            OpCode::LocalGet | OpCode::LocalSet | OpCode::LocalTee => {
                some!(operator, LocalIndex(local_index) => {
                    local_index.sha3_hash(hasher)?;
                }, "Local index is required")
            }
            OpCode::GlobalGet | OpCode::GlobalSet => {
                some!(operator, GlobalIndex(global_index) => {
                    global_index.sha3_hash(hasher)?;
                }, "Global index is required")
            }
            OpCode::I32Load
            | OpCode::I64Load
            | OpCode::F32Load
            | OpCode::F64Load
            | OpCode::I32Load8Signed
            | OpCode::I32Load8Unsigned
            | OpCode::I32Load16Signed
            | OpCode::I32Load16Unsigned
            | OpCode::I64Load8Signed
            | OpCode::I64Load8Unsigned
            | OpCode::I64Load16Signed
            | OpCode::I64Load16Unsigned
            | OpCode::I64Load32Signed
            | OpCode::I64Load32Unsigned
            | OpCode::I32Store
            | OpCode::I64Store
            | OpCode::F32Store
            | OpCode::F64Store
            | OpCode::I32Store8
            | OpCode::I32Store16
            | OpCode::I64Store8
            | OpCode::I64Store16
            | OpCode::I64Store32 => {
                some!(operator, Memarg(memarg) => {
                    memarg.align.context("Align is required")?.sha3_hash(hasher)?;
                    memarg.max_align.context("Max align is required")?.sha3_hash(hasher)?;
                    memarg.offset.context("Offset is required")?.sha3_hash(hasher)?;
                    memarg.memory.context("Memory is required")?.sha3_hash(hasher)?;
                }, "Mem arg is required")
            }
            OpCode::MemorySize | OpCode::MemoryGrow => {
                some!(operator, Mem(mem) => {
                    mem.sha3_hash(hasher)?;
                }, "Mem is required")
            }
            OpCode::I32Constant => {
                some!(operator, I32Value(i32_value) => {
                    i32_value.sha3_hash(hasher)?;
                }, "I32 value is required")
            }
            OpCode::I64Constant => {
                some!(operator, I64Value(i64_value) => {
                    i64_value.sha3_hash(hasher)?;
                }, "I64 value is required")
            }
            OpCode::F32Constant => {
                some!(operator, F32Value(f32_value) => {
                    f32_value.sha3_hash(hasher)?;
                }, "F32 value is required")
            }
            OpCode::F64Constant => {
                some!(operator, F64Value(f64_value) => {
                    f64_value.sha3_hash(hasher)?;
                }, "F64 value is required")
            }
            OpCode::BulkMemoryExtMemoryInit => {
                some!(operator, MemoryInit(memory_init) => {
                    memory_init.data_index.context("Data index is required")?.sha3_hash(hasher)?;
                    memory_init.address.context("Address is required")?.sha3_hash(hasher)?;
                }, "Data index and address are required")
            }
            OpCode::BulkMemoryExtDataDrop => {
                some!(operator, DataIndex(data_index) => {
                    data_index.sha3_hash(hasher)?;
                }, "Data index is required")
            }
            OpCode::BulkMemoryExtMemoryCopy => {
                some!(operator, MemoryCopy(memory_copy) => {
                    memory_copy.destination_address.context("Destination address is required")?.sha3_hash(hasher)?;
                    memory_copy.source_address.context("Source address is required")?.sha3_hash(hasher)?;
                }, "Destination address and source address are required")
            }
            OpCode::BulkMemoryExtMemoryFill => {
                some!(operator, Mem(mem) => {
                    mem.sha3_hash(hasher)?;
                }, "Mem is required")
            }
            OpCode::BulkMemoryExtTableInit => {
                some!(operator, TableInit(table_init) => {
                    table_init.element_index.context("Element index is required")?.sha3_hash(hasher)?;
                    table_init.table.context("Table is required")?.sha3_hash(hasher)?;
                }, "Table index is required")
            }
            OpCode::BulkMemoryExtElemDrop => {
                some!(operator, ElementIndex(element_index) => {
                    element_index.sha3_hash(hasher)?;
                }, "Element index is required")
            }
            OpCode::BulkMemoryExtTableCopy => {
                some!(operator, TableCopy(table_copy) => {
                    table_copy.dst_table.context("Dst table is required")?.sha3_hash(hasher)?;
                    table_copy.src_table.context("Src table is required")?.sha3_hash(hasher)?;
                }, "Dst table and src table are required")
            }
            OpCode::ExceptionsExtTryTable => {
                some!(operator, TryTable(try_table) => {
                    try_table.r#type.context("Block type is required")?.block_type.context("Block type is required")?.sha3_hash(hasher)?;
                    try_table.catches.sha3_hash(hasher)?;
                }, "Type index and catches are required")
            }
            OpCode::ExceptionsExtThrow | OpCode::LegacyExceptionsExtCatch => {
                some!(operator, TagIndex(tag_index) => {
                    tag_index.sha3_hash(hasher)?;
                }, "Tag index is required")
            }
        };

        Ok(())
    }
}

impl Sha3Hash for Version {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.number
            .context("Version number is required")?
            .sha3_hash(hasher)?;
        self.encoding
            .context("Version encoding is required")?
            .sha3_hash(hasher)?;
        Ok(())
    }
}

impl Sha3Hash for FuncType {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.params.sha3_hash(hasher)?;
        self.results.sha3_hash(hasher)?;
        Ok(())
    }
}

impl Sha3Hash for SubType {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        match &self.kind {
            Some(wasm::sub_type::Kind::Func(func_type)) => func_type.sha3_hash(hasher)?,
            _ => bail!("Sub type kind is required"),
        }
        Ok(())
    }
}

impl Sha3Hash for TypeSection {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.types.sha3_hash(hasher)?;
        Ok(())
    }
}

impl Sha3Hash for TypeRefFunc {
    fn sha3_hash<D: Digest>(&self, _hasher: &mut D) -> Result<()> {
        // let module = self
        //     .module
        //     .as_ref()
        //     .context("Module is required")?;
        // let name = self
        //     .name
        //     .as_ref()
        //     .context("Name is required")?;
        // let function_type = self
        //     .function_type
        //     .context("Function type is required")?;
        //TODO
        Ok(())
    }
}

impl Sha3Hash for ImportSection {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.imports.sha3_hash(hasher)?;
        Ok(())
    }
}

impl Sha3Hash for ProgramModule {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.protocol_version
            .context("Protocol version is required")?
            .sha3_hash(hasher)?;
        self.version
            .context("Version is required")?
            .sha3_hash(hasher)?;

        // pub import_section: ::core::option::Option<ImportSection>,
        // #[prost(message, optional, tag = "5")]
        // pub function_section: ::core::option::Option<FunctionSection>,
        // #[prost(message, optional, tag = "6")]
        // pub table_section: ::core::option::Option<TableSection>,
        // #[prost(message, optional, tag = "7")]
        // pub memory_section: ::core::option::Option<MemorySection>,
        // #[prost(message, optional, tag = "8")]
        // pub tag_section: ::core::option::Option<TagSection>,
        // #[prost(message, optional, tag = "9")]
        // pub global_section: ::core::option::Option<GlobalSection>,
        // #[prost(message, optional, tag = "10")]
        // pub export_section: ::core::option::Option<ExportSection>,
        // #[prost(message, optional, tag = "11")]
        // pub element_section: ::core::option::Option<ElementSection>,
        // #[prost(message, optional, tag = "12")]
        // pub code_section: ::core::option::Option<CodeSection>,
        // #[prost(message, optional, tag = "13")]
        // pub data_section: ::core::option::Option<DataSection>,

        macro_rules! hash_section {
            ($opt:expr $(,)?) => {{
                match &$opt {
                    Some(v) => v.sha3_hash(hasher)?,
                    None => hasher.update([0]),
                }
            }};
        }

        hash_section!(self.type_section);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::libernet::wasm::operator::Operator as OperatorVariant;
    use crate::libernet::wasm::{
        BreakTargets, CallIndirectOp, CatchAllElements, CatchAllRef, CatchElement, CatchOne,
        CatchOneRef, MemArg, ValueType, block_type, catch_element,
    };
    use crate::libernet::wasm::{OpCode, Operator};

    fn sha512<I: IntoIterator<Item = T>, T: AsRef<[u8]>>(parts: I) -> String {
        let mut hasher = sha3::Sha3_512::new();
        for p in parts {
            hasher.update(p.as_ref());
        }
        hex::encode(hasher.finalize())
    }

    fn hash<I: IntoIterator<Item = T>, T: Sha3Hash>(parts: I) -> String {
        let mut hasher = sha3::Sha3_512::new();
        for p in parts {
            p.sha3_hash(&mut hasher).unwrap();
        }
        hex::encode(hasher.finalize())
    }

    macro_rules! hash_eq {
        ($left:expr, $right:expr) => {
            assert_eq!(hash($left), sha512($right));
        };
    }

    macro_rules! hash_err {
        ($left:expr) => {
            let mut hasher = sha3::Sha3_512::new();
            assert!($left.sha3_hash(&mut hasher).is_err());
        };
    }

    #[test]
    fn test_some_macro_success() {
        let result: Result<u32, _> = (|| {
            let opt: Option<u32> = Some(42);
            let x = some!(opt, x => { Ok(x) }, "expected some");
            x
        })();
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_some_macro_failure() {
        let result: Result<u32, _> = (|| {
            let opt: Option<u32> = None;
            some!(opt, x => { Ok(x) }, "expected some")
        })();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "expected some");
    }

    #[test]
    fn test_u32_to_hash() {
        hash_eq!([42u32], [42u32.to_le_bytes()]);
    }

    #[test]
    fn test_u64_to_hash() {
        hash_eq!([42u64], [42u64.to_le_bytes()]);
    }

    #[test]
    fn test_i32_to_hash() {
        hash_eq!([42i32], [42i32.to_le_bytes()]);
    }

    #[test]
    fn test_i64_to_hash() {
        hash_eq!([42i64], [42i64.to_le_bytes()]);
    }

    #[test]
    fn test_vec_to_hash() {
        hash_eq!([Vec::<u32>::new()], [0u64.to_le_bytes()]);
        hash_eq!(
            [vec![1u32, 2u32]],
            [
                &2u64.to_le_bytes()[..],
                &1u32.to_le_bytes()[..],
                &2u32.to_le_bytes()[..]
            ]
        );
    }

    #[test]
    fn test_value_type_i32_to_hash() {
        hash_eq!(
            [ValueType {
                value_type: Some(PlainType::ValueTypeI32 as i32),
                reference_type: None,
            }],
            [&(PlainType::ValueTypeI32 as i32).to_le_bytes()[..], &[0]]
        );
    }

    #[test]
    fn test_value_type_missing_value_type_fails() {
        let vt = ValueType {
            value_type: None,
            reference_type: None,
        };
        hash_err!(vt);
    }

    #[test]
    fn test_value_type_ref_type_with_primitive_fails() {
        let vt = ValueType {
            value_type: Some(PlainType::ValueTypeI32 as i32),
            reference_type: Some(RefType::RefFunc as i32),
        };
        hash_err!(vt);
    }

    #[test]
    fn test_catch_element_one_to_hash() {
        let ce = CatchElement {
            catch_element: Some(catch_element::CatchElement::One(CatchOne {
                tag: Some(1),
                label: Some(2),
            })),
        };
        hash_eq!(
            [ce],
            [&[0], &1u32.to_le_bytes()[..], &2u32.to_le_bytes()[..]]
        );
    }

    #[test]
    fn test_catch_element_one_ref_to_hash() {
        let ce = CatchElement {
            catch_element: Some(catch_element::CatchElement::OneRef(CatchOneRef {
                tag: Some(1),
                label: Some(2),
            })),
        };
        hash_eq!(
            [ce],
            [&[1], &1u32.to_le_bytes()[..], &2u32.to_le_bytes()[..]]
        );
    }

    #[test]
    fn test_catch_element_all_to_hash() {
        let ce = CatchElement {
            catch_element: Some(catch_element::CatchElement::All(CatchAllElements {
                label: Some(5),
            })),
        };
        hash_eq!([ce], [&[2], &5u32.to_le_bytes()[..]]);
    }

    #[test]
    fn test_catch_element_all_ref_to_hash() {
        let ce = CatchElement {
            catch_element: Some(catch_element::CatchElement::AllRef(CatchAllRef {
                label: Some(5),
            })),
        };
        hash_eq!([ce], [&[3], &5u32.to_le_bytes()[..]]);
    }

    #[test]
    fn test_catch_element_missing_fails() {
        let ce = CatchElement {
            catch_element: None,
        };
        hash_err!(ce);
    }

    #[test]
    fn test_operator_nop_to_hash() {
        let op = Operator {
            opcode: Some(OpCode::Nop as i32),
            operator: None,
        };
        hash_eq!([op], [&(OpCode::Nop as i32).to_le_bytes()[..], &[0]]);
    }

    #[test]
    fn test_operator_nop_with_operator_fails() {
        let op = Operator {
            opcode: Some(OpCode::Nop as i32),
            operator: Some(OperatorVariant::LocalIndex(0)),
        };
        hash_err!(op);
    }

    #[test]
    fn test_operator_call_to_hash() {
        let op = Operator {
            opcode: Some(OpCode::Call as i32),
            operator: Some(OperatorVariant::FunctionIndex(42)),
        };
        hash_eq!(
            [op],
            [
                &(OpCode::Call as i32).to_le_bytes()[..],
                &42u32.to_le_bytes()[..]
            ]
        );
    }

    #[test]
    fn test_operator_call_missing_function_index_fails() {
        let op = Operator {
            opcode: Some(OpCode::Call as i32),
            operator: None,
        };
        hash_err!(op);
    }

    #[test]
    fn test_operator_i32_constant_to_hash() {
        let op = Operator {
            opcode: Some(OpCode::I32Constant as i32),
            operator: Some(OperatorVariant::I32Value(100)),
        };
        hash_eq!(
            [op],
            [
                &(OpCode::I32Constant as i32).to_le_bytes()[..],
                &100u32.to_le_bytes()[..]
            ]
        );
    }

    #[test]
    fn test_operator_block_empty_to_hash() {
        let op = Operator {
            opcode: Some(OpCode::Block as i32),
            operator: Some(OperatorVariant::BlockType(wasm::BlockType {
                block_type: Some(block_type::BlockType::Empty(110)),
            })),
        };
        hash_eq!([op], [&(OpCode::Block as i32).to_le_bytes()[..], &[0]]);
    }

    #[test]
    fn test_operator_block_value_type_to_hash() {
        let value_type = ValueType {
            value_type: Some(PlainType::ValueTypeI32 as i32),
            reference_type: None,
        };
        let op = Operator {
            opcode: Some(OpCode::Block as i32),
            operator: Some(OperatorVariant::BlockType(wasm::BlockType {
                block_type: Some(block_type::BlockType::ValueType(value_type)),
            })),
        };
        hash_eq!(
            [op],
            [
                &(OpCode::Block as i32).to_le_bytes()[..],
                &(PlainType::ValueTypeI32 as i32).to_le_bytes()[..],
                &[0]
            ]
        );
    }

    #[test]
    fn test_operator_block_function_type_to_hash() {
        let op = Operator {
            opcode: Some(OpCode::Block as i32),
            operator: Some(OperatorVariant::BlockType(wasm::BlockType {
                block_type: Some(block_type::BlockType::TypeIndex(110)),
            })),
        };
        hash_eq!(
            [op],
            [
                &(OpCode::Block as i32).to_le_bytes()[..],
                &110u32.to_le_bytes()[..]
            ]
        );
    }

    #[test]
    fn test_operator_local_get_to_hash() {
        let op = Operator {
            opcode: Some(OpCode::LocalGet as i32),
            operator: Some(OperatorVariant::LocalIndex(3)),
        };
        hash_eq!(
            [op],
            [
                &(OpCode::LocalGet as i32).to_le_bytes()[..],
                &3u32.to_le_bytes()[..]
            ]
        );
    }

    #[test]
    fn test_operator_memarg_to_hash() {
        let op = Operator {
            opcode: Some(OpCode::I32Load as i32),
            operator: Some(OperatorVariant::Memarg(MemArg {
                align: Some(1),
                max_align: Some(2),
                offset: Some(3),
                memory: Some(4),
            })),
        };
        hash_eq!(
            [op],
            [
                &(OpCode::I32Load as i32).to_le_bytes()[..],
                &1u32.to_le_bytes()[..],
                &2u32.to_le_bytes()[..],
                &3u64.to_le_bytes()[..],
                &4u32.to_le_bytes()[..]
            ]
        );
    }

    #[test]
    fn test_operator_br_table_to_hash() {
        let op = Operator {
            opcode: Some(OpCode::BrTable as i32),
            operator: Some(OperatorVariant::Targets(BreakTargets {
                default: Some(5),
                targets: vec![1, 2, 3],
            })),
        };
        hash_eq!(
            [op],
            [
                &(OpCode::BrTable as i32).to_le_bytes()[..],
                &5u32.to_le_bytes()[..],
                &3u64.to_le_bytes()[..],
                &1u32.to_le_bytes()[..],
                &2u32.to_le_bytes()[..],
                &3u32.to_le_bytes()[..]
            ]
        );
    }

    #[test]
    fn test_operator_call_indirect_to_hash() {
        let op = Operator {
            opcode: Some(OpCode::CallIndirect as i32),
            operator: Some(OperatorVariant::CallIndirect(CallIndirectOp {
                type_index: Some(1),
                table_index: Some(2),
            })),
        };
        hash_eq!(
            [op],
            [
                &(OpCode::CallIndirect as i32).to_le_bytes()[..],
                &1u32.to_le_bytes()[..],
                &2u32.to_le_bytes()[..]
            ]
        );
    }

    #[test]
    fn test_operator_hash_deterministic() {
        let op = Operator {
            opcode: Some(OpCode::Nop as i32),
            operator: None,
        };
        let mut hasher1 = sha3::Sha3_512::new();
        let mut hasher2 = sha3::Sha3_512::new();
        op.sha3_hash(&mut hasher1).unwrap();
        op.sha3_hash(&mut hasher2).unwrap();
        assert_eq!(hasher1.finalize(), hasher2.finalize());
    }

    #[test]
    fn test_operator_hash_different_operators_different_scalars() {
        let mut hasher1 = sha3::Sha3_512::new();
        let mut hasher2 = sha3::Sha3_512::new();
        let nop = Operator {
            opcode: Some(OpCode::Nop as i32),
            operator: None,
        };
        let ret = Operator {
            opcode: Some(OpCode::Return as i32),
            operator: None,
        };
        nop.sha3_hash(&mut hasher1).unwrap();
        ret.sha3_hash(&mut hasher2).unwrap();
        assert_ne!(hasher1.finalize(), hasher2.finalize());
    }

    #[test]
    fn test_operator_same_op_same_hash() {
        let mut hasher1 = sha3::Sha3_512::new();
        let mut hasher2 = sha3::Sha3_512::new();
        let op1 = Operator {
            opcode: Some(OpCode::I32Constant as i32),
            operator: Some(OperatorVariant::I32Value(42)),
        };
        let op2 = Operator {
            opcode: Some(OpCode::I32Constant as i32),
            operator: Some(OperatorVariant::I32Value(42)),
        };
        op1.sha3_hash(&mut hasher1).unwrap();
        op2.sha3_hash(&mut hasher2).unwrap();
        assert_eq!(hasher1.finalize(), hasher2.finalize());
    }
}
