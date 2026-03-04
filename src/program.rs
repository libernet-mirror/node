use crate::libernet::wasm::{
    CatchElement, CodeSection, CodeSectionEntry, Data, DataKind, DataSection, Element,
    ElementExpressions, ElementFunctions, ElementKind, ElementSection, Export, ExportSection,
    Expression, FuncType, FunctionSection, Global, GlobalSection, GlobalType, ImportSection,
    Locals, MemorySection, MemoryType, OpCode, Operator, PlainType, ProgramModule, RefType,
    SubType, TableSection, TableType, TagSection, TagType, TypeRefFunc, TypeSection, ValueType,
    Version, block_type, catch_element, element::Items, operator::Operator::*, sub_type,
};
use anyhow::{Context, Result, bail};
use sha3::Digest;

const OPTION_TAG: [u8; 1] = [1];
const BLOCK_TYPE_EMPTY_TAG: [u8; 1] = [2];
const BLOCK_TYPE_VALUE_TYPE_TAG: [u8; 1] = [3];
const BLOCK_TYPE_TYPE_INDEX_TAG: [u8; 1] = [4];
const CATCH_ELEMENT_ONE_TAG: [u8; 1] = [5];
const CATCH_ELEMENT_ONE_REF_TAG: [u8; 1] = [6];
const CATCH_ELEMENT_ALL_TAG: [u8; 1] = [7];
const CATCH_ELEMENT_ALL_REF_TAG: [u8; 1] = [8];

macro_rules! some {
    ($expr:expr, $pat:pat => $body:block, $msg:expr $(,)?) => {{
        match $expr {
            Some($pat) => $body,
            _ => anyhow::bail!($msg),
        }
    }};
}

pub trait Sha3Hash {
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

impl Sha3Hash for String {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        (self.len() as u64).sha3_hash(hasher)?;
        hasher.update(self.as_bytes());
        Ok(())
    }
}

impl Sha3Hash for bool {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        hasher.update([if *self { 1 } else { 0 }]);
        Ok(())
    }
}

impl Sha3Hash for Vec<u8> {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        (self.len() as u64).sha3_hash(hasher)?;
        hasher.update(self);
        Ok(())
    }
}

impl<T: Sha3Hash> Sha3Hash for Option<T> {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        match self {
            Some(v) => {
                hasher.update(OPTION_TAG);
                v.sha3_hash(hasher)?;
            }
            None => hasher.update([0]),
        }
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

impl Sha3Hash for ValueType {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        let value_code = self.value_type.context("Value type is required")?;
        value_code.sha3_hash(hasher)?;
        match PlainType::try_from(value_code)? {
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

impl Sha3Hash for block_type::BlockType {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        match self {
            block_type::BlockType::Empty(_) => hasher.update(BLOCK_TYPE_EMPTY_TAG),
            block_type::BlockType::ValueType(vt) => {
                hasher.update(BLOCK_TYPE_VALUE_TYPE_TAG);
                vt.sha3_hash(hasher)?;
            }
            block_type::BlockType::TypeIndex(v) => {
                hasher.update(BLOCK_TYPE_TYPE_INDEX_TAG);
                v.sha3_hash(hasher)?;
            }
        };
        Ok(())
    }
}

impl Sha3Hash for CatchElement {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        let catch_element = self.catch_element.context("Catch element is required")?;
        match catch_element {
            catch_element::CatchElement::One(one) => {
                hasher.update(CATCH_ELEMENT_ONE_TAG);
                one.tag.context("One: Tag is required")?.sha3_hash(hasher)?;
                one.label
                    .context("One: Label is required")?
                    .sha3_hash(hasher)?;
            }
            catch_element::CatchElement::OneRef(one_ref) => {
                hasher.update(CATCH_ELEMENT_ONE_REF_TAG);
                one_ref
                    .tag
                    .context("OneRef: Tag is required")?
                    .sha3_hash(hasher)?;
                one_ref
                    .label
                    .context("OneRef: Label is required")?
                    .sha3_hash(hasher)?;
            }
            catch_element::CatchElement::All(all) => {
                hasher.update(CATCH_ELEMENT_ALL_TAG);
                all.label
                    .context("All: Label is required")?
                    .sha3_hash(hasher)?;
            }
            catch_element::CatchElement::AllRef(all_ref) => {
                hasher.update(CATCH_ELEMENT_ALL_REF_TAG);
                all_ref
                    .label
                    .context("AllRef: Label is required")?
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
            Some(sub_type::Kind::Func(func_type)) => {
                hasher.update([1]);
                func_type.sha3_hash(hasher)?;
            }
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
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.module
            .as_ref()
            .context("Module is required")?
            .sha3_hash(hasher)?;
        self.name
            .as_ref()
            .context("Name is required")?
            .sha3_hash(hasher)?;
        self.function_type
            .context("Function type is required")?
            .sha3_hash(hasher)?;
        Ok(())
    }
}

impl Sha3Hash for ImportSection {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.imports.sha3_hash(hasher)?;
        Ok(())
    }
}

impl Sha3Hash for FunctionSection {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.type_idxs.sha3_hash(hasher)?;
        Ok(())
    }
}

impl Sha3Hash for TableSection {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.types.sha3_hash(hasher)?;
        Ok(())
    }
}

impl Sha3Hash for TableType {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.reference_type
            .context("Reference type is required")?
            .sha3_hash(hasher)?;
        self.table64
            .context("Table64 is required")?
            .sha3_hash(hasher)?;
        self.initial
            .context("Initial is required")?
            .sha3_hash(hasher)?;
        self.maximum.sha3_hash(hasher)?;
        self.shared
            .context("Shared is required")?
            .sha3_hash(hasher)?;
        Ok(())
    }
}

impl Sha3Hash for MemorySection {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.memory_types.sha3_hash(hasher)?;
        Ok(())
    }
}

impl Sha3Hash for MemoryType {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.memory64
            .context("Memory64 is required")?
            .sha3_hash(hasher)?;
        self.shared
            .context("Shared is required")?
            .sha3_hash(hasher)?;
        self.initial
            .context("Initial is required")?
            .sha3_hash(hasher)?;
        self.maximum.sha3_hash(hasher)?;
        self.page_size_log2.sha3_hash(hasher)?;
        Ok(())
    }
}

impl Sha3Hash for TagSection {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.tags.sha3_hash(hasher)?;
        Ok(())
    }
}

impl Sha3Hash for TagType {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.kind.sha3_hash(hasher)?;
        self.function_type_idx.sha3_hash(hasher)?;
        Ok(())
    }
}

impl Sha3Hash for GlobalSection {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.globals.sha3_hash(hasher)?;
        Ok(())
    }
}

impl Sha3Hash for Global {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.r#type.context("Type is required")?.sha3_hash(hasher)?;
        self.init_expr.sha3_hash(hasher)?;
        Ok(())
    }
}

impl Sha3Hash for Expression {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.operators.sha3_hash(hasher)?;
        Ok(())
    }
}

impl Sha3Hash for GlobalType {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.content_type
            .context("Content type is required")?
            .sha3_hash(hasher)?;
        self.mutable
            .context("Mutable is required")?
            .sha3_hash(hasher)?;
        self.shared
            .context("Shared is required")?
            .sha3_hash(hasher)?;
        Ok(())
    }
}

impl Sha3Hash for ExportSection {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.exports.sha3_hash(hasher)?;
        Ok(())
    }
}

impl Sha3Hash for Export {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.name
            .as_ref()
            .context("Name is required")?
            .sha3_hash(hasher)?;
        self.kind.context("Kind is required")?.sha3_hash(hasher)?;
        self.index.context("Index is required")?.sha3_hash(hasher)?;
        Ok(())
    }
}

impl Sha3Hash for ElementSection {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.elements.sha3_hash(hasher)?;
        Ok(())
    }
}
impl Sha3Hash for Element {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.kind
            .as_ref()
            .context("Kind is required")?
            .sha3_hash(hasher)?;
        self.items.sha3_hash(hasher)?;
        Ok(())
    }
}

impl Sha3Hash for ElementKind {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.r#type.context("Type is required")?.sha3_hash(hasher)?;
        self.table_index.sha3_hash(hasher)?;
        self.expression.sha3_hash(hasher)?;
        Ok(())
    }
}

impl Sha3Hash for Items {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        match self {
            Items::Functions(functions) => functions.sha3_hash(hasher)?,
            Items::Expressions(expressions) => expressions.sha3_hash(hasher)?,
        }
        Ok(())
    }
}

impl Sha3Hash for ElementFunctions {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.functions.sha3_hash(hasher)?;
        Ok(())
    }
}

impl Sha3Hash for ElementExpressions {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.reference_type
            .context("Reference type is required")?
            .sha3_hash(hasher)?;
        self.expressions.sha3_hash(hasher)?;
        Ok(())
    }
}

impl Sha3Hash for CodeSection {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.code_section_entry.sha3_hash(hasher)?;
        Ok(())
    }
}

impl Sha3Hash for CodeSectionEntry {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.locals.sha3_hash(hasher)?;
        self.body.sha3_hash(hasher)?;
        Ok(())
    }
}

impl Sha3Hash for Locals {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.count.context("Count is required")?.sha3_hash(hasher)?;
        self.value_type
            .context("Value type is required")?
            .sha3_hash(hasher)?;
        Ok(())
    }
}

impl Sha3Hash for DataSection {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.datas.sha3_hash(hasher)?;
        Ok(())
    }
}

impl Sha3Hash for Data {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.kind
            .as_ref()
            .context("Kind is required")?
            .sha3_hash(hasher)?;
        self.data
            .as_ref()
            .context("Data is required")?
            .sha3_hash(hasher)?;
        Ok(())
    }
}

impl Sha3Hash for DataKind {
    fn sha3_hash<D: Digest>(&self, hasher: &mut D) -> Result<()> {
        self.r#type
            .as_ref()
            .context("Type is required")?
            .sha3_hash(hasher)?;
        self.memory_index.sha3_hash(hasher)?;
        self.expression.sha3_hash(hasher)?;
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

        macro_rules! hash_section {
            ($opt:expr $(,)?) => {{
                match &$opt {
                    Some(v) => v.sha3_hash(hasher)?,
                    None => hasher.update([0]),
                }
            }};
        }

        hash_section!(self.type_section);
        hash_section!(self.import_section);
        hash_section!(self.function_section);
        hash_section!(self.table_section);
        hash_section!(self.memory_section);
        hash_section!(self.tag_section);
        hash_section!(self.global_section);
        hash_section!(self.export_section);
        hash_section!(self.element_section);
        hash_section!(self.code_section);
        hash_section!(self.data_section);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use primitive_types::H512;

    use super::*;
    use crate::libernet::wasm::{
        BlockType, BreakTargets, CallIndirectOp, CatchAllElements, CatchAllRef, CatchOne,
        CatchOneRef, DataKindType, ElementKindType, Encoding, ExternalKind, MemArg, TagKind,
        operator::Operator as OperatorVariant,
    };

    fn sha3_512<I: IntoIterator<Item = T>, T: AsRef<[u8]>>(parts: I) -> H512 {
        let mut hasher = sha3::Sha3_512::new();
        for p in parts {
            hasher.update(p.as_ref());
        }
        H512::from_slice(hasher.finalize().as_slice())
    }

    fn hash<I: IntoIterator<Item = T>, T: Sha3Hash>(parts: I) -> H512 {
        let mut hasher = sha3::Sha3_512::new();
        for p in parts {
            p.sha3_hash(&mut hasher).unwrap();
        }
        H512::from_slice(hasher.finalize().as_slice())
    }

    macro_rules! hash_eq {
        ($left:expr, $right:expr) => {
            assert_eq!(hash($left), sha3_512($right));
        };
    }

    macro_rules! hash_err {
        ($left:expr) => {
            let mut hasher = sha3::Sha3_512::new();
            assert!($left.sha3_hash(&mut hasher).is_err());
        };
    }

    fn i32_vt() -> ValueType {
        ValueType {
            value_type: Some(PlainType::ValueTypeI32 as i32),
            reference_type: None,
        }
    }

    fn empty_expr() -> Expression {
        Expression { operators: vec![] }
    }

    fn default_version() -> Version {
        Version {
            number: Some(1),
            encoding: Some(Encoding::Module as i32),
        }
    }

    fn default_pm() -> ProgramModule {
        ProgramModule {
            protocol_version: Some(1),
            version: Some(default_version()),
            type_section: None,
            import_section: None,
            function_section: None,
            table_section: None,
            memory_section: None,
            tag_section: None,
            global_section: None,
            export_section: None,
            element_section: None,
            code_section: None,
            data_section: None,
        }
    }

    // --- some! macro ---

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

    // --- primitives ---

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
    fn test_bool_to_hash() {
        hash_eq!([true], [&[1]]);
        hash_eq!([false], [&[0]]);
    }

    #[test]
    fn test_option_to_hash() {
        hash_eq!([Some(42u32)], [&OPTION_TAG, &42u32.to_le_bytes()[..]]);
        hash_eq!([None::<u32>], [&[0]]);
    }

    #[test]
    fn test_string_to_hash() {
        hash_eq!(
            ["hello".to_string()],
            [&("hello".len() as u64).to_le_bytes()[..], &b"hello"[..]]
        );
    }

    #[test]
    fn test_bytes_to_hash() {
        hash_eq!(
            [b"hello".to_vec()],
            [&("hello".len() as u64).to_le_bytes()[..], &b"hello"[..]]
        );
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

    // --- ValueType ---

    #[test]
    fn test_value_type_i32_to_hash() {
        hash_eq!(
            [i32_vt()],
            [&(PlainType::ValueTypeI32 as i32).to_le_bytes()[..], &[0]]
        );
    }

    #[test]
    fn test_value_type_ref_to_hash() {
        hash_eq!(
            [ValueType {
                value_type: Some(PlainType::ValueTypeRef as i32),
                reference_type: Some(RefType::RefFunc as i32),
            }],
            [
                &(PlainType::ValueTypeRef as i32).to_le_bytes()[..],
                &(RefType::RefFunc as i32).to_le_bytes()[..]
            ]
        );
    }

    #[test]
    fn test_value_type_missing_value_type_fails() {
        hash_err!(ValueType {
            value_type: None,
            reference_type: None,
        });
    }

    #[test]
    fn test_value_type_ref_type_with_primitive_fails() {
        hash_err!(ValueType {
            value_type: Some(PlainType::ValueTypeI32 as i32),
            reference_type: Some(RefType::RefFunc as i32),
        });
    }

    #[test]
    fn test_value_type_ref_missing_reference_type_fails() {
        hash_err!(ValueType {
            value_type: Some(PlainType::ValueTypeRef as i32),
            reference_type: None,
        });
    }

    // --- CatchElement ---

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
            [
                &CATCH_ELEMENT_ONE_TAG,
                &1u32.to_le_bytes()[..],
                &2u32.to_le_bytes()[..]
            ]
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
            [
                &CATCH_ELEMENT_ONE_REF_TAG,
                &1u32.to_le_bytes()[..],
                &2u32.to_le_bytes()[..]
            ]
        );
    }

    #[test]
    fn test_catch_element_all_to_hash() {
        let ce = CatchElement {
            catch_element: Some(catch_element::CatchElement::All(CatchAllElements {
                label: Some(5),
            })),
        };
        hash_eq!([ce], [&CATCH_ELEMENT_ALL_TAG, &5u32.to_le_bytes()[..]]);
    }

    #[test]
    fn test_catch_element_all_ref_to_hash() {
        let ce = CatchElement {
            catch_element: Some(catch_element::CatchElement::AllRef(CatchAllRef {
                label: Some(5),
            })),
        };
        hash_eq!([ce], [&CATCH_ELEMENT_ALL_REF_TAG, &5u32.to_le_bytes()[..]]);
    }

    #[test]
    fn test_catch_element_missing_fails() {
        hash_err!(CatchElement {
            catch_element: None,
        });
    }

    // --- Operator ---

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
        hash_err!(Operator {
            opcode: Some(OpCode::Nop as i32),
            operator: Some(OperatorVariant::LocalIndex(0)),
        });
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
        hash_err!(Operator {
            opcode: Some(OpCode::Call as i32),
            operator: None,
        });
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
            operator: Some(OperatorVariant::BlockType(BlockType {
                block_type: Some(block_type::BlockType::Empty(110)),
            })),
        };
        hash_eq!(
            [op],
            [
                &(OpCode::Block as i32).to_le_bytes()[..],
                &BLOCK_TYPE_EMPTY_TAG
            ]
        );
    }

    #[test]
    fn test_operator_block_value_type_to_hash() {
        let op = Operator {
            opcode: Some(OpCode::Block as i32),
            operator: Some(OperatorVariant::BlockType(BlockType {
                block_type: Some(block_type::BlockType::ValueType(i32_vt())),
            })),
        };
        hash_eq!(
            [op],
            [
                &(OpCode::Block as i32).to_le_bytes()[..],
                &BLOCK_TYPE_VALUE_TYPE_TAG,
                &(PlainType::ValueTypeI32 as i32).to_le_bytes()[..],
                &[0]
            ]
        );
    }

    #[test]
    fn test_operator_block_function_type_to_hash() {
        let op = Operator {
            opcode: Some(OpCode::Block as i32),
            operator: Some(OperatorVariant::BlockType(BlockType {
                block_type: Some(block_type::BlockType::TypeIndex(110)),
            })),
        };
        hash_eq!(
            [op],
            [
                &(OpCode::Block as i32).to_le_bytes()[..],
                &BLOCK_TYPE_TYPE_INDEX_TAG,
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

    // --- Version ---

    #[test]
    fn test_version_to_hash() {
        hash_eq!(
            [default_version()],
            [
                &1u32.to_le_bytes()[..],
                &(Encoding::Module as i32).to_le_bytes()[..]
            ]
        );
    }

    #[test]
    fn test_version_missing_number_fails() {
        hash_err!(Version {
            number: None,
            encoding: Some(Encoding::Module as i32),
        });
    }

    #[test]
    fn test_version_missing_encoding_fails() {
        hash_err!(Version {
            number: Some(1),
            encoding: None,
        });
    }

    // --- FuncType ---

    #[test]
    fn test_func_type_with_params_and_results_to_hash() {
        let ft = FuncType {
            params: vec![i32_vt()],
            results: vec![i32_vt()],
        };
        hash_eq!(
            [ft],
            [
                &1u64.to_le_bytes()[..],
                &(PlainType::ValueTypeI32 as i32).to_le_bytes()[..],
                &[0],
                &1u64.to_le_bytes()[..],
                &(PlainType::ValueTypeI32 as i32).to_le_bytes()[..],
                &[0]
            ]
        );
    }

    // --- SubType ---

    #[test]
    fn test_sub_type_func_to_hash() {
        let st = SubType {
            kind: Some(sub_type::Kind::Func(FuncType {
                params: vec![],
                results: vec![],
            })),
        };
        hash_eq!(
            [st],
            [&[1], &0u64.to_le_bytes()[..], &0u64.to_le_bytes()[..]]
        );
    }

    #[test]
    fn test_sub_type_missing_kind_fails() {
        hash_err!(SubType { kind: None });
    }

    // --- TypeRefFunc ---

    #[test]
    fn test_type_ref_func_to_hash() {
        let trf = TypeRefFunc {
            module: Some("env".to_string()),
            name: Some("foo".to_string()),
            function_type: Some(42),
        };
        hash_eq!(
            [trf],
            [
                &3u64.to_le_bytes()[..],
                b"env",
                &3u64.to_le_bytes()[..],
                b"foo",
                &42u32.to_le_bytes()[..]
            ]
        );
    }

    #[test]
    fn test_type_ref_func_missing_module_fails() {
        hash_err!(TypeRefFunc {
            module: None,
            name: Some("foo".to_string()),
            function_type: Some(42),
        });
    }

    #[test]
    fn test_type_ref_func_missing_name_fails() {
        hash_err!(TypeRefFunc {
            module: Some("env".to_string()),
            name: None,
            function_type: Some(42),
        });
    }

    #[test]
    fn test_type_ref_func_missing_function_type_fails() {
        hash_err!(TypeRefFunc {
            module: Some("env".to_string()),
            name: Some("foo".to_string()),
            function_type: None,
        });
    }

    // --- Sections (empty) ---

    #[test]
    fn test_empty_sections_to_hash() {
        let empty_vec_hash = sha3_512([0u64.to_le_bytes()]);
        assert_eq!(hash([TypeSection { types: vec![] }]), empty_vec_hash);
        assert_eq!(hash([ImportSection { imports: vec![] }]), empty_vec_hash);
        assert_eq!(
            hash([FunctionSection { type_idxs: vec![] }]),
            empty_vec_hash
        );
        assert_eq!(hash([TableSection { types: vec![] }]), empty_vec_hash);
        assert_eq!(
            hash([MemorySection {
                memory_types: vec![]
            }]),
            empty_vec_hash
        );
        assert_eq!(hash([TagSection { tags: vec![] }]), empty_vec_hash);
        assert_eq!(hash([GlobalSection { globals: vec![] }]), empty_vec_hash);
        assert_eq!(hash([ExportSection { exports: vec![] }]), empty_vec_hash);
        assert_eq!(hash([ElementSection { elements: vec![] }]), empty_vec_hash);
        assert_eq!(
            hash([CodeSection {
                code_section_entry: vec![]
            }]),
            empty_vec_hash
        );
        assert_eq!(hash([DataSection { datas: vec![] }]), empty_vec_hash);
    }

    // --- TypeSection (non-empty) ---

    #[test]
    fn test_type_section_with_types_to_hash() {
        let st = SubType {
            kind: Some(sub_type::Kind::Func(FuncType {
                params: vec![],
                results: vec![],
            })),
        };
        let ts = TypeSection { types: vec![st] };
        hash_eq!(
            [ts],
            [
                &1u64.to_le_bytes()[..],
                &[1],
                &0u64.to_le_bytes()[..],
                &0u64.to_le_bytes()[..]
            ]
        );
    }

    // --- FunctionSection (non-empty) ---

    #[test]
    fn test_function_section_to_hash() {
        let fs = FunctionSection {
            type_idxs: vec![0, 1],
        };
        hash_eq!(
            [fs],
            [
                &2u64.to_le_bytes()[..],
                &0u32.to_le_bytes()[..],
                &1u32.to_le_bytes()[..]
            ]
        );
    }

    // --- TableType ---

    #[test]
    fn test_table_type_to_hash() {
        let table = TableType {
            reference_type: Some(RefType::RefFunc as i32),
            table64: Some(true),
            initial: Some(100),
            maximum: Some(200),
            shared: Some(false),
        };
        hash_eq!(
            [table],
            [
                &(RefType::RefFunc as i32).to_le_bytes()[..],
                &[1],
                &100u64.to_le_bytes()[..],
                &OPTION_TAG,
                &200u64.to_le_bytes()[..],
                &[0]
            ]
        );
    }

    // --- MemoryType ---

    #[test]
    fn test_memory_type_to_hash() {
        let memory = MemoryType {
            memory64: Some(true),
            shared: Some(false),
            initial: Some(1),
            maximum: Some(256),
            page_size_log2: Some(16),
        };
        hash_eq!(
            [memory],
            [
                &[1],
                &[0],
                &1u64.to_le_bytes()[..],
                &OPTION_TAG,
                &256u64.to_le_bytes()[..],
                &OPTION_TAG,
                &16u32.to_le_bytes()[..]
            ]
        );
    }

    // --- TagType ---

    #[test]
    fn test_tag_type_to_hash() {
        let tag = TagType {
            kind: Some(TagKind::Exception as i32),
            function_type_idx: Some(42),
        };
        hash_eq!(
            [tag],
            [
                &OPTION_TAG,
                &(TagKind::Exception as i32).to_le_bytes()[..],
                &OPTION_TAG,
                &42u32.to_le_bytes()[..]
            ]
        );
    }

    // --- GlobalType ---

    #[test]
    fn test_global_type_to_hash() {
        let gt = GlobalType {
            content_type: Some(i32_vt()),
            mutable: Some(true),
            shared: Some(false),
        };
        hash_eq!(
            [gt],
            [
                &(PlainType::ValueTypeI32 as i32).to_le_bytes()[..],
                &[0],
                &[1],
                &[0]
            ]
        );
    }

    #[test]
    fn test_global_type_missing_content_type_fails() {
        hash_err!(GlobalType {
            content_type: None,
            mutable: Some(true),
            shared: Some(false),
        });
    }

    #[test]
    fn test_global_type_missing_mutable_fails() {
        hash_err!(GlobalType {
            content_type: Some(i32_vt()),
            mutable: None,
            shared: Some(false),
        });
    }

    #[test]
    fn test_global_type_missing_shared_fails() {
        hash_err!(GlobalType {
            content_type: Some(i32_vt()),
            mutable: Some(true),
            shared: None,
        });
    }

    // --- Expression ---

    #[test]
    fn test_expression_with_operators_to_hash() {
        let nop = Operator {
            opcode: Some(OpCode::Nop as i32),
            operator: None,
        };
        let expr = Expression {
            operators: vec![nop],
        };
        hash_eq!(
            [expr],
            [
                &1u64.to_le_bytes()[..],
                &(OpCode::Nop as i32).to_le_bytes()[..],
                &[0]
            ]
        );
    }

    // --- Global ---

    #[test]
    fn test_global_to_hash() {
        let gt = GlobalType {
            content_type: Some(i32_vt()),
            mutable: Some(false),
            shared: Some(false),
        };
        let g = Global {
            r#type: Some(gt),
            init_expr: Some(empty_expr()),
        };
        hash_eq!(
            [g],
            [
                &(PlainType::ValueTypeI32 as i32).to_le_bytes()[..],
                &[0],
                &[0],
                &[0],
                &OPTION_TAG,
                &0u64.to_le_bytes()[..]
            ]
        );
    }

    #[test]
    fn test_global_missing_type_fails() {
        hash_err!(Global {
            r#type: None,
            init_expr: Some(empty_expr()),
        });
    }

    // --- Export ---

    #[test]
    fn test_export_to_hash() {
        let e = Export {
            name: Some("foo".to_string()),
            kind: Some(ExternalKind::ExtFunc as i32),
            index: Some(0),
        };
        hash_eq!(
            [e],
            [
                &3u64.to_le_bytes()[..],
                b"foo",
                &(ExternalKind::ExtFunc as i32).to_le_bytes()[..],
                &0u32.to_le_bytes()[..]
            ]
        );
    }

    #[test]
    fn test_export_missing_name_fails() {
        hash_err!(Export {
            name: None,
            kind: Some(ExternalKind::ExtFunc as i32),
            index: Some(0),
        });
    }

    #[test]
    fn test_export_missing_kind_fails() {
        hash_err!(Export {
            name: Some("foo".to_string()),
            kind: None,
            index: Some(0),
        });
    }

    #[test]
    fn test_export_missing_index_fails() {
        hash_err!(Export {
            name: Some("foo".to_string()),
            kind: Some(ExternalKind::ExtFunc as i32),
            index: None,
        });
    }

    // --- ElementKind ---

    #[test]
    fn test_element_kind_active_to_hash() {
        let ek = ElementKind {
            r#type: Some(ElementKindType::ElActive as i32),
            table_index: Some(0),
            expression: Some(empty_expr()),
        };
        hash_eq!(
            [ek],
            [
                &(ElementKindType::ElActive as i32).to_le_bytes()[..],
                &OPTION_TAG,
                &0u32.to_le_bytes()[..],
                &OPTION_TAG,
                &0u64.to_le_bytes()[..]
            ]
        );
    }

    #[test]
    fn test_element_kind_passive_to_hash() {
        let ek = ElementKind {
            r#type: Some(ElementKindType::ElPassive as i32),
            table_index: None,
            expression: None,
        };
        hash_eq!(
            [ek],
            [
                &(ElementKindType::ElPassive as i32).to_le_bytes()[..],
                &[0],
                &[0]
            ]
        );
    }

    #[test]
    fn test_element_kind_missing_type_fails() {
        hash_err!(ElementKind {
            r#type: None,
            table_index: None,
            expression: None,
        });
    }

    // --- ElementFunctions / ElementExpressions / Items ---

    #[test]
    fn test_element_functions_to_hash() {
        let ef = ElementFunctions {
            functions: vec![1, 2, 3],
        };
        hash_eq!(
            [ef],
            [
                &3u64.to_le_bytes()[..],
                &1u32.to_le_bytes()[..],
                &2u32.to_le_bytes()[..],
                &3u32.to_le_bytes()[..]
            ]
        );
    }

    #[test]
    fn test_element_expressions_to_hash() {
        let ee = ElementExpressions {
            reference_type: Some(RefType::RefFunc as i32),
            expressions: vec![],
        };
        hash_eq!(
            [ee],
            [
                &(RefType::RefFunc as i32).to_le_bytes()[..],
                &0u64.to_le_bytes()[..]
            ]
        );
    }

    #[test]
    fn test_element_expressions_missing_ref_type_fails() {
        hash_err!(ElementExpressions {
            reference_type: None,
            expressions: vec![],
        });
    }

    #[test]
    fn test_items_functions_to_hash() {
        let items = Items::Functions(ElementFunctions { functions: vec![1] });
        hash_eq!([items], [&1u64.to_le_bytes()[..], &1u32.to_le_bytes()[..]]);
    }

    #[test]
    fn test_items_expressions_to_hash() {
        let items = Items::Expressions(ElementExpressions {
            reference_type: Some(RefType::RefFunc as i32),
            expressions: vec![],
        });
        hash_eq!(
            [items],
            [
                &(RefType::RefFunc as i32).to_le_bytes()[..],
                &0u64.to_le_bytes()[..]
            ]
        );
    }

    // --- Element ---

    #[test]
    fn test_element_to_hash() {
        let ek = ElementKind {
            r#type: Some(ElementKindType::ElPassive as i32),
            table_index: None,
            expression: None,
        };
        let el = Element {
            kind: Some(ek),
            items: Some(Items::Functions(ElementFunctions { functions: vec![] })),
        };
        hash_eq!(
            [el],
            [
                &(ElementKindType::ElPassive as i32).to_le_bytes()[..],
                &[0],
                &[0],
                &OPTION_TAG,
                &0u64.to_le_bytes()[..]
            ]
        );
    }

    #[test]
    fn test_element_none_items_to_hash() {
        let ek = ElementKind {
            r#type: Some(ElementKindType::ElPassive as i32),
            table_index: None,
            expression: None,
        };
        let el = Element {
            kind: Some(ek),
            items: None,
        };
        hash_eq!(
            [el],
            [
                &(ElementKindType::ElPassive as i32).to_le_bytes()[..],
                &[0],
                &[0],
                &[0]
            ]
        );
    }

    #[test]
    fn test_element_missing_kind_fails() {
        hash_err!(Element {
            kind: None,
            items: None,
        });
    }

    // --- CodeSectionEntry / Locals ---

    #[test]
    fn test_code_section_entry_empty_to_hash() {
        let cse = CodeSectionEntry {
            locals: vec![],
            body: vec![],
        };
        hash_eq!([cse], [0u64.to_le_bytes(), 0u64.to_le_bytes()]);
    }

    #[test]
    fn test_locals_to_hash() {
        let l = Locals {
            count: Some(3),
            value_type: Some(i32_vt()),
        };
        hash_eq!(
            [l],
            [
                &3u32.to_le_bytes()[..],
                &(PlainType::ValueTypeI32 as i32).to_le_bytes()[..],
                &[0]
            ]
        );
    }

    #[test]
    fn test_locals_missing_count_fails() {
        hash_err!(Locals {
            count: None,
            value_type: Some(i32_vt()),
        });
    }

    #[test]
    fn test_locals_missing_value_type_fails() {
        hash_err!(Locals {
            count: Some(3),
            value_type: None,
        });
    }

    // --- DataKind / Data ---

    #[test]
    fn test_data_kind_passive_to_hash() {
        let dk = DataKind {
            r#type: Some(DataKindType::Passive as i32),
            memory_index: None,
            expression: None,
        };
        hash_eq!(
            [dk],
            [
                &(DataKindType::Passive as i32).to_le_bytes()[..],
                &[0],
                &[0]
            ]
        );
    }

    #[test]
    fn test_data_kind_active_to_hash() {
        let dk = DataKind {
            r#type: Some(DataKindType::Active as i32),
            memory_index: Some(0),
            expression: Some(empty_expr()),
        };
        hash_eq!(
            [dk],
            [
                &(DataKindType::Active as i32).to_le_bytes()[..],
                &OPTION_TAG,
                &0u32.to_le_bytes()[..],
                &OPTION_TAG,
                &0u64.to_le_bytes()[..]
            ]
        );
    }

    #[test]
    fn test_data_kind_missing_type_fails() {
        hash_err!(DataKind {
            r#type: None,
            memory_index: None,
            expression: None,
        });
    }

    #[test]
    fn test_data_to_hash() {
        let dk = DataKind {
            r#type: Some(DataKindType::Passive as i32),
            memory_index: None,
            expression: None,
        };
        let d = Data {
            kind: Some(dk),
            data: Some(b"hi".to_vec()),
        };
        hash_eq!(
            [d],
            [
                &(DataKindType::Passive as i32).to_le_bytes()[..],
                &[0],
                &[0],
                &2u64.to_le_bytes()[..],
                b"hi"
            ]
        );
    }

    #[test]
    fn test_data_missing_kind_fails() {
        hash_err!(Data {
            kind: None,
            data: Some(b"hi".to_vec()),
        });
    }

    #[test]
    fn test_data_missing_data_fails() {
        let dk = DataKind {
            r#type: Some(DataKindType::Passive as i32),
            memory_index: None,
            expression: None,
        };
        hash_err!(Data {
            kind: Some(dk),
            data: None,
        });
    }

    // --- ProgramModule ---

    #[test]
    fn test_program_module_minimal_to_hash() {
        hash_eq!(
            [default_pm()],
            [
                &1u32.to_le_bytes()[..],
                &1u32.to_le_bytes()[..],
                &(Encoding::Module as i32).to_le_bytes()[..],
                &[0u8; 11][..]
            ]
        );
    }

    #[test]
    fn test_program_module_missing_protocol_version_fails() {
        hash_err!(ProgramModule {
            protocol_version: None,
            ..default_pm()
        });
    }

    #[test]
    fn test_program_module_missing_version_fails() {
        hash_err!(ProgramModule {
            version: None,
            ..default_pm()
        });
    }

    #[test]
    fn test_program_module_with_sections_to_hash() {
        let pm = ProgramModule {
            type_section: Some(TypeSection { types: vec![] }),
            import_section: Some(ImportSection { imports: vec![] }),
            function_section: Some(FunctionSection { type_idxs: vec![] }),
            ..default_pm()
        };
        hash_eq!(
            [pm],
            [
                &1u32.to_le_bytes()[..],
                &1u32.to_le_bytes()[..],
                &(Encoding::Module as i32).to_le_bytes()[..],
                &0u64.to_le_bytes()[..],
                &0u64.to_le_bytes()[..],
                &0u64.to_le_bytes()[..],
                &[0u8; 8][..]
            ]
        );
    }
}
