use crate::libernet::wasm::{self, CatchElement, PlainType, RefType};
use crate::libernet::wasm::{OpCode, Operator, operator::Operator::*};
use anyhow::{Result, anyhow, bail};
use blstrs::Scalar;
use crypto::{merkle::AsScalar, poseidon::hash_t4};

#[macro_export]
macro_rules! opmatch {
    ($expr:expr, $pat:pat => $body:block, $msg:expr $(,)?) => {{
        match $expr {
            Some($pat) => $body,
            _ => anyhow::bail!($msg),
        }
    }};
}

trait ToScalar {
    fn to_scalar(&self) -> Result<Scalar>;
}

impl ToScalar for u32 {
    fn to_scalar(&self) -> Result<Scalar> {
        Ok(self.as_scalar())
    }
}

impl<T> ToScalar for Vec<T>
where
    T: ToScalar,
{
    fn to_scalar(&self) -> Result<Scalar> {
        let mut scalar = (self.len() as u64).as_scalar();
        for elem in self {
            scalar = hash_t4(&[scalar, elem.to_scalar()?]);
        }
        Ok(scalar)
    }
}

impl ToScalar for wasm::ValueType {
    fn to_scalar(&self) -> Result<Scalar> {
        let value_code = self
            .value_type
            .ok_or_else(|| anyhow!("Value type is required"))?;
        let plain_type = PlainType::try_from(value_code)?;
        let body = match plain_type {
            PlainType::ValueTypeI32
            | PlainType::ValueTypeI64
            | PlainType::ValueTypeF32
            | PlainType::ValueTypeF64
            | PlainType::ValueTypeV128 => {
                if self.reference_type.is_some() {
                    bail!("Reference type is set for primitive value type");
                }
                0.into()
            }
            PlainType::ValueTypeRef => {
                let ref_code = self
                    .reference_type
                    .ok_or_else(|| anyhow!("Reference type is required"))?;
                if RefType::try_from(ref_code).is_err() {
                    bail!("Invalid reference type");
                }
                ref_code.as_scalar()
            }
        };
        Ok(hash_t4(&[value_code.as_scalar(), body]))
    }
}

impl ToScalar for wasm::block_type::BlockType {
    fn to_scalar(&self) -> Result<Scalar> {
        Ok(match self {
            wasm::block_type::BlockType::Empty(_) => -1.as_scalar(),
            wasm::block_type::BlockType::ValueType(vt) => vt.to_scalar()?,
            wasm::block_type::BlockType::FunctionType(_) => todo!(),
        })
    }
}

impl ToScalar for CatchElement {
    fn to_scalar(&self) -> Result<Scalar> {
        let catch_element = self
            .catch_element
            .ok_or(anyhow!("Catch element is required"))?;
        Ok(match catch_element {
            wasm::catch_element::CatchElement::One(one) => hash_t4(&[
                one.tag.ok_or(anyhow!("One: Tag is required"))?.as_scalar(),
                one.label
                    .ok_or(anyhow!("One: Label is required"))?
                    .as_scalar(),
            ]),
            wasm::catch_element::CatchElement::OneRef(one_ref) => hash_t4(&[
                one_ref
                    .tag
                    .ok_or(anyhow!("OneRef: Tag is required"))?
                    .as_scalar(),
                one_ref
                    .label
                    .ok_or(anyhow!("OneRef: Label is required"))?
                    .as_scalar(),
            ]),
            wasm::catch_element::CatchElement::All(all) => hash_t4(&[all
                .label
                .ok_or(anyhow!("All: Label is required"))?
                .as_scalar()]),
            wasm::catch_element::CatchElement::AllRef(all_ref) => hash_t4(&[all_ref
                .label
                .ok_or(anyhow!("AllRef: Label is required"))?
                .as_scalar()]),
        })
    }
}

impl ToScalar for Operator {
    fn to_scalar(&self) -> Result<Scalar> {
        let opcode_value = self.opcode.ok_or_else(|| anyhow!("Opcode is required"))?;
        let opcode = OpCode::try_from(opcode_value)?;
        let operator = &self.operator;

        let body: Scalar = match opcode {
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
                0.into()
            }
            OpCode::Block | OpCode::Loop | OpCode::If | OpCode::LegacyExceptionsExtTry => {
                opmatch!(operator, BlockType(block_type) => {
                    match block_type.block_type {
                        Some(block_type) => block_type.to_scalar()?,
                        _ => bail!("Block type is required"),
                    }
                }, "Block type is required")
            }
            OpCode::Br
            | OpCode::BrIf
            | OpCode::LegacyExceptionsExtRethrow
            | OpCode::LegacyExceptionsExtDelegate => {
                opmatch!(operator, RelativeDepth(relative_depth) => {
                    relative_depth.as_scalar()
                }, "Relative depth is required")
            }
            OpCode::BrTable => {
                opmatch!(operator, Targets(targets) => {
                    let default = targets.default.ok_or_else(|| anyhow!("Default target is required"))?;
                    hash_t4(&[default.as_scalar(), targets.targets.to_scalar()?])
                }, "Type index is required")
            }
            OpCode::Call => {
                opmatch!(operator, FunctionIndex(function_index) => {
                    function_index.as_scalar()
                }, "Function index is required")
            }
            OpCode::CallIndirect => {
                opmatch!(operator, CallIndirect(call_indirect) => {
                    let type_index = call_indirect.type_index.ok_or_else(|| anyhow!("Type index is required"))?;
                    let table_index = call_indirect.table_index.ok_or_else(|| anyhow!("Table index is required"))?;
                    hash_t4(&[type_index.as_scalar(), table_index.as_scalar()])
                }, "Type index and table index are required")
            }
            OpCode::LocalGet | OpCode::LocalSet | OpCode::LocalTee => {
                opmatch!(operator, LocalIndex(local_index) => {
                    local_index.as_scalar()
                }, "Local index is required")
            }
            OpCode::GlobalGet | OpCode::GlobalSet => {
                opmatch!(operator, GlobalIndex(global_index) => {
                    global_index.as_scalar()
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
                opmatch!(operator, Memarg(memarg) => {
                    let align = memarg.align.ok_or_else(|| anyhow!("Align is required"))?;
                    let max_align = memarg.max_align.ok_or_else(|| anyhow!("Max align is required"))?;
                    let offset = memarg.offset.ok_or_else(|| anyhow!("Offset is required"))?;
                    let memory = memarg.memory.ok_or_else(|| anyhow!("Memory is required"))?;
                    hash_t4(&[align.as_scalar(), max_align.as_scalar(), offset.as_scalar(), memory.as_scalar()])
                }, "Mem arg is required")
            }
            OpCode::MemorySize | OpCode::MemoryGrow => {
                opmatch!(operator, Mem(mem) => {
                    mem.as_scalar()
                }, "Mem is required")
            }
            OpCode::I32Constant => {
                opmatch!(operator, I32Value(i32_value) => {
                    i32_value.as_scalar()
                }, "I32 value is required")
            }
            OpCode::I64Constant => {
                opmatch!(operator, I64Value(i64_value) => {
                    i64_value.as_scalar()
                }, "I64 value is required")
            }
            OpCode::F32Constant => {
                opmatch!(operator, F32Value(f32_value) => {
                    f32_value.as_scalar()
                }, "F32 value is required")
            }
            OpCode::F64Constant => {
                opmatch!(operator, F64Value(f64_value) => {
                    f64_value.as_scalar()
                }, "F64 value is required")
            }
            OpCode::BulkMemoryExtMemoryInit => {
                opmatch!(operator, MemoryInit(memory_init) => {
                    let data_index = memory_init.data_index.ok_or_else(|| anyhow!("Data index is required"))?;
                    let address = memory_init.address.ok_or_else(|| anyhow!("Address is required"))?;
                    hash_t4(&[data_index.as_scalar(), address.as_scalar()])
                }, "Data index and address are required")
            }
            OpCode::BulkMemoryExtDataDrop => {
                opmatch!(operator, DataIndex(data_index) => {
                    data_index.as_scalar()
                }, "Data index is required")
            }
            OpCode::BulkMemoryExtMemoryCopy => {
                opmatch!(operator, MemoryCopy(memory_copy) => {
                    let destination_address = memory_copy.destination_address.ok_or_else(|| anyhow!("Destination address is required"))?;
                    let source_address = memory_copy.source_address.ok_or_else(|| anyhow!("Source address is required"))?;
                    hash_t4(&[destination_address.as_scalar(), source_address.as_scalar()])
                }, "Destination address and source address are required")
            }
            OpCode::BulkMemoryExtMemoryFill => {
                opmatch!(operator, Mem(mem) => {
                    mem.as_scalar()
                }, "Mem is required")
            }
            OpCode::BulkMemoryExtTableInit => {
                opmatch!(operator, TableInit(table_init) => {
                    let element_index = table_init.element_index.ok_or_else(|| anyhow!("Element index is required"))?;
                    let table = table_init.table.ok_or_else(|| anyhow!("Table is required"))?;
                    hash_t4(&[element_index.as_scalar(), table.as_scalar()])
                }, "Table index is required")
            }
            OpCode::BulkMemoryExtElemDrop => {
                opmatch!(operator, ElementIndex(element_index) => {
                    element_index.as_scalar()
                }, "Element index is required")
            }
            OpCode::BulkMemoryExtTableCopy => {
                opmatch!(operator, TableCopy(table_copy) => {
                    let dst_table = table_copy.dst_table.ok_or_else(|| anyhow!("Dst table is required"))?;
                    let src_table = table_copy.src_table.ok_or_else(|| anyhow!("Src table is required"))?;
                    hash_t4(&[dst_table.as_scalar(), src_table.as_scalar()])
                }, "Dst table and src table are required")
            }
            OpCode::ExceptionsExtTryTable => {
                opmatch!(operator, TryTable(try_table) => {
                    let block_type = try_table.r#type.ok_or_else(|| anyhow!("Block type is required"))?.block_type.ok_or_else(|| anyhow!("Block type is required"))?.to_scalar()?;
                    let catches = try_table.catches.to_scalar()?;
                    hash_t4(&[block_type, catches])
                }, "Type index and catches are required")
            }
            OpCode::ExceptionsExtThrow | OpCode::LegacyExceptionsExtCatch => {
                opmatch!(operator, TagIndex(tag_index) => {
                    tag_index.as_scalar()
                }, "Tag index is required")
            }
        };

        Ok(hash_t4(&[opcode_value.as_scalar(), body]))
    }
}

impl AsScalar for Operator {
    fn as_scalar(&self) -> Scalar {
        hash_t4(&match self.to_scalar() {
            Ok(scalar) => [1.as_scalar(), scalar],
            Err(_) => [0.as_scalar(), 0.as_scalar()],
        })
    }
}
