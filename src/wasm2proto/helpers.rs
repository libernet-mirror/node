use anyhow::{Ok, Result, anyhow, bail};

use crate::program::*;

impl TryFrom<wasmparser::ValType> for ValueType {
    type Error = anyhow::Error;

    fn try_from(val_type: wasmparser::ValType) -> Result<Self> {
        use wasmparser::ValType;
        match val_type {
            ValType::I32 => Ok(ValueType::I32),
            ValType::I64 => Ok(ValueType::I64),
            ValType::F32 => Ok(ValueType::F32),
            ValType::F64 => Ok(ValueType::F64),
            ValType::V128 => Ok(ValueType::V128),
            ValType::Ref(_) => Err(anyhow!("Ref types are not supported")),
        }
    }
}

impl TryFrom<ValueType> for wasm_encoder::ValType {
    type Error = anyhow::Error;

    fn try_from(value_type: ValueType) -> Result<Self> {
        match value_type {
            ValueType::I32 => Ok(wasm_encoder::ValType::I32),
            ValueType::I64 => Ok(wasm_encoder::ValType::I64),
            ValueType::F32 => Ok(wasm_encoder::ValType::F32),
            ValueType::F64 => Ok(wasm_encoder::ValType::F64),
            ValueType::V128 => Ok(wasm_encoder::ValType::V128),
        }
    }
}

impl TryFrom<wasmparser::ConstExpr<'_>> for Expression {
    type Error = anyhow::Error;

    fn try_from(expr: wasmparser::ConstExpr<'_>) -> Result<Self> {
        let mut r = expr.get_binary_reader();
        let mut bytecode = r.read_bytes(r.bytes_remaining())?.to_vec();
        // remove end opcode, wasmencoder adds it automatically
        if bytecode.last() == Some(&0x0B) {
            bytecode.pop();
        }
        if !r.eof() {
            bail!("Unexpected bytes remaining in expression");
        }
        Ok(Expression { bytecode })
    }
}

impl TryFrom<wasmparser::BinaryReader<'_>> for Expression {
    type Error = anyhow::Error;

    fn try_from(mut r: wasmparser::BinaryReader<'_>) -> Result<Self> {
        let n = r.bytes_remaining();
        Ok(Expression {
            bytecode: r.read_bytes(n)?.to_vec(),
        })
    }
}

impl TryFrom<wasmparser::ExternalKind> for ExternalKind {
    type Error = anyhow::Error;

    fn try_from(external_kind: wasmparser::ExternalKind) -> Result<Self> {
        match external_kind {
            wasmparser::ExternalKind::Func => Ok(ExternalKind::ExtFunc),
            wasmparser::ExternalKind::Table => Ok(ExternalKind::ExtTable),
            wasmparser::ExternalKind::Memory => Ok(ExternalKind::ExtMemory),
            wasmparser::ExternalKind::Global => Ok(ExternalKind::ExtGlobal),
            wasmparser::ExternalKind::Tag => Ok(ExternalKind::ExtTag),
            wasmparser::ExternalKind::FuncExact => Ok(ExternalKind::ExtFuncExact),
        }
    }
}

impl TryFrom<ExternalKind> for wasm_encoder::ExportKind {
    type Error = anyhow::Error;

    fn try_from(external_kind: ExternalKind) -> Result<wasm_encoder::ExportKind> {
        match external_kind {
            ExternalKind::ExtFunc => Ok(wasm_encoder::ExportKind::Func),
            ExternalKind::ExtTable => Ok(wasm_encoder::ExportKind::Table),
            ExternalKind::ExtMemory => Ok(wasm_encoder::ExportKind::Memory),
            ExternalKind::ExtGlobal => Ok(wasm_encoder::ExportKind::Global),
            ExternalKind::ExtTag => Ok(wasm_encoder::ExportKind::Tag),
            _ => Err(anyhow!("ExternalKind is not supported")),
        }
    }
}

impl TryFrom<wasmparser::ElementKind<'_>> for ElementKind {
    type Error = anyhow::Error;

    fn try_from(element_kind: wasmparser::ElementKind) -> Result<Self> {
        match element_kind {
            wasmparser::ElementKind::Passive => Ok(ElementKind {
                ty: ElementKindType::ElPassive as i32,
                table_index: None,
                expression: None,
            }),
            wasmparser::ElementKind::Active {
                table_index,
                offset_expr,
            } => Ok(ElementKind {
                ty: ElementKindType::ElActive as i32,
                table_index,
                expression: Some(Expression::try_from(offset_expr)?),
            }),
            wasmparser::ElementKind::Declared => Ok(ElementKind {
                ty: ElementKindType::ElDeclared as i32,
                table_index: None,
                expression: None,
            }),
        }
    }
}

impl TryFrom<wasmparser::DataKind<'_>> for DataKind {
    type Error = anyhow::Error;

    fn try_from(element_kind: wasmparser::DataKind) -> Result<Self> {
        match element_kind {
            wasmparser::DataKind::Passive => Ok(DataKind {
                ty: DataKindType::Passive as i32,
                memory_index: None,
                expression: None,
            }),
            wasmparser::DataKind::Active {
                memory_index,
                offset_expr,
            } => Ok(DataKind {
                ty: DataKindType::Active as i32,
                memory_index: Some(memory_index),
                expression: Some(Expression::try_from(offset_expr)?),
            }),
        }
    }
}

impl TryFrom<wasmparser::RefType> for RefType {
    type Error = anyhow::Error;

    fn try_from(ref_type: wasmparser::RefType) -> Result<Self> {
        use wasmparser::{AbstractHeapType, HeapType};
        match ref_type.heap_type() {
            HeapType::Abstract {
                shared: false,
                ty: AbstractHeapType::Func,
            } => {
                // Ok
            }
            _ => {
                bail!("Only funcref elements are supported");
            }
        };

        Ok(RefType {
            shared: false,
            nullable: ref_type.is_nullable(),
            ty: AbstractRefType::RefFunc as i32,
        })
    }
}

impl TryFrom<RefType> for wasm_encoder::RefType {
    type Error = anyhow::Error;

    fn try_from(ref_type: RefType) -> Result<Self> {
        use wasm_encoder::{AbstractHeapType, HeapType};
        Ok(wasm_encoder::RefType {
            nullable: ref_type.nullable,
            heap_type: HeapType::Abstract {
                shared: ref_type.shared,
                ty: AbstractHeapType::Func,
            },
        })
    }
}
