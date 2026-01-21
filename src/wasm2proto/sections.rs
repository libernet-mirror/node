use crate::program::*;
use anyhow::{Ok, Result, anyhow, bail};

impl Section {
    pub fn from_wasmparser(payload: wasmparser::Payload) -> Result<Option<Self>> {
        use wasmparser::Payload;
        match payload {
            Payload::TypeSection(section) => Ok(Some(Section {
                section: Some(section::Section::TypeSection(TypeSection::from_wasmparser(
                    section,
                )?)),
            })),
            Payload::ImportSection(section) => Ok(Some(Section {
                section: Some(section::Section::ImportSection(
                    ImportSection::from_wasmparser(section)?,
                )),
            })),
            Payload::FunctionSection(section) => Ok(Some(Section {
                section: Some(section::Section::FunctionSection(
                    FunctionSection::from_wasmparser(section)?,
                )),
            })),
            Payload::TableSection(section) => Ok(Some(Section {
                section: Some(section::Section::TableSection(
                    TableSection::from_wasmparser(section)?,
                )),
            })),
            Payload::MemorySection(section) => Ok(Some(Section {
                section: Some(section::Section::MemorySection(
                    MemorySection::from_wasmparser(section)?,
                )),
            })),
            Payload::TagSection(_) => {
                bail!("TagSection is not supported");
            }
            Payload::GlobalSection(section) => Ok(Some(Section {
                section: Some(section::Section::GlobalSection(
                    GlobalSection::from_wasmparser(section)?,
                )),
            })),
            Payload::ExportSection(section) => Ok(Some(Section {
                section: Some(section::Section::ExportSection(
                    ExportSection::from_wasmparser(section)?,
                )),
            })),
            Payload::StartSection { .. } => {
                bail!("StartSection is not supported");
            }
            Payload::ElementSection(section) => Ok(Some(Section {
                section: Some(section::Section::ElementSection(
                    ElementSection::from_wasmparser(section)?,
                )),
            })),
            Payload::DataCountSection { .. } => {
                // this section provider information about data sections count, we don't need it
                Ok(None)
            }
            Payload::DataSection(section) => Ok(Some(Section {
                section: Some(section::Section::DataSection(DataSection::from_wasmparser(
                    section,
                )?)),
            })),
            Payload::CodeSectionStart { .. } => {
                // this section provider information about code sections count, we don't need it
                Ok(None)
            }
            Payload::CodeSectionEntry(body) => Ok(Some(Section {
                section: Some(section::Section::CodeSectionEntry(
                    CodeSectionEntry::from_wasmparser(body)?,
                )),
            })),
            Payload::InstanceSection(_) => Ok(None),
            Payload::CoreTypeSection(_) => Ok(None),
            Payload::ComponentInstanceSection(_) => Ok(None),
            Payload::ComponentAliasSection(_) => Ok(None),
            Payload::ComponentTypeSection(_) => Ok(None),
            Payload::ComponentCanonicalSection(_) => Ok(None),
            Payload::ComponentStartSection { .. } => Ok(None),
            Payload::ComponentImportSection(_) => Ok(None),
            Payload::ComponentExportSection(_) => Ok(None),
            Payload::CustomSection(_) => Ok(None),
            Payload::End(_) => Ok(None),
            rest => {
                bail!("Unknown section {:?}", rest);
            }
        }
    }
    pub fn render_wasm(
        &self,
        module: &mut wasm_encoder::Module,
        code_section: &mut wasm_encoder::CodeSection,
    ) -> Result<()> {
        match &self.section {
            Some(section::Section::TypeSection(type_section)) => type_section.render_wasm(module),
            Some(section::Section::ImportSection(import_section)) => {
                import_section.render_wasm(module)
            }
            Some(section::Section::FunctionSection(function_section)) => {
                function_section.render_wasm(module)
            }
            Some(section::Section::TableSection(table_section)) => {
                table_section.render_wasm(module)
            }
            Some(section::Section::MemorySection(memory_section)) => {
                memory_section.render_wasm(module)
            }
            Some(section::Section::GlobalSection(global_section)) => {
                global_section.render_wasm(module)
            }
            Some(section::Section::ExportSection(export_section)) => {
                export_section.render_wasm(module)
            }
            Some(section::Section::ElementSection(element_section)) => {
                element_section.render_wasm(module)
            }
            Some(section::Section::CodeSectionEntry(code_section_entry)) => {
                code_section_entry.render_wasm(code_section)
            }
            Some(section::Section::DataSection(data_section)) => data_section.render_wasm(module),
            _ => bail!("render_wasm: is not supported for section {:?}", self),
        }
    }
}

impl Version {
    pub fn from_wasmparser(payload: &wasmparser::Payload) -> Result<Option<Version>> {
        use wasmparser::{Encoding, Payload};
        match payload {
            &Payload::Version { num, encoding, .. } => {
                if num != 1 {
                    bail!("Only version 1 is supported, got {}", num);
                }

                if encoding != Encoding::Module {
                    bail!("Only Encoding::Module is supported, got {:?}", encoding);
                }

                Ok(Some(Version {
                    num: num as u32,
                    encoding: encoding as i32,
                }))
            }
            _ => Ok(None),
        }
    }
}

impl TypeSection {
    fn from_wasmparser(
        types: wasmparser::SectionLimited<'_, wasmparser::RecGroup>,
    ) -> Result<TypeSection> {
        use wasmparser::CompositeInnerType;

        let mut program_types: Vec<SubType> = Vec::new();
        for group in types {
            let group = group?;
            let types = group.types().collect::<Vec<_>>();
            if types.is_empty() {
                bail!("Expected at least 1 type in type group");
            }
            if types.len() > 1 {
                bail!("Recursive & GC type groups are not supported");
            }
            let atype = types[0];
            if !atype.is_final {
                bail!("Non-final types are not supported");
            }
            if atype.supertype_idx.is_some() {
                bail!("Supertype indexes are not supported");
            }
            match &atype.composite_type.inner {
                CompositeInnerType::Func(ft) => {
                    let mut params: Vec<i32> = Vec::new();
                    for param in ft.params() {
                        params.push(ValueType::try_from(*param)? as i32);
                    }
                    let mut results: Vec<i32> = Vec::new();
                    for result in ft.results() {
                        results.push(ValueType::try_from(*result)? as i32);
                    }
                    program_types.push(SubType {
                        kind: Some(sub_type::Kind::Func(FuncType { params, results })),
                    });
                }
                inner_type => {
                    bail!("Type is not supported {:?}", inner_type);
                }
            }
        }
        Ok(TypeSection {
            types: program_types,
        })
    }

    fn render_wasm(&self, module: &mut wasm_encoder::Module) -> Result<()> {
        use wasm_encoder::{CompositeInnerType, CompositeType, SubType, TypeSection, ValType};
        let mut types = TypeSection::new();
        for ty in &self.types {
            match &ty.kind {
                Some(sub_type::Kind::Func(ft)) => {
                    let mut params: Vec<ValType> = Vec::new();
                    for p in &ft.params {
                        params.push(ValueType::try_from(*p)?.try_into()?);
                    }
                    let mut results: Vec<ValType> = Vec::new();
                    for r in &ft.results {
                        results.push(ValueType::try_from(*r)?.try_into()?);
                    }
                    let ty = &SubType {
                        is_final: true,
                        supertype_idx: None,
                        composite_type: CompositeType {
                            inner: CompositeInnerType::Func(wasm_encoder::FuncType::new(
                                params, results,
                            )),
                            shared: false,
                            descriptor: None,
                            describes: None,
                        },
                    };
                    types.ty().subtype(ty);
                }
                None => {
                    bail!("Type is not supported {:?}", ty);
                }
            }
        }
        module.section(&types);
        Ok(())
    }
}

impl ImportSection {
    fn from_wasmparser(
        imports: wasmparser::SectionLimited<'_, wasmparser::Imports>,
    ) -> Result<ImportSection> {
        use wasmparser::{Imports, TypeRef};
        let mut refs: Vec<TypeRefFunc> = Vec::new();
        for import in imports {
            match import? {
                Imports::Single(_, import) => {
                    let module = import.module.to_string();
                    let name = import.name.to_string();
                    match import.ty {
                        TypeRef::Func(ftype) => {
                            refs.push(TypeRefFunc {
                                module,
                                name,
                                ftype,
                            });
                        }
                        _ => bail!("ImportSection: only Func type imports are supported"),
                    }
                }
                _ => {
                    bail!("ImportSection: only Single Import is supported");
                }
            }
        }

        Ok(ImportSection { imports: refs })
    }

    fn render_wasm(&self, module: &mut wasm_encoder::Module) -> Result<()> {
        use wasm_encoder::{EntityType, ImportSection};
        let mut imports = ImportSection::new();
        for import in &self.imports {
            imports.import(
                import.module.as_str(),
                import.name.as_str(),
                EntityType::Function(import.ftype),
            );
        }
        module.section(&imports);
        Ok(())
    }
}

impl FunctionSection {
    fn from_wasmparser(functions: wasmparser::SectionLimited<'_, u32>) -> Result<FunctionSection> {
        let mut type_idxs: Vec<u32> = Vec::new();
        for function in functions {
            type_idxs.push(function?);
        }
        Ok(FunctionSection { type_idxs })
    }
    fn render_wasm(&self, module: &mut wasm_encoder::Module) -> Result<()> {
        use wasm_encoder::FunctionSection;
        let mut functions = FunctionSection::new();
        for type_idx in &self.type_idxs {
            functions.function(*type_idx);
        }
        module.section(&functions);
        Ok(())
    }
}

impl TableSection {
    fn from_wasmparser(
        tables: wasmparser::SectionLimited<'_, wasmparser::Table>,
    ) -> Result<TableSection> {
        use wasmparser::TableInit;
        let mut proto_tables: Vec<TableType> = Vec::new();
        for table in tables {
            let table = table?;
            if let TableInit::Expr(_) = table.init {
                bail!("Table init is not supported");
            }

            if table.ty.shared {
                bail!("Shared tables are not supported");
            }

            proto_tables.push(TableType {
                ref_type: RefType::try_from(table.ty.element_type)?,
                table64: table.ty.table64,
                initial: table.ty.initial,
                maximum: table.ty.maximum,
                shared: table.ty.shared,
            });
        }
        Ok(TableSection {
            types: proto_tables,
        })
    }

    fn render_wasm(&self, module: &mut wasm_encoder::Module) -> Result<()> {
        use wasm_encoder::{TableSection, TableType};
        let mut table_types = TableSection::new();
        for ty in &self.types {
            table_types.table(TableType {
                element_type: ty.ref_type.try_into()?,
                table64: ty.table64,
                minimum: ty.initial,
                maximum: ty.maximum,
                shared: ty.shared,
            });
        }
        module.section(&table_types);
        Ok(())
    }
}

impl MemorySection {
    fn from_wasmparser(
        section: wasmparser::SectionLimited<'_, wasmparser::MemoryType>,
    ) -> Result<MemorySection> {
        let mut memory_types: Vec<MemoryType> = Vec::new();
        for memory in section {
            let memory = memory?;
            memory_types.push(MemoryType {
                memory64: memory.memory64,
                shared: memory.shared,
                initial: memory.initial,
                maximum: memory.maximum,
                page_size_log2: memory.page_size_log2,
            })
        }
        Ok(MemorySection { memory_types })
    }
    fn render_wasm(&self, module: &mut wasm_encoder::Module) -> Result<()> {
        use wasm_encoder::MemorySection;
        let mut types = MemorySection::new();
        for memory in &self.memory_types {
            types.memory(wasm_encoder::MemoryType {
                memory64: memory.memory64,
                shared: memory.shared,
                minimum: memory.initial,
                maximum: memory.maximum,
                page_size_log2: memory.page_size_log2,
            });
        }
        module.section(&types);
        Ok(())
    }
}

impl GlobalSection {
    fn from_wasmparser(
        section: wasmparser::SectionLimited<'_, wasmparser::Global>,
    ) -> Result<GlobalSection> {
        let mut globals: Vec<Global> = Vec::new();
        for global in section {
            let global = global?;
            globals.push(Global {
                ty: GlobalType {
                    content_type: ValueType::try_from(global.ty.content_type)? as i32,
                    mutable: global.ty.mutable,
                    shared: global.ty.shared,
                },
                init_expr: global.init_expr.try_into()?,
            });
        }
        Ok(GlobalSection { globals })
    }
    fn render_wasm(&self, module: &mut wasm_encoder::Module) -> Result<()> {
        use wasm_encoder::{ConstExpr, GlobalSection, GlobalType};
        let mut globals = GlobalSection::new();
        for global in &self.globals {
            globals.global(
                GlobalType {
                    val_type: ValueType::try_from(global.ty.content_type)?.try_into()?,
                    mutable: global.ty.mutable,
                    shared: global.ty.shared,
                },
                &ConstExpr::raw(global.init_expr.bytecode.clone()),
            );
        }
        module.section(&globals);
        Ok(())
    }
}

impl ExportSection {
    fn from_wasmparser(
        section: wasmparser::SectionLimited<'_, wasmparser::Export>,
    ) -> Result<ExportSection> {
        let mut exports: Vec<Export> = Vec::new();
        for export in section {
            let export = export?;
            exports.push(Export {
                name: export.name.to_string(),
                kind: ExternalKind::try_from(export.kind)? as i32,
                index: export.index,
            });
        }

        Ok(ExportSection { exports })
    }
    fn render_wasm(&self, module: &mut wasm_encoder::Module) -> Result<()> {
        use wasm_encoder::ExportSection;
        let mut exports = ExportSection::new();
        for export in &self.exports {
            exports.export(
                export.name.as_str(),
                ExternalKind::try_from(export.kind)?.try_into()?,
                export.index,
            );
        }
        module.section(&exports);
        Ok(())
    }
}

impl ElementSection {
    fn from_wasmparser(
        section: wasmparser::SectionLimited<'_, wasmparser::Element>,
    ) -> Result<ElementSection> {
        use wasmparser::ElementItems;
        let mut elements: Vec<Element> = Vec::new();
        for element in section {
            let element = element?;

            let items = match element.items {
                ElementItems::Functions(section) => {
                    let mut functions = Vec::new();
                    for function in section {
                        functions.push(function?);
                    }
                    element::Items::Functions(ElementFunctions { functions })
                }
                ElementItems::Expressions(ref_type, section) => {
                    let mut expressions = Vec::new();
                    for expression in section {
                        expressions.push(Expression::try_from(expression?)?);
                    }
                    element::Items::Expressions(ElementExpressions {
                        ref_type: RefType::try_from(ref_type)?,
                        expressions,
                    })
                }
            };

            elements.push(Element {
                kind: ElementKind::try_from(element.kind)?,
                items: Some(items),
            });
        }

        Ok(ElementSection { elements })
    }

    fn render_wasm(&self, module: &mut wasm_encoder::Module) -> Result<()> {
        use wasm_encoder::{
            ConstExpr, ElementMode, ElementSection, ElementSegment, Elements, RefType,
        };
        let mut elements = ElementSection::new();
        for element in &self.elements {
            let element_mode = match ElementKindType::try_from(element.kind.ty)? {
                ElementKindType::ElPassive => ElementMode::Passive,
                ElementKindType::ElActive => ElementMode::Active {
                    table: element.kind.table_index,
                    offset: &ConstExpr::raw(
                        element
                            .kind
                            .expression
                            .as_ref()
                            .ok_or(anyhow!("Expression not found"))?
                            .bytecode
                            .clone(),
                    ),
                },
                ElementKindType::ElDeclared => ElementMode::Declared,
            };
            let items = match element.items.as_ref().ok_or(anyhow!("Items not found"))? {
                element::Items::Functions(functions) => {
                    Elements::Functions(functions.functions.clone().into())
                }
                element::Items::Expressions(expressions) => Elements::Expressions(
                    RefType::try_from(expressions.ref_type)?,
                    expressions
                        .expressions
                        .clone()
                        .into_iter()
                        .map(|e| ConstExpr::raw(e.bytecode.clone()))
                        .collect(),
                ),
            };
            elements.segment(ElementSegment {
                mode: element_mode,
                elements: items,
            });
        }
        module.section(&elements);
        Ok(())
    }
}

impl CodeSectionEntry {
    fn from_wasmparser(section: wasmparser::FunctionBody) -> Result<CodeSectionEntry> {
        let mut locals: Vec<Locals> = Vec::new();
        for local in section.get_locals_reader()? {
            let (count, val_type) = local?;

            locals.push(Locals {
                count,
                value_type: ValueType::try_from(val_type)? as i32,
            });
        }
        Ok(CodeSectionEntry {
            locals,
            body: Expression::try_from(section.get_binary_reader_for_operators()?)?,
        })
    }

    fn render_wasm(&self, code_section: &mut wasm_encoder::CodeSection) -> Result<()> {
        use wasm_encoder::{Function, ValType};
        let mut locals: Vec<(u32, ValType)> = Vec::new();
        for local in &self.locals {
            locals.push((
                local.count,
                ValueType::try_from(local.value_type)?.try_into()?,
            ));
        }
        let mut function = Function::new(locals);
        function.raw(self.body.bytecode.clone());
        code_section.function(&function);
        Ok(())
    }
}

impl DataSection {
    fn from_wasmparser(
        section: wasmparser::SectionLimited<'_, wasmparser::Data>,
    ) -> Result<DataSection> {
        let mut datas: Vec<Data> = Vec::new();
        for data in section {
            let data = data?;
            datas.push(Data {
                kind: DataKind::try_from(data.kind)?,
                data: data.data.to_vec(),
            });
        }

        Ok(DataSection { datas })
    }
    fn render_wasm(&self, module: &mut wasm_encoder::Module) -> Result<()> {
        use wasm_encoder::{ConstExpr, DataSection, DataSegment, DataSegmentMode};
        let mut section = DataSection::new();
        for data in &self.datas {
            let data_mode = match DataKindType::try_from(data.kind.ty)? {
                DataKindType::Passive => DataSegmentMode::Passive,
                DataKindType::Active => DataSegmentMode::Active {
                    memory_index: data
                        .kind
                        .memory_index
                        .ok_or(anyhow!("Memory index not found"))?,
                    offset: &ConstExpr::raw(
                        data.kind
                            .expression
                            .as_ref()
                            .ok_or(anyhow!("Expression not found"))?
                            .bytecode
                            .clone(),
                    ),
                },
            };
            section.segment(DataSegment {
                mode: data_mode,
                data: data.data.clone(),
            });
        }
        module.section(&section);
        Ok(())
    }
}
