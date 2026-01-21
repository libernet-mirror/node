use crate::program::*;
use anyhow::{Ok, Result, anyhow};

pub fn from_wasm(bytes: &[u8]) -> Result<ProgramModule> {
    use wasmparser::Parser;
    let mut version: Option<Version> = None;
    let mut proto_sections: Vec<Section> = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload?;
        if let Some(payload) = Version::from_wasmparser(&payload)? {
            version = Some(payload);
        } else if let Some(payload) = Section::from_wasmparser(payload)? {
            proto_sections.push(payload);
        }
    }

    Ok(ProgramModule {
        protocol_version: 1,
        version: version.ok_or(anyhow!("Version not found"))?,
        sections: proto_sections,
    })
}

pub fn render_wasm(program: ProgramModule) -> Result<Vec<u8>> {
    use wasm_encoder::{CodeSection, Module};

    let mut module: Module = Module::new();
    let mut code_section: CodeSection = CodeSection::new();
    let mut last_code_section_entry: Option<&Section> = None;

    for section in &program.sections {
        if let Some(section::Section::CodeSectionEntry(_)) = &section.section {
            last_code_section_entry = Some(section);
        };
    }

    for section in &program.sections {
        section.render_wasm(&mut module, &mut code_section)?;
        if let Some(last_code_section_entry) = last_code_section_entry
            && last_code_section_entry == section {
                module.section(&code_section);
            }
    }
    Ok(module.finish())
}
