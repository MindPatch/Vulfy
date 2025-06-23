use std::path::Path;
use quick_xml::events::Event;
use quick_xml::Reader;

use crate::error::{VulfyError, VulfyResult};
use crate::types::{Ecosystem, Package};
use super::PackageParser;

#[derive(Debug)]
pub struct JavaParser;

impl PackageParser for JavaParser {
    fn can_parse(&self, file_path: &Path) -> bool {
        matches!(
            file_path.file_name().and_then(|n| n.to_str()),
            Some("pom.xml") | Some("build.gradle") | Some("build.gradle.kts") | 
            Some("gradle.properties") | Some("ivy.xml")
        )
    }

    async fn parse(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        match filename {
            "pom.xml" => {
                let content = tokio::fs::read_to_string(file_path).await?;
                self.parse_pom_xml(&content, file_path).await
            }
            "build.gradle" | "build.gradle.kts" => {
                self.parse_gradle_build(file_path).await
            }
            "gradle.properties" => {
                Ok(Vec::new()) // Skip properties files for now
            }
            "ivy.xml" => {
                self.parse_ivy_xml(file_path).await
            }
            _ => Ok(Vec::new()),
        }
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Maven
    }
}

impl JavaParser {
    async fn parse_pom_xml(&self, content: &str, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let mut reader = Reader::from_str(content);
        let mut buf = Vec::new();
        let mut packages = Vec::new();
        let mut in_dependencies = false;
        let mut current_group_id = String::new();
        let mut current_artifact_id = String::new();
        let mut current_version = String::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    match e.name().as_ref() {
                        b"dependencies" => in_dependencies = true,
                        b"dependency" if in_dependencies => {
                            current_group_id = String::new();
                            current_artifact_id = String::new();
                            current_version = String::new();
                        }
                        _ => {}
                    }
                }
                Ok(Event::End(ref e)) => {
                    match e.name().as_ref() {
                        b"dependencies" => in_dependencies = false,
                        b"dependency" if in_dependencies => {
                            if !current_group_id.is_empty() && !current_artifact_id.is_empty() && !current_version.is_empty() {
                                packages.push(Package {
                                    name: format!("{}:{}", current_group_id, current_artifact_id),
                                    version: current_version.clone(),
                                    ecosystem: Ecosystem::Maven,
                                    source_file: file_path.to_path_buf(),
                                });
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::Text(e)) if in_dependencies => {
                    let _text = e.unescape().unwrap().into_owned();
                    // This is a simplified approach - in reality, we'd need to track which element we're in
                    // For now, we'll use a heuristic based on position
                }
                Ok(Event::Empty(ref e)) if in_dependencies => {
                    // Handle self-closing tags within dependency
                    match e.name().as_ref() {
                        b"groupId" => {
                            if let Some(value) = self.extract_text_content(&mut reader, &mut buf)? {
                                current_group_id = value;
                            }
                        }
                        b"artifactId" => {
                            if let Some(value) = self.extract_text_content(&mut reader, &mut buf)? {
                                current_artifact_id = value;
                            }
                        }
                        b"version" => {
                            if let Some(value) = self.extract_text_content(&mut reader, &mut buf)? {
                                current_version = value;
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(VulfyError::Xml(e.into())),
                _ => {}
            }
            buf.clear();
        }

        // Fallback: Simple regex-based parsing for basic cases
        if packages.is_empty() {
            packages = self.parse_pom_xml_fallback(content, file_path).await?;
        }

        Ok(packages)
    }

    fn extract_text_content(&self, reader: &mut Reader<&[u8]>, buf: &mut Vec<u8>) -> VulfyResult<Option<String>> {
        match reader.read_event_into(buf) {
            Ok(Event::Text(e)) => {
                Ok(Some(e.unescape().unwrap().into_owned()))
            }
            _ => Ok(None)
        }
    }

    async fn parse_pom_xml_fallback(&self, content: &str, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let mut packages = Vec::new();
        
        // Simple regex-like parsing for basic dependency extraction
        let lines: Vec<&str> = content.lines().collect();
        let mut i = 0;
        
        while i < lines.len() {
            let line = lines[i].trim();
            
            if line.contains("<dependency>") {
                let mut group_id = String::new();
                let mut artifact_id = String::new();
                let mut version = String::new();
                
                // Look ahead for dependency info
                let mut j = i + 1;
                while j < lines.len() && !lines[j].trim().contains("</dependency>") {
                    let dep_line = lines[j].trim();
                    
                    if dep_line.contains("<groupId>") {
                        group_id = self.extract_xml_value(dep_line, "groupId");
                    } else if dep_line.contains("<artifactId>") {
                        artifact_id = self.extract_xml_value(dep_line, "artifactId");
                    } else if dep_line.contains("<version>") {
                        version = self.extract_xml_value(dep_line, "version");
                    }
                    
                    j += 1;
                }
                
                if !group_id.is_empty() && !artifact_id.is_empty() && !version.is_empty() {
                    packages.push(Package {
                        name: format!("{}:{}", group_id, artifact_id),
                        version,
                        ecosystem: Ecosystem::Maven,
                        source_file: file_path.to_path_buf(),
                    });
                }
                
                i = j;
            } else {
                i += 1;
            }
        }
        
        Ok(packages)
    }

    fn extract_xml_value(&self, line: &str, tag: &str) -> String {
        let start_tag = format!("<{}>", tag);
        let end_tag = format!("</{}>", tag);
        
        if let (Some(start), Some(end)) = (line.find(&start_tag), line.find(&end_tag)) {
            let start_pos = start + start_tag.len();
            if start_pos < end {
                return line[start_pos..end].trim().to_string();
            }
        }
        
        String::new()
    }

    async fn parse_gradle_build(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let mut packages = Vec::new();

        // Parse Gradle dependencies from build.gradle or build.gradle.kts
        let lines: Vec<&str> = content.lines().collect();
        let mut in_dependencies = false;

        for line in lines {
            let line = line.trim();
            
            if line.contains("dependencies") && line.contains('{') {
                in_dependencies = true;
                continue;
            } else if in_dependencies && line.contains('}') {
                in_dependencies = false;
                continue;
            }

            if in_dependencies {
                if let Some(dependency) = self.parse_gradle_dependency_line(line) {
                    packages.push(Package {
                        name: dependency.0,
                        version: dependency.1,
                        ecosystem: Ecosystem::Maven,
                        source_file: file_path.to_path_buf(),
                    });
                }
            }
        }

        Ok(packages)
    }

    async fn parse_ivy_xml(&self, file_path: &Path) -> VulfyResult<Vec<Package>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let mut packages = Vec::new();

        // Simple XML parsing for ivy.xml dependencies
        for line in content.lines() {
            let line = line.trim();
            if line.contains("<dependency") && (line.contains("org=") || line.contains("name=")) {
                if let Some(dependency) = self.parse_ivy_dependency_line(line) {
                    packages.push(Package {
                        name: dependency.0,
                        version: dependency.1,
                        ecosystem: Ecosystem::Maven,
                        source_file: file_path.to_path_buf(),
                    });
                }
            }
        }

        Ok(packages)
    }

    fn parse_gradle_dependency_line(&self, line: &str) -> Option<(String, String)> {
        // Parse Gradle dependency formats:
        // implementation 'group:artifact:version'
        // implementation "group:artifact:version"
        // implementation group: 'group', name: 'artifact', version: 'version'
        
        let line = line.trim();
        
        // Skip comments and non-dependency lines
        if line.starts_with("//") || line.starts_with("/*") || !line.contains("'") && !line.contains('"') {
            return None;
        }

        // Format: implementation 'group:artifact:version'
        if let Some(quote_start) = line.find('\'').or_else(|| line.find('"')) {
            let quote_char = line.chars().nth(quote_start).unwrap();
            if let Some(quote_end) = line[quote_start + 1..].find(quote_char) {
                let dependency_str = &line[quote_start + 1..quote_start + 1 + quote_end];
                let parts: Vec<&str> = dependency_str.split(':').collect();
                
                if parts.len() >= 3 {
                    let group = parts[0];
                    let artifact = parts[1];
                    let version = parts[2];
                    return Some((format!("{}:{}", group, artifact), version.to_string()));
                }
            }
        }

        // Format: implementation group: 'group', name: 'artifact', version: 'version'
        if line.contains("group:") && line.contains("name:") && line.contains("version:") {
            let group = self.extract_gradle_property(line, "group");
            let name = self.extract_gradle_property(line, "name");
            let version = self.extract_gradle_property(line, "version");
            
            if !group.is_empty() && !name.is_empty() && !version.is_empty() {
                return Some((format!("{}:{}", group, name), version));
            }
        }

        None
    }

    fn parse_ivy_dependency_line(&self, line: &str) -> Option<(String, String)> {
        // Parse ivy.xml dependency format:
        // <dependency org="group" name="artifact" rev="version"/>
        
        let org = self.extract_xml_attribute(line, "org");
        let name = self.extract_xml_attribute(line, "name");
        let rev = self.extract_xml_attribute(line, "rev");
        
        if !org.is_empty() && !name.is_empty() && !rev.is_empty() {
            Some((format!("{}:{}", org, name), rev))
        } else {
            None
        }
    }

    fn extract_gradle_property(&self, line: &str, property: &str) -> String {
        let pattern = format!("{}:", property);
        if let Some(start) = line.find(&pattern) {
            let start_pos = start + pattern.len();
            let rest = &line[start_pos..].trim();
            
            // Extract quoted value
            if let Some(quote_start) = rest.find('\'').or_else(|| rest.find('"')) {
                let quote_char = rest.chars().nth(quote_start).unwrap();
                if let Some(quote_end) = rest[quote_start + 1..].find(quote_char) {
                    return rest[quote_start + 1..quote_start + 1 + quote_end].to_string();
                }
            }
        }
        String::new()
    }

    fn extract_xml_attribute(&self, line: &str, attr: &str) -> String {
        let pattern = format!("{}=\"", attr);
        if let Some(start) = line.find(&pattern) {
            let start_pos = start + pattern.len();
            if let Some(end) = line[start_pos..].find('"') {
                return line[start_pos..start_pos + end].to_string();
            }
        }
        String::new()
    }
} 