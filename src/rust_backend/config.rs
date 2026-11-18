//! Compile a complete Rust WAF generation or validate it against a staged filesystem.
mod diagnostics;

use std::{
    collections::{BTreeMap, HashSet},
    fmt, fs,
    path::{Component, Path, PathBuf},
    sync::{Arc, OnceLock},
};

use flate2::read::GzDecoder;
use glob::Pattern;
use haproxy_spoa_hub_plugin_api::Diagnostic;
use tempfile::TempDir;
use zentinel_modsec::{
    CompiledRuleset, Error, ModSecurity,
    engine::phase::Phase,
    error::SourceLocation,
    parser::{Directive, OperatorName, Parser, ParserHost},
};

use super::transaction::RuleCatalog;
use crate::config::PluginConfig;

pub(crate) struct Waf {
    pub(super) engine: ModSecurity,
    pub(super) catalog: Arc<RuleCatalog>,
}
impl fmt::Debug for Waf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Waf")
            .field("rule_count", &self.rule_count())
            .finish()
    }
}
impl Waf {
    pub(crate) fn rule_count(&self) -> i32 {
        self.engine.rule_count().try_into().unwrap_or(i32::MAX)
    }
}

#[cfg(test)]
static ACTIVE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
#[cfg(test)]
pub(crate) fn active_count() -> i32 {
    ACTIVE.load(std::sync::atomic::Ordering::SeqCst)
}
#[cfg(test)]
impl Drop for Waf {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

pub(crate) fn create_waf(
    directives: &str,
    directives_file: Option<&str>,
    req_body_limit: i32,
    req_body_mem_limit: i32,
    resp_body_limit: i32,
    config: &PluginConfig,
) -> Result<Waf, String> {
    let files = RuleFiles::new("", false)?;
    let mut parser = parse(directives, directives_file, &files)
        .map_err(|e| files.logical_message(&e.to_string()))?;
    // Coraza applies positive connector limits after every policy directive.
    let mut limits = String::new();
    if req_body_limit > 0 {
        let mem = if req_body_mem_limit > 0 {
            req_body_mem_limit.min(req_body_limit)
        } else {
            req_body_limit
        };
        limits.push_str(&format!(
            "SecRequestBodyLimit {req_body_limit}\nSecRequestBodyInMemoryLimit {mem}\n"
        ));
    }
    if resp_body_limit > 0 {
        limits.push_str(&format!("SecResponseBodyLimit {resp_body_limit}\n"));
    }
    parser.parse(&limits).map_err(|e| e.to_string())?;
    let engine = compile(parser, &files).map_err(|e| files.logical_message(&e.to_string()))?;
    let catalog = Arc::new(RuleCatalog::new(&engine, config));
    #[cfg(test)]
    ACTIVE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    Ok(Waf { engine, catalog })
}

pub(crate) fn validate_directives(directives: &str, staged_files: &str) -> Vec<Diagnostic> {
    let files = match RuleFiles::new(staged_files, true) {
        Ok(files) => files,
        Err(message) => return vec![Diagnostic::error(0, 0, message)],
    };
    match parse(directives, None, &files).and_then(|parser| compile(parser, &files)) {
        Ok(_) => Vec::new(),
        Err(error) => {
            let (line, column) = if let Error::Parse { location, .. } = &error {
                let mut fields = location.rsplit(':');
                let col = fields.next().and_then(|s| s.parse().ok()).unwrap_or(0);
                (fields.next().and_then(|s| s.parse().ok()).unwrap_or(0), col)
            } else {
                (0, 0)
            };
            vec![Diagnostic::error(
                line,
                column,
                files.logical_message(&error.to_string()),
            )]
        }
    }
}

fn parse(
    directives: &str,
    path: Option<&str>,
    files: &Arc<RuleFiles>,
) -> zentinel_modsec::Result<Parser> {
    if directives.as_bytes().contains(&0) || path.is_some_and(|p| p.as_bytes().contains(&0)) {
        return Err(config_error("directives contain interior null byte"));
    }
    let mut parser = Parser::new().with_host(Arc::clone(files) as Arc<dyn ParserHost>);
    parser.parse(directives)?;
    if let Some(path) = path.filter(|s| !s.is_empty()) {
        for file in files.includes(None, Path::new(path))? {
            parser.parse_file(&file)?;
        }
    }
    Ok(parser)
}

fn compile(parser: Parser, files: &RuleFiles) -> zentinel_modsec::Result<ModSecurity> {
    let mut directives = parser.into_directives();
    if let Some(staged) = &files.staged {
        for directive in &mut directives {
            let Directive::SecRule(rule) = directive else {
                continue;
            };
            if rule.operator.name != OperatorName::ValidateSchema {
                continue;
            }
            // Schema files are confined to the declaring rule's directory.
            // Keep the relative operand for the engine's confinement checks,
            // even when an inline or OS rule refers to a staged schema.
            let original = files.base(rule.location.file.as_deref());
            let staged_dir = staged.path().join(unroot(&original));
            let root = if staged_dir.join(&rule.operator.argument).is_file() {
                staged_dir
            } else {
                original
            };
            let filename = rule
                .location
                .file
                .as_deref()
                .and_then(Path::file_name)
                .unwrap_or_else(|| std::ffi::OsStr::new("inline.conf"));
            rule.location.file = Some(root.join(filename));
        }
    }
    let rules = diagnostics::checked(|| CompiledRuleset::compile_multiphase(directives))?;
    for phase in Phase::ALL {
        for rule in rules.rules_for_phase(phase) {
            if rule.operator.name() == "noMatch" && rule.operator_spec.name != OperatorName::NoMatch
            {
                return Err(config_error(format!(
                    "rule {}: unsupported or invalid {:?} operator",
                    rule.id.as_deref().unwrap_or("(chain)"),
                    rule.operator_spec.name
                )));
            }
        }
    }
    let mut engine = ModSecurity::new(rules);
    engine.set_autodetect_structured_request_bodies(false);
    Ok(engine)
}

fn config_error(message: impl Into<String>) -> Error {
    Error::Config {
        message: message.into(),
    }
}

const ASSETS: &[u8] = include_bytes!("../../resources/crs/rules.tar.gz");

/// Compilers receive real source paths so rule-relative phrase lists and schema
/// references resolve through the engine's ordinary file loader. Staged names
/// are projected under a private directory and never written to their OS path.
struct RuleFiles {
    embedded: OnceLock<Result<TempDir, String>>,
    staged: Option<TempDir>,
    staged_names: BTreeMap<PathBuf, PathBuf>,
    admission: bool,
}

impl RuleFiles {
    fn new(staged_json: &str, admission: bool) -> Result<Arc<Self>, String> {
        let files: BTreeMap<String, String> = if staged_json.trim().is_empty() {
            BTreeMap::new()
        } else {
            serde_json::from_str(staged_json).map_err(|e| format!("parsing staged files: {e}"))?
        };
        let mut staged_names = BTreeMap::new();
        let staged = if files.is_empty() {
            None
        } else {
            let root = tempfile::tempdir().map_err(|e| e.to_string())?;
            for (name, contents) in files {
                let relative = unroot(Path::new(&name));
                if relative.as_os_str().is_empty() {
                    continue;
                }
                let path = root.path().join(relative);
                if staged_names
                    .insert(path.clone(), PathBuf::from(&name))
                    .is_some()
                {
                    return Err(format!(
                        "duplicate staged file after path normalization: {name}"
                    ));
                }
                fs::create_dir_all(path.parent().unwrap())
                    .and_then(|()| fs::write(path, contents))
                    .map_err(|e| format!("staging {name}: {e}"))?;
            }
            Some(root)
        };
        Ok(Arc::new(Self {
            embedded: OnceLock::new(),
            staged,
            staged_names,
            admission,
        }))
    }

    fn embedded_root(&self) -> zentinel_modsec::Result<&Path> {
        self.embedded
            .get_or_init(|| {
                let root = tempfile::tempdir().map_err(|e| e.to_string())?;
                tar::Archive::new(GzDecoder::new(ASSETS))
                    .unpack(root.path())
                    .map_err(|e| e.to_string())?;
                Ok(root)
            })
            .as_ref()
            .map(TempDir::path)
            .map_err(|e| config_error(format!("opening embedded CRS: {e}")))
    }

    /// Both Includes and rule data operands can address the embedded namespace.
    fn embedded_base(&self, operand: &Path) -> zentinel_modsec::Result<Option<&Path>> {
        if !operand.to_string_lossy().starts_with('@') {
            return Ok(None);
        }
        if operand.components().any(|c| c == Component::ParentDir) {
            return Err(config_error("invalid embedded resource path"));
        }
        self.embedded_root().map(Some)
    }

    fn logical_message(&self, message: &str) -> String {
        let mut message = message.to_string();
        if let Some(root) = &self.staged {
            message = message.replace(&format!("{}/", root.path().display()), "/");
        }
        if let Some(Ok(root)) = self.embedded.get() {
            message = message.replace(&format!("{}/", root.path().display()), "");
        }
        message
    }

    fn base(&self, file: Option<&Path>) -> PathBuf {
        file.map(|path| self.staged_names.get(path).map_or(path, PathBuf::as_path))
            .and_then(Path::parent)
            .unwrap_or(Path::new(""))
            .to_owned()
    }
}

fn unroot(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => out.push(name),
            Component::ParentDir => {
                out.pop();
            }
            _ => {}
        }
    }
    out
}

/// Escape the directory separately so brackets in a declaring file's path
/// remain literal even when the Include operand contains a glob.
fn file_matches(base: &Path, operand: &Path) -> zentinel_modsec::Result<Vec<PathBuf>> {
    let name = operand
        .to_str()
        .ok_or_else(|| config_error("invalid UTF-8 Include operand"))?;
    if !name.contains(['*', '?', '[']) {
        let path = base.join(operand);
        return Ok(
            if path.try_exists().map_err(|e| config_error(e.to_string()))? {
                vec![path]
            } else {
                Vec::new()
            },
        );
    }
    let escaped = Pattern::escape(&base.to_string_lossy());
    let pattern = Path::new(&escaped).join(operand);
    glob::glob(&pattern.to_string_lossy())
        .map_err(|e| config_error(e.to_string()))?
        .filter_map(|result| match result {
            Ok(path) if !path.is_file() => None,
            other => Some(other.map_err(|e| config_error(e.to_string()))),
        })
        .collect()
}

impl ParserHost for RuleFiles {
    fn includes(
        &self,
        file: Option<&Path>,
        operand: &Path,
    ) -> zentinel_modsec::Result<Vec<PathBuf>> {
        let base = self.base(file);
        let mut matches = Vec::new();
        if let Some(embedded) = self.embedded_base(operand)? {
            matches = file_matches(embedded, operand)?;
        } else {
            let logical = base.join(operand);
            let mut shadowed = HashSet::new();
            if let Some(staged) = &self.staged {
                for path in file_matches(staged.path(), &unroot(&logical))? {
                    shadowed.insert(path.strip_prefix(staged.path()).unwrap().to_owned());
                    matches.push(path);
                }
            }
            for path in file_matches(&base, operand)? {
                if !shadowed.contains(&unroot(&path)) {
                    matches.push(path);
                }
            }
        }
        if matches.is_empty() {
            let message = format!("Include {} matched no files", base.join(operand).display());
            if self.admission || !operand.to_string_lossy().contains(['*', '?', '[']) {
                return Err(config_error(message));
            }
            log::warn!("{message}");
        }
        Ok(matches)
    }

    fn data_file(&self, file: Option<&Path>, operand: &Path) -> zentinel_modsec::Result<PathBuf> {
        if let Some(embedded) = self.embedded_base(operand)? {
            return Ok(embedded.join(operand));
        }
        let path = self.base(file).join(operand);
        if let Some(staged) = &self.staged {
            let candidate = staged.path().join(unroot(&path));
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
        Ok(path)
    }

    fn unknown_directive(
        &self,
        name: &str,
        argument: &str,
        location: &SourceLocation,
    ) -> zentinel_modsec::Result<()> {
        // The embedded recommended policy sets these Coraza defaults. Audit
        // output is owned by the plugin, which never opens Coraza audit files.
        let bundled = self
            .embedded
            .get()
            .and_then(|v| v.as_ref().ok())
            .is_some_and(|root| {
                location.file.as_deref() == Some(&root.path().join("@coraza.conf-recommended"))
            });
        if bundled
            && matches!(
                name.to_ascii_lowercase().as_str(),
                "secauditengine"
                    | "secauditlogrelevantstatus"
                    | "secauditlogparts"
                    | "secauditlogtype"
                    | "secauditlogformat"
                    | "secdatadir"
            )
        {
            return Ok(());
        }
        if name.eq_ignore_ascii_case("SecRxPreFilter")
            && ["On", "Off"]
                .iter()
                .any(|value| argument.eq_ignore_ascii_case(value))
        {
            return Ok(());
        }
        Err(Error::parse(
            format!("unknown or unsupported directive {name}"),
            location.to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staged_globs_shadow_os_files_and_find_nested_phrase_data() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("policies");
        fs::create_dir(&dir).unwrap();
        let rule = dir.join("request.conf");
        fs::write(&rule, "SecInvalidOnDisk ignored").unwrap();
        fs::write(dir.join("other.conf"), "SecAction \"id:3,phase:1,pass\"").unwrap();
        let staged = serde_json::json!({
            rule.to_str().unwrap(): "Include nested/methods.conf",
            dir.join("nested/methods.conf").to_str().unwrap(): "SecRule REQUEST_METHOD \"@pmFromFile permitted.txt\" \"id:2,phase:1,pass\"",
            dir.join("nested/permitted.txt").to_str().unwrap(): "GET"
        });
        let files = RuleFiles::new(&staged.to_string(), true).unwrap();
        let config = format!("SecRuleEngine On\nInclude {}/*.conf", dir.display());
        let engine = compile(parse(&config, None, &files).unwrap(), &files).unwrap();
        assert_eq!(engine.rule_count(), 2);
        let mut tx = engine.new_transaction();
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert_eq!(tx.matched_rules(), ["2", "3"]);
        assert!(
            fs::read_to_string(rule)
                .unwrap()
                .starts_with("SecInvalidOnDisk")
        );
    }

    #[test]
    fn empty_include_is_an_admission_error_and_diagnostics_keep_the_original_name() {
        let temp = tempfile::tempdir().unwrap();
        let missing = format!("Include {}/*.conf", temp.path().display());
        assert!(
            validate_directives(&missing, "")[0]
                .message
                .contains("matched no files")
        );
        let staged = serde_json::json!({"/staged/policy.conf": "\nSecUnknown 3"});
        let diag = &validate_directives("Include /staged/policy.conf", &staged.to_string())[0];
        assert_eq!(diag.line, 2);
        assert!(diag.message.contains("/staged/policy.conf:2:1"));
    }

    #[test]
    fn phrase_lists_can_address_the_bundle_without_an_include() {
        let input =
            r#"SecRule ARGS "@pmFromFile @owasp_crs/restricted-files.data" "id:1,phase:1,deny""#;
        assert!(validate_directives(input, "").is_empty());
        let missing = input.replace("restricted-files.data", "missing.data");
        assert!(!validate_directives(&missing, "").is_empty());
    }

    #[test]
    fn staged_inline_schema_and_its_companion_are_compiled_before_admission() {
        let staged = serde_json::json!({
            "schema.json": r#"{"$ref":"type.json"}"#,
            "type.json": r#"{"type":"object"}"#,
        });
        let rule = r#"SecRule REQUEST_BODY "@validateSchema schema.json" "id:1,phase:2,deny""#;
        assert!(validate_directives(rule, &staged.to_string()).is_empty());
        let mut incomplete = staged;
        incomplete.as_object_mut().unwrap().remove("type.json");
        assert!(!validate_directives(rule, &incomplete.to_string()).is_empty());
    }

    #[test]
    fn unsupported_controls_and_transformations_are_admission_errors() {
        for rule in [
            r#"SecAction "id:7,phase:1,pass,ctl:unrecognizedOption=On""#,
            r#"SecRule ARGS "@streq x" "id:7,phase:1,deny,t:parityOdd7bit""#,
        ] {
            let diagnostics = validate_directives(rule, "");
            assert_eq!(diagnostics.len(), 1, "{rule}");
            assert!(diagnostics[0].message.contains('7'));
        }
    }

    #[test]
    fn explicit_file_is_appended_after_inline_rules_and_connector_limits_win() {
        let _guard = crate::plugin::TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("last.conf");
        fs::write(&file, "SecRuleEngine On\nSecRequestBodyLimit 200").unwrap();
        let config = PluginConfig::default();
        let waf = create_waf("SecRuleEngine Off", file.to_str(), 12, 20, 30, &config).unwrap();
        let body = waf.engine.ruleset().body_config();
        assert_eq!(body.request_limit, 12);
        assert_eq!(body.request_in_memory_limit, Some(12));
        assert_eq!(body.response_limit, 30);
    }
}
