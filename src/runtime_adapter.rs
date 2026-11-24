//! Fixed-command, transparent runtime adapters for repository-native tests.
//! Model-provided shell strings are never evaluated. Runtime code is isolated
//! with Bubblewrap when available; an explicit override is required otherwise.

use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    env, fs,
    io::Write,
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
};

fn clean_target(raw:&str)->Result<String,String>{
    let t=raw.trim();
    if t.is_empty()||t.len()>300||t.starts_with('/')||t.contains("..")
        ||!t.chars().all(|c|c.is_ascii_alphanumeric()||"/._:-[]".contains(c)){
        return Err("invalid adapter target".into());
    }
    Ok(t.to_string())
}

fn resolve_binary(binary:&str)->Option<PathBuf>{
    if binary.starts_with("./"){return None;}
    let candidates=[
        PathBuf::from(format!("/usr/bin/{binary}")),
        PathBuf::from(format!("/usr/local/bin/{binary}")),
        PathBuf::from(format!("/bin/{binary}")),
        PathBuf::from(format!("/home/user/.cargo/bin/{binary}")),
    ];
    if let Some(path)=candidates.into_iter().find(|p|p.is_file()){return Some(path);}
    Command::new("sh").arg("-c").arg("command -v \"$1\"")
        .arg("alewo-adapter").arg(binary).output().ok()
        .filter(|o|o.status.success()).and_then(|o|{
            let path=PathBuf::from(String::from_utf8_lossy(&o.stdout).trim());
            path.is_file().then_some(path)
        })
}

fn present(binary:&str)->bool{resolve_binary(binary).is_some()}

fn unsafe_runtime_opt_in()->bool{
    env::var("ALEWO_ALLOW_UNSANDBOXED_RUNTIME").ok().as_deref()==Some("1")
}

pub fn discover(root:&Path)->Vec<&'static str>{
    if !present("bwrap")&&!unsafe_runtime_opt_in(){return Vec::new();}
    let mut out=Vec::new();
    let checks=[
        ("cargo_test","Cargo.toml","cargo"),
        ("go_test","go.mod","go"),
        ("pytest","pyproject.toml","python3"),
        ("pytest","pytest.ini","python3"),
        ("node_test","package.json","node"),
        ("maven_test","pom.xml","mvn"),
        ("gradle_test","gradlew","./gradlew"),
        ("dotnet_test","", "dotnet"),
        ("php_file","", "php"),
        ("python_file","", "python3"),
        ("ruby_file","Gemfile","ruby"),
        ("bash_file","", "bash"),
        ("make_test","Makefile","make"),
        ("ctest","CMakeLists.txt","ctest"),
        ("c_asan_file","", "gcc"),
        ("cpp_asan_file","", "g++"),
    ];
    for (adapter,manifest,binary) in checks{
        let manifest_ok=manifest.is_empty()||root.join(manifest).exists();
        let binary_ok=if binary.starts_with("./"){root.join(&binary[2..]).is_file()}else{present(binary)};
        if manifest_ok&&binary_ok&&!out.contains(&adapter){out.push(adapter);}
    }
    out.push("native_binary");
    out
}

fn bin(name:&str)->Result<PathBuf,String>{
    resolve_binary(name).ok_or_else(||format!("runtime binary not found: {name}"))
}

fn command_for(root:&Path,adapter:&str,target:&str)->Result<(PathBuf,Vec<String>),String>{
    let t=clean_target(target)?;
    match adapter{
        "cargo_test"=>{
            if !root.join("Cargo.toml").is_file(){return Err("Cargo.toml not found".into());}
            let mut a=vec!["test".into(),"--release".into()];
            if t!="all"{a.push(t);}
            Ok((bin("cargo")?,a))
        },
        "go_test"=>{
            if !root.join("go.mod").is_file(){return Err("go.mod not found".into());}
            Ok((bin("go")?,vec!["test".into(),if t=="all"{"./...".into()}else{t}]))
        },
        "pytest"=>Ok((bin("python3")?,vec!["-m".into(),"pytest".into(),t,"-q".into()])),
        "node_test"=>Ok((bin("node")?,vec!["--test".into(),t])),
        "maven_test"=>Ok((bin("mvn")?,vec!["-q".into(),format!("-Dtest={t}"),"test".into()])),
        "gradle_test"=>{
            let gradle=root.join("gradlew");
            if !gradle.is_file(){return Err("gradlew not found".into());}
            Ok((gradle,vec!["test".into(),"--tests".into(),t]))
        },
        "dotnet_test"=>Ok((bin("dotnet")?,vec!["test".into(),"--filter".into(),t])),
        "make_test"=>{
            if !root.join("Makefile").is_file()&&!root.join("makefile").is_file(){
                return Err("Makefile not found".into());
            }
            Ok((bin("make")?,vec!["-j1".into(),t]))
        },
        "ctest"=>{
            let test_dir=if root.join("build/CTestTestfile.cmake").is_file(){
                root.join("build")
            }else if root.join("CTestTestfile.cmake").is_file(){root.to_path_buf()}
            else{return Err("CTestTestfile.cmake not found in root or build/".into());};
            Ok((bin("ctest")?,vec!["--test-dir".into(),test_dir.to_string_lossy().into_owned(),
                "-R".into(),t,"--output-on-failure".into()]))
        },
        "native_binary"=>{
            let path=crate::agent::safe(root,&t)?;
            if !path.is_file(){return Err("native binary target must be an existing file".into());}
            Ok((path,Vec::new()))
        },
        "c_asan_file"|"cpp_asan_file"=>{
            let path=crate::agent::safe(root,&t)?;
            if !path.is_file(){return Err("sanitizer target must be an existing source file".into());}
            let compiler=if adapter=="c_asan_file"{
                resolve_binary("clang").or_else(||resolve_binary("gcc"))
            }else{resolve_binary("clang++").or_else(||resolve_binary("g++"))}
                .ok_or("no C/C++ compiler found")?;
            let script="set -eu; out=/tmp/alewo-sanitized-test; \"$1\" -fsanitize=address,undefined -fno-omit-frame-pointer -O1 -g \"$2\" -o \"$out\"; \"$out\"";
            Ok((bin("sh")?,vec!["-c".into(),script.into(),"alewo-sanitizer".into(),
                compiler.to_string_lossy().into_owned(),path.to_string_lossy().into_owned()]))
        },
        "php_file"|"python_file"|"ruby_file"|"bash_file"=>{
            let path=crate::agent::safe(root,&t)?;
            if !path.is_file(){return Err("adapter target must be an existing file".into());}
            let binary=match adapter{
                "php_file"=>bin("php")?,"python_file"=>bin("python3")?,
                "ruby_file"=>bin("ruby")?,_=>bin("bash")?
            };
            let mut args=Vec::new();
            if adapter=="php_file"{args.extend(["-n".into(),"-d".into(),"allow_url_fopen=0".into()]);}
            if adapter=="python_file"{args.push("-I".into());}
            args.push(path.to_string_lossy().into_owned());
            Ok((binary,args))
        },
        _=>Err(format!("unsupported runtime adapter: {adapter}"))
    }
}

fn parent_dirs(path:&Path)->Vec<PathBuf>{
    let mut out=Vec::new();let mut current=PathBuf::from("/");
    let Some(parent)=path.parent() else{return out;};
    for component in parent.components(){
        if let Component::Normal(part)=component{
            current.push(part);out.push(current.clone());
        }
    }
    out
}

fn secret_files(root:&Path)->Vec<PathBuf>{
    let mut out=Vec::new();
    if let Ok(entries)=fs::read_dir(root){
        for entry in entries.flatten(){
            let name=entry.file_name().to_string_lossy().to_ascii_lowercase();
            if entry.path().is_file()&&(name.starts_with(".env")||
                matches!(name.as_str(),".npmrc"|".netrc"|".pypirc")){
                out.push(entry.path());
            }
        }
    }
    for rel in ["data/memory.sqlite","data/memory.sqlite-wal","data/memory.sqlite-shm"]{
        let path=root.join(rel);if path.is_file(){out.push(path);}
    }
    for path in ["/home/user/.cargo/credentials","/home/user/.cargo/credentials.toml"]{
        let path=PathBuf::from(path);if path.is_file(){out.push(path);}
    }
    out
}

pub fn run(root:&Path,spec:&Value)->Result<Value,String>{
    let adapter=spec["adapter"].as_str().unwrap_or("php_file");
    let target=spec["target"].as_str().or_else(||spec["path"].as_str()).unwrap_or("");
    let (binary,args)=command_for(root,adapter,target)?;
    let timeout=spec["timeout_seconds"].as_u64().unwrap_or(60).clamp(1,300);
    let timeout_bin=bin("timeout")?;
    let bubblewrap=resolve_binary("bwrap");
    if bubblewrap.is_none()&&!unsafe_runtime_opt_in(){
        return Err("runtime execution refused: Bubblewrap is unavailable; set ALEWO_ALLOW_UNSANDBOXED_RUNTIME=1 only inside an independently isolated disposable environment".into());
    }
    let mut command=Command::new(timeout_bin);
    command.arg(timeout.to_string());
    let sandbox=if let Some(bwrap)=bubblewrap{
        command.arg(bwrap).args([
            "--die-with-parent","--new-session","--unshare-net","--clearenv",
            "--setenv","PATH","/home/user/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "--setenv","LANG","C.UTF-8","--setenv","LC_ALL","C.UTF-8",
            "--setenv","CARGO_HOME","/home/user/.cargo",
            "--setenv","RUSTUP_HOME","/home/user/.rustup",
            "--setenv","CARGO_TARGET_DIR","/tmp/alewo-cargo-target",
            "--setenv","PYTHONDONTWRITEBYTECODE","1",
        ]);
        for base in ["/usr","/usr/local","/bin","/lib","/lib64","/etc"]{
            let path=Path::new(base);
            if path.exists(){command.arg("--ro-bind").arg(path).arg(path);}
        }
        command.args(["--dev","/dev","--proc","/proc","--tmpfs","/tmp"]);
        let tool_dirs=["/home/user/.cargo","/home/user/.rustup"].into_iter()
            .map(PathBuf::from).filter(|p|p.is_dir()).collect::<Vec<_>>();
        let mut dirs=BTreeSet::new();
        for path in std::iter::once(root.to_path_buf()).chain(tool_dirs.iter().cloned()){
            dirs.extend(parent_dirs(&path));
        }
        for dir in dirs{command.arg("--dir").arg(dir);}
        command.arg("--ro-bind").arg(root).arg(root);
        for path in &tool_dirs{command.arg("--ro-bind").arg(path).arg(path);}
        for path in secret_files(root){
            command.arg("--ro-bind").arg("/dev/null").arg(path);
        }
        command.arg("--chdir").arg(root).arg("--").arg(&binary).args(&args);
        "bubblewrap_ro_no_network_env_clear"
    }else{
        command.arg(&binary).args(&args).current_dir(root);
        "operator_opt_in_unsandboxed"
    };
    command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child=command.spawn().map_err(|e|format!("adapter spawn failed: {e}"))?;
    if let Some(input)=spec.get("input").filter(|v|!v.is_null()){
        let bytes=serde_json::to_vec(input).map_err(|e|e.to_string())?;
        if bytes.len()>64_000{return Err("runtime input exceeds 64KB".into());}
        if let Some(mut stdin)=child.stdin.take(){stdin.write_all(&bytes).map_err(|e|e.to_string())?;}
    }
    let output=child.wait_with_output().map_err(|e|e.to_string())?;
    let stdout=String::from_utf8_lossy(&output.stdout).chars().take(4000).collect::<String>();
    let stderr=String::from_utf8_lossy(&output.stderr).chars().take(2400).collect::<String>();
    Ok(json!({
        "adapter":adapter,"target":target,"binary":binary,
        "args":args,"exit":output.status.code(),"success":output.status.success(),
        "timed_out":output.status.code()==Some(124),
        "stdout":stdout,"stderr":stderr,"transparent":true,
        "sandbox":sandbox,"network":if sandbox.starts_with("bubblewrap"){"denied"}else{"operator_environment"}
    }))
}

#[cfg(test)]
mod tests{
    use super::*;
    use std::time::{SystemTime,UNIX_EPOCH};

    #[test]fn rejects_shell_metacharacters(){
        assert!(clean_target("tests/x.rs;curl bad").is_err());
        assert!(clean_target("../escape").is_err());
        assert_eq!(clean_target("tests/case_1.py").unwrap(),"tests/case_1.py");
    }

    #[test]fn c_sanitizer_adapter_compiles_and_runs_in_sandbox(){
        if !present("bwrap")||(!present("clang")&&!present("gcc")){return;}
        let dir=env::temp_dir().join(format!("alewo-c-asan-{}",
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir_all(dir.join("tests")).unwrap();
        fs::write(dir.join("tests/check.c"),
            "#include <stdio.h>\nint main(void){puts(\"{\\\"native\\\":\\\"ok\\\"}\");return 0;}\n").unwrap();
        let result=run(&dir,&json!({"adapter":"c_asan_file","target":"tests/check.c"})).unwrap();
        assert_eq!(result["exit"],0);
        assert!(result["stdout"].as_str().unwrap().contains("\"native\":\"ok\""));
        assert_eq!(result["network"],"denied");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]fn sandbox_hides_project_env_file(){
        if !present("bwrap")||!present("php"){return;}
        let dir=env::temp_dir().join(format!("alewo-sandbox-{}",
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir_all(dir.join("tests")).unwrap();
        fs::write(dir.join(".env"),"NVIDIA_API_KEY=secret").unwrap();
        fs::write(dir.join("tests/check.php"),
            "<?php echo file_exists('.env') ? filesize('.env') : -1;").unwrap();
        let result=run(&dir,&json!({"adapter":"php_file","target":"tests/check.php"})).unwrap();
        assert_eq!(result["stdout"],"0");
        assert_eq!(result["sandbox"],"bubblewrap_ro_no_network_env_clear");
        fs::remove_dir_all(dir).unwrap();
    }
}
