use std::ffi::OsStr;
use std::path::Path;

use clap::Arg;

fn main() {
    env_logger::init();
    let args = clap::App::new("trrr")
        .arg(
            Arg::with_name("exe")
                .index(1)
                .required(true)
                .help("Exe to be launched")
        )
        .arg(
            Arg::with_name("dll")
                .index(2)
                .multiple(true)
                .required(true)
                .help("DLLs to be injected")
        )
        .arg(
            Arg::with_name("args")
                .short("a")
                .long("args")
                .help("Arguments to the child process")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("function")
                .short("f")
                .long("function")
                .default_value("Initialize")
                .help("Function to call")
        )
        .arg(
            Arg::with_name("module")
                .short("m")
                .long("module")
                .help("Modules to hook for injection.\n\
                       Including file extension, not including path.\n\
                       E.g. `-m program.exe` `-m library.dll`.\n\
                       Defaults to just the exe.")
                .multiple(true)
                .takes_value(true)
        )
        .arg(
            Arg::with_name("cwd")
                .long("cwd")
                .help("Set the working directory of process")
        )
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .help("Print details about steps being taken")
        )
        .get_matches();

    let verbose = args.is_present("verbose");
    let exe = Path::new(args.value_of_os("exe").unwrap());
    let dlls = args.values_of_os("dll").unwrap().collect::<Vec<_>>();
    let child_args = args.value_of_os("args").unwrap_or(OsStr::new(""));
    let cwd = args.value_of_os("cwd").map(Path::new);
    let func = args.value_of_lossy("function").unwrap();
    if verbose { println!("Creating process..."); }
    let inject_modules = if let Some(modules) = args.values_of_os("module") {
        modules.collect()
    } else {
        let exe_filename = match exe.file_name() {
            Some(s) => s,
            None => {
                println!("No file name for path {}", exe.display());
                return;
            }
        };
        vec![exe_filename]
    };
    let mut process = trrr::Process::create(exe, child_args, cwd, &[], &inject_modules)
        .expect("Process creation failed");

    if verbose {
        println!("Injecting {} dlls", dlls.len());
        for dll in &dlls {
            println!("  {}", Path::new(dll).display());
        }
    }
    let dlls = dlls.into_iter()
        .map(|n| (n, func.as_bytes().into()))
        .collect::<Vec<(&OsStr, Vec<u8>)>>();
    let inject_thread = match process.inject(&dlls) {
        Err(e) => {
            println!("Error injecting dlls: {}", e);
            process.terminate(1);
            return;
        }
        Ok(t) => t,
    };
    if verbose { println!("Running process.") }
    if let Err(e) = inject_thread.run() {
        println!("Error on running inject thread: {}", e);
        process.terminate(1);
        return;
    }
}
