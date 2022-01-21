//! Trrr, a win32 dll injection library.
//!
//! Trrr allows creating 32-bit Windows processes, which have an external
//! .dll loaded and its initialization function called before the program
//! itself gets to run anything. Injecting to an already running process
//! will also work, as long as the injected dlls work with other threads
//! running during their initialization functions.
//!
//! The injection is done by starting a remote thread, which runs a short
//! assembly stub loading dlls and calling their functions. Any errors
//! get reported back to the parent process via pipe.
//!
//! # Example
//!
//! ```no_run
//! use trrr::Process;
//!
//! let mut process = Process::create("process.exe", "--args=values", None).unwrap();
//! let dlls = [("library.dll", &b"init_dll"[..]), ("other.dll", &b"init_other"[..])];
//! let thread = process.create_inject_thread(&dlls, false).unwrap();
//! if let Err(e) = thread.run() {
//!     println!("Oh no! {}", e);
//!     process.terminate(1);
//!     return;
//! }
//! process.resume().unwrap();
//! process.wait_for_exit().unwrap();
//!
//! ```

#[macro_use] extern crate log;
#[macro_use] extern crate scopeguard;
#[macro_use] extern crate quick_error;

mod nt_api;

use std::{mem, slice, error, fmt};
use std::ffi::OsStr;
use std::path::{Path};
use std::ptr::{null_mut, null, copy_nonoverlapping};
use std::io;

use std::os::windows::ffi::OsStrExt;

use byteorder::{ByteOrder, LittleEndian};

use winapi::um::debugapi::{ContinueDebugEvent, DebugActiveProcessStop, WaitForDebugEvent};
use winapi::um::errhandlingapi::{GetLastError};
use winapi::um::fileapi::{ReadFile};
use winapi::um::handleapi::{CloseHandle, DuplicateHandle};
use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory, VirtualAllocEx};
use winapi::um::minwinbase::{DEBUG_EVENT};
use winapi::um::namedpipeapi::{CreatePipe};
use winapi::um::processenv::{GetEnvironmentStringsW, FreeEnvironmentStringsW};
use winapi::um::processthreadsapi::{
    CreateProcessW, TerminateProcess, GetExitCodeProcess, ResumeThread, GetCurrentProcess,
    GetThreadContext, SetThreadContext, GetProcessId, GetThreadId,
    SuspendThread, PROCESS_INFORMATION, STARTUPINFOW,
};
use winapi::um::synchapi::{WaitForSingleObject};
use winapi::um::minwinbase::{CREATE_THREAD_DEBUG_EVENT, EXIT_THREAD_DEBUG_EVENT};
use winapi::um::winbase::{CREATE_UNICODE_ENVIRONMENT, DEBUG_PROCESS, INFINITE};
use winapi::um::winnt::{
    DUPLICATE_SAME_ACCESS, CONTEXT, CONTEXT_INTEGER, CONTEXT_CONTROL, HANDLE, MEM_COMMIT,
    MEM_RESERVE, PAGE_EXECUTE_READWRITE, PVOID,
};
use winapi::shared::minwindef::{FALSE, FARPROC};
use winapi::shared::winerror::{ERROR_SEM_TIMEOUT};

#[cfg(target_arch = "x86_64")]
use winapi::um::winnt::{WOW64_CONTEXT, WOW64_CONTEXT_INTEGER, WOW64_CONTEXT_CONTROL};
#[cfg(target_arch = "x86_64")]
use winapi::um::winbase::{Wow64GetThreadContext, Wow64SetThreadContext};
#[cfg(all(target_arch = "x86_64", feature = "wow64"))]
use winapi::um::wow64apiset::IsWow64Process;

use self::Error::*;

/// Winapi error.
#[derive(Debug)]
pub struct WinErr {
    pub err: io::Error,
    pub desc: String,
}

impl WinErr {
    pub fn desc(&self) -> String {
        format!("{}: {}", self.desc, self.err)
    }
}

/// Generic error.
#[derive(Debug)]
pub enum Error {
    /// A Windows API call failed.
    Win(WinErr),
    /// Something else went wrong.
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Win(ref win) => write!(fmt, "{}", win.desc()),
            Other(ref desc) => write!(fmt, "{}", desc),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Win(_) => "Windows api error",
            Other(_) => "Misc error",
        }
    }
}

fn win_err<T, S: Into<String>>(desc: S) -> Result<T, Error> {
    Err(Win(WinErr {
        err: io::Error::last_os_error(),
        desc: desc.into(),
    }))
}

static ASSEMBLY_32: &'static [u8] = &[
    0x55,               //     push ebp
    0x89, 0xe5,         //     mov ebp, esp
    0x60,               //     pushad
    0x31, 0xff,         //     xor edi, edi                ; Dll index
    0x8b, 0x75, 0x08,   //     mov esi, [ebp + 8]          ; Data pointer
    0x8b, 0x5e, 0x24,   //     mov ebx, [esi + 24]         ; Dll name table
    0x3b, 0x7e, 0x20,   //     cmp edi, [esi + 20]         ; Cmp index, dll_name_count
    0x74, 0x1d,         //     je out
                        // next_dll:
    0xff, 0x34, 0xfb,   //     push dword [ebx + edi * 8]  ; Push dll name
    0xff, 0x16,         //     call [esi + 0]              ; Call LoadLibraryW
    0x85, 0xc0,         //     test eax, eax
    0x74, 0x1f,         //     je load_library_fail
    0xff, 0x74, 0xfb, 0x04, //     push dword [ebx + edi * 8 +4] ; Init function name/ordinal
    0x50,               //     push eax
    0xff, 0x56, 0x04,   //     call [esi + 4]              ; Call GetProcAddress(eax=dll, ecx=ordinal)
    0x85, 0xc0,         //     test eax, eax
    0x74, 0x1c,         //     je func_not_found
    0xff, 0xd0,         //     call eax
    0x47,               //     inc edi
    0x3b, 0x7e, 0x20,   //     cmp edi, [esi + 20]         ; Cmp index, dll_name_count
    0x75, 0xe3,         //     jne next_dll
                        // out:
    0xc7, 0x46, 0x40, 0x00, 0x00, 0x00, 0x00, //     mov [esi + 40], 0
    0x31, 0xdb,         //     xor ebx, ebx
    0xeb, 0x1b,         //     jmp send_result
                        // load_library_fail:
    0xc7, 0x46, 0x40, 0x01, 0x00, 0x00, 0x00, //     mov [esi + 40], 1
    0xeb, 0x07,         //     jmp generic_error
                        // func_not_found:
    0xc7, 0x46, 0x40, 0x02, 0x00, 0x00, 0x00, //     mov [esi + 40], 2
                        // generic_error:
    0xff, 0x56, 0x08,   //     call [esi + 8]              ; GetLastError
    0x89, 0xc3,         //     mov ebx, eax
    0x89, 0x46, 0x44,   //     mov [esi + 44], eax
    0x89, 0x7e, 0x48,   //     mov [esi + 48], edi
                        // send_result:
    0x6a, 0x00,         //     push 0
    0x8d, 0x46, 0x50,   //     lea eax, [esi + 50]         ; Scratch space
    0x50,               //     push eax
    0x6a, 0x0c,         //     push 0xc
    0x8d, 0x46, 0x40,   //     lea eax, [esi + 40]         ; Result buffer
    0x50,               //     push eax
    0xff, 0x76, 0x28,   //     push [esi + 28]             ; Pipe handle
    0xff, 0x56, 0x0c,   //     call [esi + c]              ; WriteFile
    0xff, 0x76, 0x28,   //     push [esi + 28]             ; Pipe handle
    0xff, 0x56, 0x10,   //     call [esi + 10]             ; CloseHandle
    0x89, 0xd8,         //     mov eax, ebx
    0x61,               //     popad
    0x5d,               //     pop ebp
    0xc2, 0x04, 0x00,   //     retn 4
];

// The parameter is set up by this code, so it uses x86-style
// calling convention (argument 1 in [rsp + 8]) instead of the usual one for x86_64,
// letting this and x86 code be closer to each other.
const ASSEMBLY_64: &'static [u8] = &[
    0x55,                   //      push rbp
    0x48, 0x89, 0xe5,       //      mov rbp, rsp
    0x48, 0x81, 0xe4, 0xf0, 0xff, 0xff, 0xff, // and rsp, ffffffff_fffffff0
                            // Stack aligned to 0x10, push 0x50 bytes of registers
    0x50, 0x51, 0x52, 0x53, 0x56, 0x57, // push { rax, rcx, rdx, rbx, rsi, rdi }
    0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, // push { r8, r9, r10, r11 }
    0x48, 0x83, 0xec, 0x30, //      sub rsp, 30                 ; Shadow space + 5th param
                            //                                  ; Align is ok if rsp sub is 0x30
    0x31, 0xff,             //      xor edi, edi                ; Dll index
    0x48, 0x8b, 0x75, 0x10, //      mov rsi, [rbp + 10]         ; Data pointer
    0x48, 0x8b, 0x5e, 0x48, //      mov rbx, [rsi + 48]         ; Dll name table
    0x3b, 0x7e, 0x40,       //      cmp edi, [rsi + 40]         ; Cmp index, dll_name_count
    0x74, 0x2e,             //      je out
                            // next_dll:
    0x89, 0xf9,             //      mov ecx, edi
    0xc1, 0xe1, 0x04,       //      shl ecx, 4
    0x48, 0x8b, 0x0c, 0x0b, //      mov rcx, [rbx + rcx]        ; Dll name
    0xff, 0x16,             //      call [rsi + 0]              ; Call LoadLibraryW
    0x48, 0x85, 0xc0,       //      test rax, rax
    0x74, 0x2a,             //      je load_library_fail
    0x89, 0xf9,             //      mov ecx, edi
    0xc1, 0xe1, 0x04,       //      shl ecx, 4
    0x48, 0x8b, 0x54, 0x0b, 0x08, // mov rdx, [rbx + rcx + 8] ; Init function name/ordinal
    0x48, 0x89, 0xc1,       //      mov rcx, rax
    0xff, 0x56, 0x08,       //      call [rsi + 8]              ; Call GetProcAddress(rcx=dll, rdx=ordinal)
    0x48, 0x85, 0xc0,       //      test rax, rax
    0x74, 0x21,             //      je func_not_found
    0xff, 0xd0,             //      call rax
    0xff, 0xc7,             //      inc edi
    0x3b, 0x7e, 0x40,       //      cmp edi, [rsi + 40]         ; Cmp index, dll_name_count
    0x75, 0xd2,             //      jne next_dll
                            // out:
    0xc7, 0x86, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //     mov [rsi + 80], 0
    0xeb, 0x25,             //      jmp send_result
                            // load_library_fail:
    0xc7, 0x86, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, //     mov [rsi + 80], 1
    0xeb, 0x0a,             //      jmp generic_error
                            // func_not_found:
    0xc7, 0x86, 0x80, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, //     mov [rsi + 80], 2
                            // generic_error:
    0xff, 0x56, 0x10,       //      call [rsi + 10]              ; GetLastError
    0x89, 0x86, 0x88, 0x00, 0x00, 0x00, // mov [rsi + 88], eax
    0x89, 0xbe, 0x90, 0x00, 0x00, 0x00, // mov [rsi + 90], edi
                            // send_result:
    0x48, 0xc7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, // mov [rsp + 20], 0 (Arg5)
    0x4c, 0x8d, 0x8e, 0xa0, 0x00, 0x00, 0x00,   //     lea r9, [rsi + a0]  ; Scratch space (Arg4)
    0x41, 0xb8, 0x18, 0x00, 0x00, 0x00,         //     mov r8d, 18 ; (Arg3, write size)
    0x48, 0x8d, 0x96, 0x80, 0x00, 0x00, 0x00,   //     lea rdx, [rsi + 80] ; Result buffer (Arg2)
    0x48, 0x8b, 0x4e, 0x50, //      mov rcx, [rsi + 50]          ; Pipe handle
    0xff, 0x56, 0x18,       //      call [rsi + 18]               ; WriteFile
    0x48, 0x8b, 0x4e, 0x50, //      mov rcx, [rsi + 50]          ; Pipe handle
    0xff, 0x56, 0x20,       //      call [rsi + 20]               ; CloseHandle
    0x48, 0x83, 0xc4, 0x30, //      add rsp, 30
    0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58, // pop { r11, r10, r9, r8 }
    0x5f, 0x5e, 0x5b, 0x5a, 0x59, 0x58, // pop { rdi, rsi, rbx, rdx, rcx, rax }
    0x48, 0x89, 0xec,       //      mov rsp, rbp
    0x5d,                   //      pop ebp
    0xc2, 0x08, 0x00,       //      retn 8
];

fn make_winapi_str<T: AsRef<OsStr>>(input: T) -> Vec<u16> {
    input.as_ref().encode_wide().chain(Some(0)).collect::<Vec<u16>>()
}

/// A child process.
///
/// Note that if a error happens, you likely wish to call `terminate()` to
/// clean up the process. It is not called automatically when the `Process`
/// is dropped.
pub struct Process<'a> {
    process: HANDLE,
    /// Main thread handle, set only for processes which were created with `Process::create`.
    main_thread: HANDLE,
    inject_modules: &'a [&'a OsStr],
    arch: Arch,
}

// Arch is used to store whether the child process is 32- or 64-bit;
// Unless the wow64 feature is enabled and host process is 64-bit,
// this will just statically be compiled to be same arch as the host process.

#[cfg(any(target_arch = "x86", not(feature = "wow64")))]
#[derive(Copy, Clone)]
pub(crate) struct Arch;

#[cfg(all(target_arch = "x86_64", feature = "wow64"))]
#[derive(Copy, Clone)]
pub(crate) struct Arch(bool);

impl Arch {
    #[cfg(any(target_arch = "x86", not(feature = "wow64")))]
    #[inline]
    fn new(_: HANDLE) -> Result<Arch, Error> {
        Ok(Arch)
    }

    #[cfg(all(target_arch = "x86_64", feature = "wow64"))]
    fn new(handle: HANDLE) -> Result<Arch, Error> {
        let mut is_wow64 = 0i32;
        let ok = unsafe { IsWow64Process(handle, &mut is_wow64) };
        if ok == 0 {
            win_err("Could not determine process arch")
        } else {
            Ok(Arch(is_wow64 == 0))
        }
    }

    #[cfg(target_arch = "x86")]
    const fn is_64(self) -> bool {
        false
    }

    #[cfg(all(target_arch = "x86_64", not(feature = "wow64")))]
    const fn is_64(self) -> bool {
        true
    }

    #[cfg(all(target_arch = "x86_64", feature = "wow64"))]
    const fn is_64(self) -> bool {
        self.0
    }

    /// Currently wow64 childs have their 64-bit PEB read,
    /// so this is just host arch == 64 check.
    /// Could be refactored to have callers just cfg out the unreachable code.
    const fn is_64_peb(self) -> bool {
        self.is_64()
            /*
        #[cfg(target_arch = "x86")]
        { false }
        #[cfg(target_arch = "x86_64")]
        { true }
            */
    }
}

impl<'a> Process<'a> {
    /// Creates a new process which will have dlls injected earlier than normal.
    ///
    /// This should mean that the injected dlls will get to run code before any regular
    /// DLL initialization / TLS callbacks have been run.
    pub fn create<N, A>(
        name: N,
        args: A,
        cwd: Option<&Path>,
        env: &[(&OsStr, &OsStr)],
        inject_modules: &'a [&'a OsStr]
    ) -> Result<Process<'a>, Error>
    where N: AsRef<OsStr>,
          A: AsRef<OsStr>,
    {
        Process::create_internal(name.as_ref(), args.as_ref(), cwd, env, inject_modules)
    }

    fn create_internal(
        name: &OsStr,
        args: &OsStr,
        cwd: Option<&Path>,
        env: &[(&OsStr, &OsStr)],
        inject_modules: &'a [&'a OsStr]
    ) -> Result<Process<'a>, Error> {
        unsafe {
            let mut process_info: PROCESS_INFORMATION = mem::zeroed();
            let mut startup_info = STARTUPINFOW {
                cb: mem::size_of::<STARTUPINFOW>() as u32,
                ..mem::zeroed()
            };
            let name16 = make_winapi_str(name);
            let mut args16 = make_winapi_str(args);
            let cwd16 = cwd.map(|s| make_winapi_str(s));
            // Wonder if Windows actually needs it to be mut
            let mut environment_block = match env.is_empty() {
                true => None,
                false => Some(Process::create_environment_block(env)?),
            };
            let flags = CREATE_UNICODE_ENVIRONMENT | DEBUG_PROCESS;
            let success = CreateProcessW(
                name16.as_ptr(),
                args16.as_mut_ptr(),
                null_mut(),
                null_mut(),
                FALSE,
                flags,
                environment_block.as_mut()
                    .map(|x| x.as_mut_ptr() as *mut _).unwrap_or(null_mut()),
                cwd16.as_ref().map(|v| v.as_ptr()).unwrap_or(null()),
                &mut startup_info as *mut STARTUPINFOW,
                &mut process_info as *mut PROCESS_INFORMATION
            );
            if success != 0 {
                let arch = Arch::new(process_info.hProcess)?;
                Ok(Process {
                    process: process_info.hProcess,
                    main_thread: process_info.hThread,
                    inject_modules,
                    arch,
                })
            } else {
                win_err("Could not create process")
            }
        }
    }

    fn create_environment_block<E: AsRef<OsStr>>(env: &[(E, E)]) -> Result<Vec<u16>, Error> {
        unsafe {
            let env_strings = GetEnvironmentStringsW();
            if env_strings == null_mut() {
                return win_err("Couldn't get environment strings");
            }
            defer!({ FreeEnvironmentStringsW(env_strings); });

            // Env strings are terminated by zero, the final one by two.
            // This length contains only first zero of the final one.
            let env_strings_len = (0isize..).find(|&i| {
                *env_strings.offset(i) == 0 && *env_strings.offset(i + 1) == 0
            }).unwrap() as usize + 1;

            let env_strings = slice::from_raw_parts(env_strings, env_strings_len);
            let mut out = Vec::with_capacity(env_strings_len);
            for string in env_strings.split(|&x| x == 0) {
                if string.len() != 0 && string[0] != b'=' as u16 {
                    out.extend(string);
                    out.push(0);
                }
            }
            for &(ref key, ref val) in env {
                let key = make_winapi_str(key);
                out.extend(&key[..key.len() - 1]);
                out.push(b'=' as u16);
                let val = make_winapi_str(val);
                out.extend(&val[..val.len() - 1]);
                out.push(0);
            }
            out.push(0);
            Ok(out)
        }
    }

    /// Forcefully terminates the process with an exit code.
    pub fn terminate(self, code: u32) {
        unsafe { TerminateProcess(self.process, code); }
    }

    /// Resumes the process's main thread and starts execution.
    ///
    /// Calling this on a process which was created with `from_handle` will panic.
    pub fn resume(&mut self) -> Result<(), Error> {
        resume_thread(self.main_thread)
    }

    /// Blocks execution until the process has exited.
    ///
    /// Returns the child's exit code.
    pub fn wait_for_exit(self) -> Result<u32, Error> {
        unsafe {
            if WaitForSingleObject(self.process, INFINITE) == 0xffffffff {
                win_err("Wait error")
            } else {
                let mut code: u32 = 0;
                if GetExitCodeProcess(self.process, &mut code as *mut u32) == 0 {
                    win_err("Error retrieving exit code")
                } else {
                    Ok(code)
                }
            }
        }
    }

    /// Returns (read_pipe, child_pipe)
    unsafe fn pipe_to_child(&self) -> Result<(HANDLE, HANDLE), Error> {
        let mut read_pipe: HANDLE = null_mut();
        let mut write_pipe: HANDLE = null_mut();
        let mut child_pipe: HANDLE = null_mut();
        let success = CreatePipe(&mut read_pipe, &mut write_pipe, null_mut(), 0);
        if success == 0 {
            return win_err("Could not create pipe");
        }
        let success = DuplicateHandle(
            GetCurrentProcess(),
            write_pipe,
            self.process,
            &mut child_pipe,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS
        );
        if success == 0 {
            return win_err("Could not duplicate pipe handle");
        }
        close_handle(write_pipe)?;
        // TODO handle leak on errors?
        Ok((read_pipe, child_pipe))
    }

    /// Returns pointer in child to the code, param pointer in child, and handle to read pipe
    unsafe fn setup_inject<D, F>(&mut self,
        dlls: &[(D, F)],
        thread: HANDLE,
    ) -> Result<(PVOID, PVOID, HANDLE), Error>
    where D: AsRef<OsStr>,
          F: AsRef<[u8]>
    {
        let (read_pipe, child_pipe) = self.pipe_to_child()?;

        let child_memory =
            construct_child_memory(self.arch, self.process, thread, child_pipe, dlls)?;
        let child_memory_len = child_memory.data.len();
        let child_ptr = allocate_in_child(self.process, child_memory_len)?;
        let param_ptr = {
            let param_offset = child_memory.param_offset;
            (child_ptr as usize + param_offset) as PVOID
        };

        let data = child_memory.place_at(self.arch, child_ptr);
        if WriteProcessMemory(self.process, child_ptr, data.as_ptr() as *mut _,
                              data.len(), null_mut()) == 0 {
            return win_err("Error when writing to child's memory");
        }
        Ok((child_ptr, param_ptr, read_pipe))
    }

    fn do_early_inject<D, F>(
        &mut self,
        dlls: &[(D, F)],
    )-> Result<RemoteThread, Error>
        where D: AsRef<OsStr>,
              F: AsRef<[u8]>
    {
        unsafe {
            let mut thread = self.main_thread;

            // Wait until the child has inited kernel32.
            // Amusingly, if we were to order windows run the code before any debug events are
            // received, it would actually end up being run after all of the initialization has
            // been done. Waiting for a few debug events lets us inject the dlls early.
            let mut debug_event: DEBUG_EVENT = mem::zeroed();
            let mut state = EarlyInjectState::new(self.process, self.arch)?;
            state.threads.push((thread, GetThreadId(thread)));
            let caught_tls_cb_address = 'outer: loop {
                let debug_wait_timeout = match state.patched_modules.len() != 0 {
                    true => 5,
                    false => INFINITE,
                };
                let ok = WaitForDebugEvent(&mut debug_event, debug_wait_timeout);
                if ok == 0 {
                    if GetLastError() != ERROR_SEM_TIMEOUT {
                        return Err(Win(WinErr {
                            err: io::Error::last_os_error(),
                            desc: "WaitForDebugEvent error".into(),
                        }));
                    }
                }
                // Check any modules that were patched in previous iterations of this loop,
                // if they have reached TLS callback infloop in the patch.
                for &(_, tls_cb_address, _, patch_region) in state.patched_modules.iter() {
                    for &(t, _) in &state.threads {
                        if self.check_eip_in_range(t, patch_region) {
                            thread = t;
                            suspend_thread(thread)?;
                            if GetThreadId(thread) != debug_event.dwThreadId {
                                ContinueDebugEvent(
                                    debug_event.dwProcessId,
                                    debug_event.dwThreadId,
                                    0x00010002,
                                );
                            }
                            break 'outer tls_cb_address;
                        }
                    }
                }

                if ok == 0 {
                    continue;
                }
                debug!("Event {:x}", debug_event.dwDebugEventCode);

                // If we've now loaded a new DLL which was asked to be patched, patch it
                // (Only if all inject modules haven't bee patched)
                if state.patched_modules.len() != self.inject_modules.len() {
                    let modules = nt_api::all_dlls(self.arch, self.process, thread)
                        .map_err(|e| Error::Other(format!("Failed to get dlls\n{}", e)))?;
                    debug!("Check modules {:x?}", modules);
                    let unpatched_modules = modules.iter()
                        .filter(|x| x.0 != 0)
                        .filter_map(|x| {
                            let path = Path::new(&x.2);
                            let name = path.file_name().and_then(|x| x.to_str())?;
                            if self.inject_modules.iter().any(|x| x.eq_ignore_ascii_case(name)) {
                                Some(x)
                            } else {
                                None
                            }
                        });
                    for &(base, size, ref name) in unpatched_modules {
                        if state.patched_modules.iter().any(|x| x.0 == base) {
                            continue;
                        }
                        let tls_cb =
                            child_first_tls_callback(self.arch, self.process, (base, size));
                        let tls_cb = match tls_cb {
                            Ok(Some(s)) => s,
                            Ok(None) => {
                                debug!("No TLS CB for {}", name);
                                state.patched_modules.push((base, 0, vec![], (0, 0)));
                                continue;
                            }
                            Err(e) => {
                                return Err(Error::Other(
                                    format!("Error reading TLS CB for {}\n{}", name, e)
                                ));
                            }
                        };
                        debug!("tls cb patch for {} {:x} {:x}", name, base, tls_cb - base);
                        let (extra_code, extra_code_pos) = state.new_extra_code();

                        let old = if !self.arch.is_64() {
                            let mut entry_patch = [
                                0xb8, 0x00, 0x00, 0x00, 0x00, // mov eax, X
                                0xff, 0xe0, // jmp eax
                            ];
                            LittleEndian::write_u32(&mut entry_patch[1..], extra_code as u32);
                            patch_in_child(self.process, tls_cb, &entry_patch)?
                        } else {
                            let mut entry_patch = [
                                0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    // mov rax, X
                                0xff, 0xe0, // jmp rax
                            ];
                            LittleEndian::write_u64(&mut entry_patch[2..], extra_code as u64);
                            patch_in_child(self.process, tls_cb, &entry_patch)?
                        };

                        debug!("Patch reg {:x}", extra_code_pos);
                        state.patched_modules.push((base, tls_cb, old, (extra_code_pos, 4)));
                    }
                }
                // Track threads
                if debug_event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT {
                    let thread = debug_event.u.CreateThread().hThread;
                    let id = GetThreadId(thread);
                    state.threads.push((thread, id));
                } else if debug_event.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT {
                    state.threads.retain(|&(_, id)| id != debug_event.dwThreadId);
                }
                ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, 0x00010002);
            };
            debug!("Caught {:x}", caught_tls_cb_address);

            // mov edi, edi - nop over 'jmp ~pause'
            for &(_, _, _, patch_region) in &state.patched_modules {
                if patch_region.0 != 0 {
                    write_in_child(self.process, patch_region.0 + 2, &[0x89, 0xff])?;
                }
            }

            let (child_ptr, param_ptr, read_pipe) = self.setup_inject(dlls, thread)?;

            for &(_, tls_cb_address, ref old, _) in &state.patched_modules {
                if tls_cb_address != 0 && !old.is_empty() {
                    write_in_child(self.process, tls_cb_address, &old)?;
                }
            }
            // The nop loop was set to child first TLS cb, re-execute the instructions which
            // had been written over.
            let stack_data = [caught_tls_cb_address as usize, param_ptr as usize];

            if !self.arch.is_64() {
                self.update_context_to_inject_asm_32(thread, child_ptr, &stack_data)?;
            } else {
                #[cfg(target_arch = "x86_64")]
                self.update_context_to_inject_asm_64(thread, child_ptr, &stack_data)?;
            }

            Ok(RemoteThread {
                process: self.process,
                thread: thread,
                pipe: read_pipe,
            })
        }
    }

    #[cfg(target_arch = "x86")]
    unsafe fn check_eip_in_range(&self, thread: HANDLE, (base, size): (usize, u32) ) -> bool {
        let mut context = CONTEXT {
            ContextFlags: CONTEXT_INTEGER | CONTEXT_CONTROL,
            ..mem::zeroed()
        };
        let ok = GetThreadContext(thread, &mut context);
        let ip = context.Eip as usize;
        ok != 0 && ip >= base && ip < base + size as usize
    }

    #[cfg(target_arch = "x86_64")]
    unsafe fn check_eip_in_range(&self, thread: HANDLE, (base, size): (usize, u32) ) -> bool {
        if !self.arch.is_64() {
            let mut context = WOW64_CONTEXT {
                ContextFlags: WOW64_CONTEXT_INTEGER | WOW64_CONTEXT_CONTROL,
                ..mem::zeroed()
            };
            let ok = Wow64GetThreadContext(thread, &mut context);
            let ip = context.Eip as usize;
            ok != 0 && ip >= base && ip < base + size as usize
        } else {
            let mut context = Context64(CONTEXT {
                ContextFlags: CONTEXT_INTEGER | CONTEXT_CONTROL,
                ..mem::zeroed()
            });
            let ok = GetThreadContext(thread, &mut context.0);
            let ip = context.0.Rip as usize;
            ok != 0 && ip >= base && ip < base + size as usize
        }
    }

    unsafe fn update_context_to_inject_asm_32(
        &self,
        thread: HANDLE,
        child_ptr: PVOID,
        stack_data: &[usize; 2],
    ) -> Result<(), Error> {
        let stack_data = [stack_data[0] as u32, stack_data[1] as u32];
        #[cfg(target_arch = "x86")]
        let mut context = CONTEXT {
            ContextFlags: CONTEXT_INTEGER | CONTEXT_CONTROL,
            ..mem::zeroed()
        };
        #[cfg(target_arch = "x86_64")]
        let mut context = WOW64_CONTEXT {
            ContextFlags: WOW64_CONTEXT_INTEGER | WOW64_CONTEXT_CONTROL,
            ..mem::zeroed()
        };
        #[cfg(target_arch = "x86")]
        let ok = GetThreadContext(thread, &mut context);
        #[cfg(target_arch = "x86_64")]
        let ok = Wow64GetThreadContext(thread, &mut context);
        if ok == 0 {
            return win_err("Error getting thread context");
        }
        context.Esp -= 0x8;
        context.Eip = child_ptr as usize as u32;
        WriteProcessMemory(
            self.process,
            context.Esp as *mut _,
            stack_data.as_ptr() as *mut _,
            0x8,
            null_mut(),
        );

        if ok == 0 {
            return win_err("Error when writing to child's memory");
        }
        #[cfg(target_arch = "x86")]
        let ok = SetThreadContext(thread, &mut context);
        #[cfg(target_arch = "x86_64")]
        let ok = Wow64SetThreadContext(thread, &mut context);
        if ok == 0 {
            return win_err("Error setting thread context");
        }
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    unsafe fn update_context_to_inject_asm_64(
        &self,
        thread: HANDLE,
        child_ptr: PVOID,
        stack_data: &[usize; 2],
    ) -> Result<(), Error> {
        let mut context = Context64(CONTEXT {
            ContextFlags: CONTEXT_INTEGER | CONTEXT_CONTROL,
            ..mem::zeroed()
        });
        let ok = GetThreadContext(thread, &mut context.0);
        if ok == 0 {
            return win_err("Error getting thread context");
        }
        context.0.Rsp -= 0x10;
        context.0.Rip = child_ptr as u64;
        WriteProcessMemory(
            self.process,
            context.0.Rsp as *mut _,
            stack_data.as_ptr() as *mut _,
            0x10,
            null_mut(),
        );

        if ok == 0 {
            return win_err("Error when writing to child's memory");
        }
        let ok = SetThreadContext(thread, &mut context.0);
        if ok == 0 {
            return win_err("Error setting thread context");
        }
        Ok(())
    }

    /// Injects dlls to the process.
    ///
    /// `dlls` is a slice containing `(dll_path, function)` for each dll to be injected.
    /// `function` is u8 slice of the function name (Practically an ASCII string)
    /// in dll to be called.
    ///
    /// The exact behaviour depends on whether process was created with
    /// `Process::create_early_inject` or not. If it was, the dlls get injected right after the
    /// main thread has loaded basic win32 dlls (kernel32 and ntdll). Otherwise the dlls are
    /// injected in a separate thread while main thread is suspended.
    ///
    /// Returns the created thread on success, which is left in a suspended state.
    /// Call `run()` on the returned thread to actually load the dlls.
    ///
    /// If `debug` is true, the remote thread will have an `int3` instruction before
    /// any of the dlls are loaded. This may be useful for debugging the loading process.
    /// The `int3` will cause a crash if a debugger is not attached, so there should be
    /// a chance to attach it before the returned thread is ran.
    pub fn inject<D, F>(&mut self, dlls: &[(D, F)]) -> Result<RemoteThread, Error>
        where D: AsRef<OsStr>,
              F: AsRef<[u8]>
    {
        self.do_early_inject(dlls)
    }
}

#[cfg(target_arch = "x86_64")]
#[repr(align(16))]
struct Context64(CONTEXT);

struct EarlyInjectState {
    process: HANDLE,
    // Handle, thread id
    threads: Vec<(HANDLE, u32)>,
    // Base in child space, patched addr, patched bytes, patch region
    patched_modules: Vec<(usize, usize, Vec<u8>, (usize, u32))>,
    // Child space
    extra_code_pos: usize,
    extra_code_end: usize,
    arch: Arch,
}

impl EarlyInjectState {
    pub unsafe fn new(process: HANDLE, arch: Arch) -> Result<EarlyInjectState, Error> {
        let extra_code = allocate_in_child(process, 4096)?;
        Ok(EarlyInjectState {
            process,
            threads: Vec::with_capacity(8),
            patched_modules: Vec::with_capacity(4),
            extra_code_pos: extra_code as usize,
            extra_code_end: extra_code as usize + 4096,
            arch,
        })
    }

    /// Code to infloop when DLL_PROCESS_ATTACH is passed
    /// Returns address of start of code in child space, and address of the infloop
    pub unsafe fn new_extra_code(&mut self) -> (usize, usize) {
        let code: &[u8] = if !self.arch.is_64() {
            &[
                // DLL_PROCESS_ATTACH
                0x83, 0x7c, 0xe4, 0x08, 0x01,   // cmp dword [esp + 8], 1
                0x74, 0x06,                     // je loop
                                                // back:
                0x31, 0xc0,                     // xor eax, eax
                0x40,                           // inc eax
                0xc2, 0x0c, 0x00,               // ret 0xc
                                                // loop:
                0xf3, 0x90,                     // pause
                0xeb, 0xfc,                     // jmp ~pause
                0xeb, 0xf4,                     // jmp back
            ]
        } else {
            &[
                // DLL_PROCESS_ATTACH
                0x83, 0xfa, 0x01,               // cmp edx, 1
                0x74, 0x05,                     // je loop
                                                // back:
                0x31, 0xc0,                     // xor eax, eax
                0xff, 0xc0,                     // inc eax
                0xc3,                           // ret
                                                // loop:
                0xf3, 0x90,                     // pause
                0xeb, 0xfc,                     // jmp ~pause
                0xeb, 0xf5,                     // jmp back
            ]
        };
        let pos = self.extra_code_pos;
        self.extra_code_pos += code.len();
        assert!(self.extra_code_pos < self.extra_code_end);
        patch_in_child(self.process, pos, &code[..])
            .expect("Couldn't patch in child");
        (pos, self.extra_code_pos - 6)
    }
}

unsafe fn allocate_in_child(process: HANDLE, size: usize) -> Result<PVOID, Error> {
    let return_addr = VirtualAllocEx(process, null_mut(), size,
        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if return_addr == null_mut() {
        return win_err("Error on child allocation");
    }
    Ok(return_addr)
}

/// Just u32s to have struct size be same on 64bit host.
/// AsmArgs64 has the "intended" types.
#[repr(C, packed)]
#[allow(non_snake_case, dead_code)]
struct AsmArgs32 {
    LoadLibraryW: u32,
    GetProcAddress: u32,
    GetLastError: u32,
    WriteFile: u32,
    CloseHandle: u32,
    _reserved_function: [u32; 0x3],
    // 0x20
    dll_amount: u32,
    dll_table: u32,
    pipe: u32,
    _reserved_input: [u32; 0x5],
    // 0x40
    scratch_space: [u32; 0x8]
}

#[repr(C, packed)]
#[allow(non_snake_case, dead_code)]
struct AsmArgs64 {
    LoadLibraryW: FARPROC,
    GetProcAddress: FARPROC,
    GetLastError: FARPROC,
    WriteFile: FARPROC,
    CloseHandle: FARPROC,
    _reserved_function: [usize; 0x3],
    // 0x40
    dll_amount: usize,
    dll_table: *mut usize,
    pipe: HANDLE,
    _reserved_input: [usize; 0x5],
    // 0x80
    scratch_space: [usize; 0x8]
}

fn win32_error(code: u32) -> String {
    format!("{}", io::Error::from_raw_os_error(code as i32))
}

quick_error! {
    #[derive(Debug)]
    /// Errors that have occured in the when running child process's remote thread.
    pub enum RemoteThreadError {
        /// Loading the dll failed.
        LoadLibrary(index: usize, code: u32) {
            display("LoadLibrary failed for dll #{}: {}", index, win32_error(*code))
        }
        /// The dll does not export specified function.
        GetProcAddress(index: usize, code: u32) {
            display("GetProcAddress failed for dll #{}: {}", index, win32_error(*code))
        }
        /// The child reported its result with a invalidly formatted message.
        /// Either a bug in the assembly stub, or something overwrote it during
        /// dll loading.
        InvalidMessage {
            display("Child process sent an invalid message")
        }
        /// Winapi error in current process's side.
        Other(err: Error) {
            from()
            source(err)
            display("{}", err)
        }
    }
}

#[repr(C, packed)]
struct RawRemoteThreadMsg {
    code: u32,
    error: u32,
    index: u32,
}

unsafe fn close_handle(handle: HANDLE) -> Result<(), Error> {
    if CloseHandle(handle) == 0 {
        win_err("Could not close handle")
    } else {
        Ok(())
    }
}

/// A thread in child process's address space.
///
/// Call `run()` to inject dlls.
pub struct RemoteThread {
    process: HANDLE,
    thread: HANDLE,
    pipe: HANDLE,
}

impl RemoteThread {
    /// Runs the remote thread, loading dlls, and blocking until all dlls have finished
    /// their initialization function.
    ///
    /// Once the function returns, the thread has exited.
    ///
    /// If an error occurs during loading, the process is left in state where
    /// dlls before the erronous one have had their initialization function run,
    /// but any dlls after have not.
    pub fn run(self) -> Result<(), RemoteThreadError> {
        unsafe {
            let process_id = GetProcessId(self.process);
            DebugActiveProcessStop(process_id);
            resume_thread(self.thread)?;
            // Not freeing memory for early injects as it is difficult to guarantee
            // that it is not executing it. Byebye 4096-or-so bytes.
            close_handle(self.thread)?;

            let message = {
                let msg_len = mem::size_of::<RawRemoteThreadMsg>();
                let mut buffer = vec![0u8; msg_len];
                let mut total_read = 0;
                while total_read < msg_len {
                    let mut read = 0;
                    let ptr = buffer.as_mut_ptr();
                    let success = ReadFile(
                        self.pipe,
                        ptr.offset(total_read as isize) as PVOID,
                        (msg_len - total_read) as u32,
                        &mut read,
                        null_mut(),
                    );
                    if success == 0 {
                        return win_err("Error while reading child process's pipe").map_err(|x| x.into());
                    }
                    total_read += read as usize;
                }
                close_handle(self.pipe)?;
                assert_eq!(total_read, msg_len);
                let mut msg: RawRemoteThreadMsg = mem::zeroed();
                copy_nonoverlapping(buffer.as_ptr(), &mut msg as *mut RawRemoteThreadMsg as *mut u8, msg_len);
                msg
            };
            match message.code {
                0 => Ok(()),
                1 => Err(RemoteThreadError::LoadLibrary(message.index as usize, message.error)),
                2 => Err(RemoteThreadError::GetProcAddress(message.index as usize, message.error)),
                _ => Err(RemoteThreadError::InvalidMessage),
            }
        }
    }
}

fn suspend_thread(thread: HANDLE) -> Result<(), Error> {
    unsafe {
        if SuspendThread(thread) == 0xffffffff {
            win_err("Error suspending thread")
        } else {
            Ok(())
        }
    }
}

fn resume_thread(thread: HANDLE) -> Result<(), Error> {
    unsafe {
        if ResumeThread(thread) == 0xffffffff {
            win_err("Error resuming thread")
        } else {
            Ok(())
        }
    }
}

struct ChildMemory {
    data: Vec<u8>,
    param_offset: usize,
    first_dll_offset: usize,
    first_name_offset: usize,
    first_func_offset: usize,
    dll_offsets: Vec<(usize, usize)>,
}

impl ChildMemory {
    /// Prepares the pointers in `self.data` when the memory is going to be placed at `addr`.
    pub fn place_at(mut self, arch: Arch, addr: PVOID) -> Vec<u8> {
        unsafe {
            let addr = addr as usize;
            if !arch.is_64() {
                let args = (self.data.as_mut_ptr().add(self.param_offset)) as *mut AsmArgs32;
                (*args).dll_table = (addr + self.first_dll_offset) as u32;
                let dlls = (self.data.as_mut_ptr().add(self.first_dll_offset)) as *mut u32;
                for (i, &(name, func)) in self.dll_offsets.iter().enumerate() {
                    assert_eq!(*dlls.add(i * 2), u32::MAX);
                    assert_eq!(*dlls.add(i * 2 + 1), u32::MAX);
                    *dlls.add(i * 2) = (addr + self.first_name_offset + name * 2) as u32;
                    *dlls.add(i * 2 + 1) = (addr + self.first_func_offset + func) as u32;
                }
            } else {
                let args = (self.data.as_mut_ptr().add(self.param_offset)) as *mut AsmArgs64;
                (*args).dll_table = (addr + self.first_dll_offset) as *mut usize;
                let dlls = (self.data.as_mut_ptr().add(self.first_dll_offset)) as *mut u64;
                for (i, &(name, func)) in self.dll_offsets.iter().enumerate() {
                    assert_eq!(*dlls.add(i * 2), u64::MAX);
                    assert_eq!(*dlls.add(i * 2 + 1), u64::MAX);
                    *dlls.add(i * 2) = (addr + self.first_name_offset + name * 2) as u64;
                    *dlls.add(i * 2 + 1) = (addr + self.first_func_offset + func) as u64;
                }
            }
        }
        self.data
    }
}

fn round16(x: usize) -> usize {
    (x | 0xf).wrapping_add(1)
}

/// `pipe` is the write half which has been duplicated to child process
unsafe fn construct_child_memory<D, F>(
    arch: Arch,
    child: HANDLE,
    thread: HANDLE,
    pipe: HANDLE,
    dlls: &[(D, F)],
) -> Result<ChildMemory, Error>
where D: AsRef<OsStr>,
      F: AsRef<[u8]>
{
    let dlls_length = dlls.iter().fold(0, |sum, &(ref a, ref b)| {
        sum + a.as_ref().encode_wide().count() * 2 + 2 + b.as_ref().len() + 1
    });
    let assembly = if !arch.is_64() { ASSEMBLY_32 } else { ASSEMBLY_64 };
    let mut buffer = Vec::with_capacity(
        round16(assembly.len()) +
        if !arch.is_64() { mem::size_of::<AsmArgs32>() } else { mem::size_of::<AsmArgs64>() } +
        dlls_length
    );
    buffer.extend(assembly);
    while buffer.len() % 0x10 != 0 {
        buffer.push(0xcc);
    }
    let param_offset = buffer.len();
    static FUNCS: &[&[u8]] = &[
        b"LoadLibraryW",
        b"GetProcAddress",
        b"GetLastError",
        b"WriteFile",
        b"CloseHandle",
    ];
    let mut funcs = [null_mut(); 5];
    for i in 0..funcs.len() {
        funcs[i] = proc_address_child(arch, child, thread, "kernel32.dll", FUNCS[i])?;
    }
    if !arch.is_64() {
        let args = {
            AsmArgs32 {
                LoadLibraryW: funcs[0] as u32,
                GetProcAddress: funcs[1] as u32,
                GetLastError: funcs[2] as u32,
                WriteFile: funcs[3] as u32,
                CloseHandle: funcs[4] as u32,
                _reserved_function: [!0; 3],
                dll_amount: dlls.len() as u32,
                dll_table: !0,
                // N.B. Windows guarantees that handles are always 32-bit;
                // truncation/*sign* extension to convert them between 32/64 bit processes is OK.
                // (Source: MSDN WOW64 docs)
                pipe: pipe as u32,
                _reserved_input: [!0; 5],
                scratch_space: [!0; 8],
            }
        };
        buffer.extend_from_slice(
            slice::from_raw_parts(&args as *const AsmArgs32 as *const u8, mem::size_of_val(&args))
        );
    } else {
        let args = {
            AsmArgs64 {
                LoadLibraryW: funcs[0],
                GetProcAddress: funcs[1],
                GetLastError: funcs[2],
                WriteFile: funcs[3],
                CloseHandle: funcs[4],
                _reserved_function: [!0; 3],
                dll_amount: dlls.len(),
                dll_table: !0 as *mut usize,
                pipe: pipe,
                _reserved_input: [!0; 5],
                scratch_space: [!0; 8],
            }
        };
        buffer.extend_from_slice(
            slice::from_raw_parts(&args as *const AsmArgs64 as *const u8, mem::size_of_val(&args))
        );
    }

    let mut names: Vec<u16> = Vec::new();
    let mut funcs: Vec<u8> = Vec::new();
    let mut dll_offsets = Vec::new();
    for &(ref name, ref func) in dlls.iter() {
        dll_offsets.push((names.len(), funcs.len()));
        names.extend(name.as_ref().encode_wide().chain(Some(0)));
        funcs.extend(func.as_ref().iter().cloned().chain(Some(0)));
    }
    let first_dll_offset = buffer.len();
    let word_size = if !arch.is_64() { 4 } else { 8 };
    buffer.extend((0..dll_offsets.len() * word_size * 2).map(|_| 0xffu8));
    let first_name_offset = buffer.len();
    buffer.extend_from_slice(
        slice::from_raw_parts(names.as_ptr() as *const u8, names.len() * 2)
    );
    let first_func_offset = buffer.len();
    buffer.extend_from_slice(&funcs);
    Ok(ChildMemory {
        data: buffer,
        param_offset: param_offset,
        first_dll_offset: first_dll_offset,
        first_name_offset: first_name_offset,
        first_func_offset: first_func_offset,
        dll_offsets: dll_offsets,
    })
}

fn read_in_child(child: HANDLE, address: usize, out: &mut [u8]) -> Result<(), Error> {
    let mut read = 0usize;
    let ok = unsafe {
        ReadProcessMemory(
            child,
            address as *mut _,
            out.as_mut_ptr() as *mut _,
            out.len(),
            &mut read,
        )
    };
    if ok == 0 || read != out.len() {
        win_err(format!("Error reading {} bytes from child", out.len()))
    } else {
        Ok(())
    }
}

fn write_in_child(child: HANDLE, address: usize, data: &[u8]) -> Result<(), Error> {
    let mut written = 0usize;
    let ok = unsafe {
        WriteProcessMemory(
            child,
            address as *mut _,
            data.as_ptr() as *const _,
            data.len(),
            &mut written,
        )
    };
    if ok == 0 || written != data.len() {
        win_err(format!("Error writing {} bytes to child", data.len()))
    } else {
        Ok(())
    }
}

/// Returns the old data on success.
fn patch_in_child(child: HANDLE, address: usize, data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut old = vec![0; data.len()];
    read_in_child(child, address, &mut old)?;
    write_in_child(child, address, data)?;
    Ok(old)
}

fn read_child_image(
    arch: Arch,
    child: HANDLE,
    (base, size): (usize, usize),
) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0; size as usize];
    read_in_child(child, base, &mut buf[..0x1000])?;
    let pe_header = read_u32(&buf, 0x3c)?;
    let section_count = read_u16(&buf, pe_header + 6)?;

    let section_offset = if !arch.is_64() { 0xf8 } else { 0x108 };
    for i in 0..section_count {
        let address =
            read_u32(&buf, pe_header + section_offset + 0x28 * i as u32 + 0xc)? as usize;
        let size = read_u32(&buf, pe_header + section_offset + 0x28 * i as u32 + 0x8)? as usize;
        read_in_child(child, base + address, &mut buf[address..address + size])
            .map_err(|e| {
                Error::Other(format!(
                    "Couldn't read section {:x} @ {:x}:{:x} of {:x}:{:x}\n{}",
                    i, address, size, base, size, e,
                ))
            })?;
    }
    Ok(buf)
}

fn proc_address_child(
    arch: Arch,
    child: HANDLE,
    thread: HANDLE,
    dll: &str,
    func: &[u8],
) -> Result<FARPROC, Error> {
    let (base, size) = nt_api::dll_base_size(arch, child, thread, dll)
        .map_err(|e| {
            let msg = format!("Could not get dll base size for {}: {}", dll, e);
            Error::Other(msg)
        })?;
    let mut buf = vec![0; size as usize];
    read_in_child(child, base, &mut buf[..0x1000])?;
    let pe_header = read_u32(&buf, 0x3c)?;
    let section_count = read_u16(&buf, pe_header + 6)?;

    let section_offset = if !arch.is_64() { 0xf8 } else { 0x108 };
    for i in 0..section_count {
        let address =
            read_u32(&buf, pe_header + section_offset + 0x28 * i as u32 + 0xc)? as usize;
        let size =
            read_u32(&buf, pe_header + section_offset + 0x28 * i as u32 + 0x8)? as usize;
        read_in_child(child, base + address, &mut buf[address..address + size])?;
    }

    let result = if !arch.is_64() {
        find_export_32(base as u32, &buf, func)
    } else {
        find_export_64(base as u64, &buf, func)
    };

    result.map_err(|e| {
            let msg = format!("Could not find {}:{} - {}", dll, String::from_utf8_lossy(func), e);
            Error::Other(msg)
        })
}

fn find_export_32(base: u32, buf: &[u8], func: &[u8]) -> Result<FARPROC, Error> {
    let pe_header = read_u32(buf, 0x3c)?;
    let export_rva = read_u32(buf, pe_header + 0x78)?;
    if export_rva == 0 {
        return Err(Error::Other("No exports".into()));
    }
    let export_count = read_u32(buf, export_rva + 0x14)?;
    let name_count = read_u32(buf, export_rva + 0x18)?;
    let export_addresses = read_u32(buf, export_rva + 0x1c)?;
    let export_names = read_u32(buf, export_rva + 0x20)?;
    let export_ordinals = read_u32(buf, export_rva + 0x24)?;
    for i in 0..export_count {
        let address = read_u32(buf, export_addresses + i * 4)?;
        let name_index = (0..name_count).find(|x| {
            read_u16(buf, export_ordinals + x * 2).unwrap_or(0) as u32 == i
        });
        if let Some(name_index) = name_index {
            let name = read_u32(buf, export_names + name_index * 4)?;
            if (&buf[name as usize..name as usize + func.len() + 1]).iter().cloned()
                .eq(func.iter().cloned().chain(Some(0))) {
                return Ok((base + address) as FARPROC);
            }
        }
    }
    Err(Error::Other("No export found".into()))
}

fn find_export_64(base: u64, buf: &[u8], func: &[u8]) -> Result<FARPROC, Error> {
    let pe_header = read_u32(buf, 0x3c)?;
    let export_rva = read_u32(buf, pe_header + 0x88)?;
    if export_rva == 0 {
        return Err(Error::Other("No exports".into()));
    }
    let export_count = read_u32(buf, export_rva + 0x14)?;
    let name_count = read_u32(buf, export_rva + 0x18)?;
    let export_addresses = read_u32(buf, export_rva + 0x1c)?;
    let export_names = read_u32(buf, export_rva + 0x20)?;
    let export_ordinals = read_u32(buf, export_rva + 0x24)?;
    for i in 0..export_count {
        let address = read_u32(buf, export_addresses + i * 4)?;
        let name_index = (0..name_count).find(|x| {
            read_u16(buf, export_ordinals + x * 2).unwrap_or(0) as u32 == i
        });
        if let Some(name_index) = name_index {
            let name = read_u32(buf, export_names + name_index * 4)?;
            if (&buf[name as usize..name as usize + func.len() + 1]).iter().cloned()
                .eq(func.iter().cloned().chain(Some(0))) {
                return Ok((base + address as u64) as FARPROC);
            }
        }
    }
    Err(Error::Other("No export found".into()))
}

fn read_u64(buf: &[u8], offset: u32) -> Result<u64, Error> {
    let offset = offset as usize;
    let slice = buf.get(offset..(offset.wrapping_add(8)))
        .ok_or_else(|| Error::Other("Oob".into()))?;
    Ok(LittleEndian::read_u64(slice))
}

fn read_u32(buf: &[u8], offset: u32) -> Result<u32, Error> {
    let offset = offset as usize;
    let slice = buf.get(offset..(offset.wrapping_add(4)))
        .ok_or_else(|| Error::Other("Oob".into()))?;
    Ok(LittleEndian::read_u32(slice))
}

fn read_u16(buf: &[u8], offset: u32) -> Result<u16, Error> {
    let offset = offset as usize;
    let slice = buf.get(offset..(offset.wrapping_add(2)))
        .ok_or_else(|| Error::Other("Oob".into()))?;
    Ok(LittleEndian::read_u16(slice))
}

fn child_first_tls_callback(
    arch: Arch,
    child: HANDLE,
    image: (usize, usize),
) -> Result<Option<usize>, Error> {
    let base = image.0;
    let image = read_child_image(arch, child, image)?;
    let pe_header = read_u32(&image, 0x3c)?;
    let tls_offset = if !arch.is_64() { 0xc0 } else { 0xd0 };
    let tls_section_addr = read_u32(&image, pe_header.wrapping_add(tls_offset))?;
    let tls_section_length = read_u32(&image, pe_header.wrapping_add(tls_offset + 4))?;
    let min_length = if !arch.is_64() { 0x10 } else { 0x20 };
    if tls_section_addr == 0 || tls_section_length < min_length {
        return Ok(None);
    }
    // This is a (relocated) direct pointer, not a RVA
    let callback_offset = if !arch.is_64() { 0xc } else { 0x18 };
    let callback_addr = tls_section_addr.wrapping_add(callback_offset);
    if !arch.is_64() {
        let callbacks = read_u32(&image, callback_addr)? as usize;
        if callbacks == 0 {
            return Ok(None);
        }
        Ok(match read_u32(&image, (callbacks - base) as u32)? {
            0 => None,
            x => Some(x as usize),
        })
    } else {
        let callbacks = read_u64(&image, callback_addr)? as usize;
        if callbacks == 0 {
            return Ok(None);
        }
        Ok(match read_u64(&image, (callbacks - base) as u32)? {
            0 => None,
            x => Some(x as usize),
        })
    }
}
