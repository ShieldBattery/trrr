use std::io;
use std::mem;
use std::ptr::null_mut;

use libc::c_void;

use winapi::um::libloaderapi::{GetModuleHandleW, GetProcAddress};
use winapi::um::memoryapi::ReadProcessMemory;
use winapi::um::winnt::HANDLE;

use crate::{Arch, Error, read_u32, read_u16, win_err, WinErr, make_winapi_str};

fn get_nt_query_information_process()
    -> Result<extern "system" fn(HANDLE, u32, *mut c_void, u32, *mut u32) -> i32, Error>
{
    unsafe {
        let ntdll = GetModuleHandleW(make_winapi_str("ntdll").as_ptr());
        if ntdll == null_mut() {
            return win_err("Could get ntdll handle");
        }
        let addr = GetProcAddress(ntdll, b"NtQueryInformationProcess\0".as_ptr() as *const i8);
        if addr == null_mut() {
            return win_err("Didn't find NtQueryInformationProcess");
        }
        Ok(mem::transmute(addr))
    }
}

// Uses u32 on pointers to be same on 64-bit.
#[repr(C, packed)]
struct Peb32 {
    reserved1: [u8; 2],
    being_debugged: u8,
    reserved2: u8,
    reserved3: [u32; 2],
    ldr: u32,
    process_parameters: u32,
    reserved4: [u8; 104],
    reserved5: [u32; 52],
    post_process_init_routine: u32,
    reserved6: [u8; 128],
    reserved7: u32,
    session_id: u32,
}

#[repr(C, packed)]
struct Peb64 {
    reserved1: [u8; 2],
    being_debugged: u8,
    reserved2: u8,
    padding: u32,
    reserved3: [u64; 2],
    ldr: u64,
    process_parameters: u64,
    reserved4: [u8; 104],
    reserved5: [u64; 52],
    post_process_init_routine: u64,
    reserved6: [u8; 128],
    reserved7: u64,
    session_id: u64,
}

#[repr(C)]
struct PebLdrData32 {
    reserved1: [u8; 8],
    reserved2: [u32; 3],
    module_list: [u32; 2],
}

#[repr(C)]
struct PebLdrData64 {
    reserved1: [u8; 8],
    reserved2: [u64; 3],
    module_list: [u64; 2],
}

#[repr(C)]
struct LdrDataTableEntry32 {
    reserved1: [u32; 2],
    links: [u32; 2],
    reserved2: [u32; 2],
    dll_base: u32,
    entry: u32,
    reserved3: u32,
    dll_name: UnicodeString32,
    reserved4: [u8; 8],
    reserved5: [u32; 3],
    checksum: u32,
    time_date_stamp: u32,
}

#[repr(C)]
struct LdrDataTableEntry64 {
    reserved1: [u64; 2],
    links: [u64; 2],
    reserved2: [u64; 2],
    dll_base: u64,
    entry: u64,
    reserved3: u64,
    dll_name: UnicodeString64,
    reserved4: [u8; 8],
    reserved5: [u64; 3],
    checksum: u32,
    padding: u32,
    time_date_stamp: u32,
}

#[repr(C)]
struct UnicodeString32 {
    size: u16,
    capacity: u16,
    pointer: u32,
}

#[repr(C)]
struct UnicodeString64 {
    size: u16,
    capacity: u16,
    padding: u32,
    pointer: u64,
}

unsafe fn nt_query_process_basic_info(process: HANDLE) -> Result<[usize; 6], Error> {
    let nt_query_process = get_nt_query_information_process()?;
    let mut info = [0usize; 6];
    let info_ptr = info[..].as_mut_ptr() as *mut c_void;
    let status = nt_query_process(
        process,
        0,
        info_ptr,
        6 * mem::size_of::<usize>() as u32,
        null_mut()
    );
    if status < 0 {
        Err(Error::Win(WinErr {
            err: io::Error::from_raw_os_error(status),
            desc: "Could not query process".into(),
        }))
    } else {
        Ok(info)
    }
}

#[cfg(any(target_arch = "x86", not(feature = "wow64")))]
fn get_peb_address(_: Arch, process: HANDLE, _thread: HANDLE) -> Result<usize, Error> {
    let info = unsafe { nt_query_process_basic_info(process)? };
    Ok(info[1])
}

#[cfg(all(target_arch = "x86_64", feature = "wow64"))]
fn get_peb_address(arch: Arch, process: HANDLE, thread: HANDLE) -> Result<usize, Error> {
    use winapi::um::winbase::{Wow64GetThreadContext, Wow64GetThreadSelectorEntry};
    use winapi::um::winnt::{WOW64_CONTEXT, WOW64_CONTEXT_SEGMENTS, WOW64_LDT_ENTRY};
    // With WOW64, NtQueryInformationProcess hands out 64bit PEB, which doesn't get the
    // DLLS that are loaded later on. The most reliable way to get 32bit PEB seems
    // to be from 32bit TEB, which can be accessed by either
    // 1) 64bit TEB + 0x2000 (Undocumented, but some (a lot of?) third-party code relies on this)
    // 2) 64bit TEB[0] (Documented by MS, with statement that it is not guaranteed to work past
    //    win8, though at least win10 still works)
    // 3) Reading FS segment with Wow64GetThreadSelectorEntry
    //
    // Doing 3) since it seems foolproof. Shame that 64bit child's GS segment cannot be read
    // without injecting instructions to child. Would be nicer than relying on ntdll APIs.
    if !arch.is_64() {
        unsafe {
            let mut context = WOW64_CONTEXT {
                ContextFlags: WOW64_CONTEXT_SEGMENTS,
                ..mem::zeroed()
            };
            let ok = Wow64GetThreadContext(thread, &mut context);
            if ok == 0 {
                return win_err("Error getting thread context");
            }
            let mut out: WOW64_LDT_ENTRY = mem::zeroed();
            let ok = Wow64GetThreadSelectorEntry(thread, context.SegFs, &mut out);
            if ok == 0 {
                return win_err("Error getting thread FS");
            }
            let teb = (out.BaseLow as u32) |
                ((out.HighWord.Bytes().BaseMid as u32) << 16) |
                ((out.HighWord.Bytes().BaseHi as u32) << 24);
            let peb = read_process_struct::<u32>(process, (teb + 0x30) as *const u8)?;
            Ok(peb as usize)
        }
    } else {
        let info = unsafe { nt_query_process_basic_info(process)? };
        Ok(info[1])
    }
}

/// Returns pointer to PEB's Ldr (Loaded DLLs) structure in child's address space
unsafe fn read_peb_ldr(arch: Arch, process: HANDLE, thread: HANDLE) -> Result<usize, Error> {
    let peb_addr = get_peb_address(arch, process, thread)?;
    if !arch.is_64_peb() {
        let peb: Peb32 = read_process_struct(process, peb_addr as *const u8)
            .or_else(|_| win_err("Could not read PEB"))?;
        Ok(peb.ldr as usize)
    } else {
        let peb: Peb64 = read_process_struct(process, peb_addr as *const u8)
            .or_else(|_| win_err("Could not read PEB"))?;
        Ok(peb.ldr as usize)
    }
}

/// `dll` should have file extension
pub(crate) fn dll_base_size(
    arch: Arch,
    process: HANDLE,
    thread: HANDLE,
    dll: &str,
) -> Result<(usize, usize), Error> {
    unsafe {
        let peb_ldr = match read_peb_ldr(arch, process, thread) {
            Ok(s) if s != 0 => s,
            _ => return Ok((0, 0)),
        };
        let mut entry_pointer;
        let end;
        let entry_offset;
        if !arch.is_64_peb() {
            let ldr_data: PebLdrData32 = read_process_struct(process, peb_ldr as *const u8)
                .or_else(|_| win_err("Could not read PEB loader data"))?;
            entry_pointer = ldr_data.module_list[0] as usize;
            end = peb_ldr + 0x14;
            entry_offset = 8;
        } else {
            let ldr_data: PebLdrData64 = read_process_struct(process, peb_ldr as *const u8)
                .or_else(|_| win_err("Could not read PEB loader data"))?;
            entry_pointer = ldr_data.module_list[0] as usize;
            end = peb_ldr + 0x20;
            entry_offset = 16;
        };

        while entry_pointer != 0 && entry_pointer != end {
            let mut result_base = None;
            if !arch.is_64_peb() {
                let entry: LdrDataTableEntry32 =
                    read_process_struct(process, (entry_pointer - entry_offset) as *const u8)?;
                if entry.dll_base == 0 {
                    return Ok((0, 0));
                }
                entry_pointer = entry.links[0] as usize;
                let dll_filename = read_process_string_32(process, &entry.dll_name)?;
                let is_wanted = dll_filename.rfind(|x| x == '/' || x == '\\')
                    .map(|pos| dll_filename[pos + 1..].eq_ignore_ascii_case(dll))
                    .unwrap_or(false);
                if is_wanted {
                    result_base = Some(entry.dll_base as usize);
                }
            } else {
                let entry: LdrDataTableEntry64 =
                    read_process_struct(process, (entry_pointer - entry_offset) as *const u8)?;
                if entry.dll_base == 0 {
                    return Ok((0, 0));
                }
                entry_pointer = entry.links[0] as usize;
                let dll_filename = read_process_string_64(process, &entry.dll_name)?;
                let is_wanted = dll_filename.rfind(|x| x == '/' || x == '\\')
                    .map(|pos| dll_filename[pos + 1..].eq_ignore_ascii_case(dll))
                    .unwrap_or(false);
                if is_wanted {
                    result_base = Some(entry.dll_base as usize);
                }
            }
            if let Some(base) = result_base {
                let size = get_dll_size_in_process(arch, process, base)?;
                return Ok((base, size as usize));
            }
        }
        Err(Error::Other(format!("{} not loaded", dll)))
    }
}

pub(crate) fn all_dlls(
    arch: Arch,
    process: HANDLE,
    thread: HANDLE,
) -> Result<Vec<(usize, usize, String)>, Error> {
    unsafe {
        let peb_ldr = match read_peb_ldr(arch, process, thread) {
            Ok(s) if s != 0 => s,
            _ => return Ok(vec![]),
        };
        let mut result = Vec::with_capacity(32);
        let mut entry_pointer;
        let end;
        let entry_offset;
        if !arch.is_64_peb() {
            let ldr_data: PebLdrData32 = read_process_struct(process, peb_ldr as *const u8)
                .or_else(|_| win_err("Could not read PEB loader data"))?;
            entry_pointer = ldr_data.module_list[0] as usize;
            end = peb_ldr + 0x14;
            entry_offset = 8;
        } else {
            let ldr_data: PebLdrData64 = read_process_struct(process, peb_ldr as *const u8)
                .or_else(|_| win_err("Could not read PEB loader data"))?;
            entry_pointer = ldr_data.module_list[0] as usize;
            end = peb_ldr + 0x20;
            entry_offset = 16;
        };

        while entry_pointer != 0 && entry_pointer != end {
            if !arch.is_64_peb() {
                let entry = read_process_struct::<LdrDataTableEntry32>(
                    process,
                    (entry_pointer - entry_offset) as *const u8,
                );
                let entry = match entry.as_ref() {
                    Ok(x) if x.dll_base != 0 => x,
                    _ => return Ok(result),
                };
                entry_pointer = entry.links[0] as usize;
                let dll_filename = read_process_string_32(process, &entry.dll_name)?;
                let size = get_dll_size_in_process(arch, process, entry.dll_base as usize)?;
                result.push((entry.dll_base as usize, size as usize, dll_filename));
            } else {
                let entry = read_process_struct::<LdrDataTableEntry64>(
                    process,
                    (entry_pointer - entry_offset) as *const u8,
                );
                let entry = match entry.as_ref() {
                    Ok(x) if x.dll_base != 0 => x,
                    _ => return Ok(result),
                };
                entry_pointer = entry.links[0] as usize;
                let dll_filename = read_process_string_64(process, &entry.dll_name)?;
                let size = get_dll_size_in_process(arch, process, entry.dll_base as usize)?;
                result.push((entry.dll_base as usize, size as usize, dll_filename));
            }
        }
        Ok(result)
    }
}

unsafe fn get_dll_size_in_process(
    arch: Arch,
    process: HANDLE,
    base: usize,
) -> Result<u32, Error> {
    let mut buf = vec![0u8; 0x1000];
    let mut read = 0usize;
    let ok = ReadProcessMemory(
        process,
        base as *mut _,
        buf.as_mut_ptr() as *mut _,
        0x1000,
        &mut read,
    );
    if ok == 0 || read != 0x1000 {
        win_err("Error reading PE header from child")
    } else {
        let pe_header = read_u32(&buf, 0x3c)?;
        let section_count = read_u16(&buf, pe_header + 6)?;

        let mut max = 0x1000;
        let section_offset = if !arch.is_64() { 0xf8 } else { 0x108 };
        for i in 0..section_count {
            let section = pe_header + section_offset + 0x28 * i as u32;
            let rva = read_u32(&buf, section + 0xc)?;
            let size = read_u32(&buf, section + 0x8)?;
            max = std::cmp::max(rva + size, max);
        }
        Ok(max)
    }
}

unsafe fn read_process_string_32(
    process: HANDLE,
    string: &UnicodeString32,
) -> Result<String, Error> {
    let mut buf = vec![0u16; string.size as usize / 2];
    let mut read = 0usize;
    let ok = ReadProcessMemory(
        process,
        string.pointer as *mut _,
        buf.as_mut_ptr() as *mut _,
        string.size as usize,
        &mut read,
    );
    if ok == 0 || read != string.size as usize {
        win_err(format!("Error reading {} bytes from child", string.size))
    } else {
        String::from_utf16(&buf)
            .map_err(|e| Error::Other(format!("Couldn't decode utf16: {}", e)))
    }
}

unsafe fn read_process_string_64(
    process: HANDLE,
    string: &UnicodeString64,
) -> Result<String, Error> {
    let mut buf = vec![0u16; string.size as usize / 2];
    let mut read = 0usize;
    let ok = ReadProcessMemory(
        process,
        string.pointer as *mut _,
        buf.as_mut_ptr() as *mut _,
        string.size as usize,
        &mut read,
    );
    if ok == 0 || read != string.size as usize {
        win_err(format!("Error reading {} bytes from child", string.size))
    } else {
        String::from_utf16(&buf)
            .map_err(|e| Error::Other(format!("Couldn't decode utf16: {}", e)))
    }
}

unsafe fn read_process_struct<T>(process: HANDLE, addr: *const u8) -> Result<T, Error> {
    let mut ret: mem::MaybeUninit<T> = mem::MaybeUninit::uninit();
    read_process_struct_nongeneric(
        process,
        addr,
        ret.as_mut_ptr() as *mut u8,
        mem::size_of::<T>(),
    )?;
    Ok(ret.assume_init())
}

unsafe fn read_process_struct_nongeneric(
    process: HANDLE,
    addr: *const u8,
    out: *mut u8,
    size: usize,
) -> Result<(), Error> {
    let mut read = 0usize;
    let ok = ReadProcessMemory(
        process,
        addr as *mut _,
        out as *mut _,
        size,
        &mut read,
    );
    if ok == 0 || read != size {
        win_err(format!("Error reading {} bytes from child", size))
    } else {
        Ok(())
    }
}
