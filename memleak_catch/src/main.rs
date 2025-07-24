use aya::programs::UProbe;
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use procfs::process::all_processes;
use aya::maps::RingBuf;
use aya::maps::stack_trace::StackTraceMap;
use object::{Object, ObjectSymbol};
use std::fs;
use std::fs::OpenOptions;
use std::io::{Write, BufWriter, BufRead, BufReader};
use std::ffi::CStr;
use std::ptr;
use libc::{time_t, tm, localtime, strftime, time};
use addr2line::Context;
use tokio::select;
use rustc_demangle::demangle;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    pid: Option<i32>,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AllocEvent {
    pub address: usize,
    pub size: usize,
    pub func_type: u8,
    pub stack_id: i64,
    pub pid_tid: u32,
    pub status: u8, // 0 = freed, 1 = leak
    pub _padding: [u8; 2], // for alignment
}

fn php_fpm_pids() -> Vec<i32> {
    all_processes()
        .unwrap()
        .filter_map(Result::ok)
        .filter(|prc| {
            if let Ok(cmdline) = prc.cmdline() {
                cmdline.iter().any(|arg| arg.contains("php-fpm"))
            } else {
                false
            }
        })
        .map(|prc| prc.pid())
        .collect()
}

// parse the /proc/pid/maps file to find the mapping for the instruction pointer
fn find_mapping_for_ip(pid: i32, ip: u64) -> Option<(String, u64)> {
    let maps_path = format!("/proc/{}/maps", pid);
    let maps = std::fs::read_to_string(maps_path).ok()?;
    for line in maps.lines() {
        let mut parts = line.split_whitespace();
        let range = parts.next()?;
        let mut range_parts = range.split('-');
        let start = u64::from_str_radix(range_parts.next()?, 16).ok()?;
        let end = u64::from_str_radix(range_parts.next()?, 16).ok()?;
        let perms = parts.next()?;
        let file_offset_str = parts.next()?;
        let file_offset = u64::from_str_radix(file_offset_str, 16).ok()?;
        if ip >= start && ip < end {
            let offset = ip - start + file_offset;
            let file = parts.last().unwrap_or("").to_string();
            return Some((file, offset));
        }
    }
    None
}

// resolve symbol name from the executable file
fn resolve_symbol(file: &str, offset: u64) -> Option<String> {
    let data = std::fs::read(file).ok()?;
    let obj_file = object::File::parse(&*data).ok()?;
    for symbol in obj_file.symbols() {
        if symbol.address() <= offset && offset < symbol.address() + symbol.size() {
            return Some(symbol.name().unwrap_or("<unknown>").to_string());
        }
    }
    None
}

fn update_status_in_file(filename: &str, address: usize) -> std::io::Result<()> {
    let file = fs::File::open(filename)?;
    let reader = BufReader::new(file);
    let mut lines: Vec<String> = Vec::new();
    let mut found = false;

    let address_str = format!("address=0x{:x}", address);

    for line in reader.lines() {
        let line = line?;
        if (line.contains("malloc: LEAK") || line.contains("calloc: LEAK") || line.contains("realloc: LEAK")) && line.contains(&address_str) {
            let updated_line = line.replace("LEAK", "freed");
            lines.push(updated_line);
            found = true;
        } else {
            lines.push(line);
        }
    }

    if found {
        // Write back to the file
        let file = fs::File::create(filename)?;
        let mut writer = BufWriter::new(file);
        for line in lines {
            writeln!(writer, "{}", line)?;
        }
    }
    Ok(())
}

fn resolve_file_line(file: &str, addr: u64) -> Option<(String, u32)> {
    // Read the binary file into memory
    let data = std::fs::read(file).ok()?;
    let object = object::File::parse(&*data).ok()?;
    let ctx = Context::new(&object).ok()?;

    // addr2line expects the address as a u64
    match ctx.find_frames(addr) {
        addr2line::LookupResult::Output(Ok(mut frames)) => {
            loop {
                match frames.next() {
                    Ok(Some(frame)) => {
                        if let (Some(file), Some(line)) = (frame.location.as_ref().and_then(|l| l.file), frame.location.as_ref().and_then(|l| l.line)) {
                            return Some((file.to_string(), line));
                        }
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        }
        _ => {}
    }
    None
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/memleak_catch"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    let php_pids = php_fpm_pids();

    let malloc_entry: &mut UProbe = ebpf.program_mut("malloc_entry").unwrap().try_into()?;
    malloc_entry.load()?;
    for pid in &php_pids {
        malloc_entry.attach(Some("malloc"), 0, "/lib/x86_64-linux-gnu/libc.so.6", Some(*pid))?;
    }

    let calloc_entry: &mut UProbe = ebpf.program_mut("calloc_entry").unwrap().try_into()?;
    calloc_entry.load()?;
    for pid in &php_pids {
        calloc_entry.attach(Some("calloc"), 0, "/lib/x86_64-linux-gnu/libc.so.6", Some(*pid))?;
    }

    let realloc_entry: &mut UProbe = ebpf.program_mut("realloc_entry").unwrap().try_into()?;
    realloc_entry.load()?;
    for pid in &php_pids {
        realloc_entry.attach(Some("realloc"), 0, "/lib/x86_64-linux-gnu/libc.so.6", Some(*pid))?;
    }

    let malloc_exit: &mut UProbe = ebpf.program_mut("malloc_exit").unwrap().try_into()?;
    malloc_exit.load()?;
    for pid in &php_pids {
        malloc_exit.attach(Some("malloc"), 0, "/lib/x86_64-linux-gnu/libc.so.6", Some(*pid))?;
    }

    let calloc_exit: &mut UProbe = ebpf.program_mut("calloc_exit").unwrap().try_into()?;
    calloc_exit.load()?;
    for pid in &php_pids {
        calloc_exit.attach(Some("calloc"), 0, "/lib/x86_64-linux-gnu/libc.so.6", Some(*pid))?;
    }

    let realloc_exit: &mut UProbe = ebpf.program_mut("realloc_exit").unwrap().try_into()?;
    realloc_exit.load()?;
    for pid in &php_pids {
        realloc_exit.attach(Some("realloc"), 0, "/lib/x86_64-linux-gnu/libc.so.6", Some(*pid))?;
    }

    let free_entry: &mut UProbe = ebpf.program_mut("free_entry").unwrap().try_into()?;
    free_entry.load()?;
    for pid in &php_pids {
        free_entry.attach(Some("free"), 0, "/lib/x86_64-linux-gnu/libc.so.6", Some(*pid))?;
    }

    let mut ringbuf = RingBuf::try_from(ebpf.map("EVENTS").unwrap())?;

    // stack_traces is a StackTraceMap
    // https://docs.rs/aya/latest/aya/maps/stack_trace/struct.StackTraceMap.html
    let stack_traces = StackTraceMap::try_from(ebpf.map("STACK_TRACES").unwrap())?;

    let mut output_file = None;
    let mut filename = None;
    unsafe {
        let mut t: time_t = time(ptr::null_mut());
        let tm: *mut tm = localtime(&mut t);
        let mut buf = [0u8; 64];
        // Format: output_day_month_hour_minute.txt
        strftime(
            buf.as_mut_ptr() as *mut i8,
            buf.len(),
            b"%d_%m_%H_%M\0".as_ptr() as *const i8,
            tm,
        );
        let cstr = CStr::from_ptr(buf.as_ptr() as *const i8);
        filename = Some(format!("output_{}.txt", cstr.to_str().unwrap()));
        output_file = Some(OpenOptions::new()
            .create(true)
            .append(true)
            .open(&filename.clone().unwrap())?);
        println!("Output file: {}", filename.clone().unwrap());
    }
    let mut writer = BufWriter::new(output_file.unwrap());
    println!("Press Ctrl+C to exit.");
    loop {
        select! {
            _ = tokio::signal::ctrl_c() => {
                println!("\nCtrl+C received, exiting.");
                break;
            }
            _ = async {
                if let Some(data) = ringbuf.next() {
                    let event = unsafe { *(data.as_ptr() as *const AllocEvent) };
                    if event.stack_id >= 0 {
                        if let Ok(trace) = stack_traces.get(&(event.stack_id as u32), 0) {
                            if let Some(first_frame) = trace.frames().iter().find(|frame| frame.ip != 0) {
                                let ip = first_frame.ip;
                                if let Some((file, offset)) = find_mapping_for_ip(event.pid_tid as i32, ip) {
                                    if file.ends_with(".so") && event.func_type != 2 {
                                        let line = match event.func_type {
                                            0 => format!("malloc: LEAK \taddress=0x{:x} \tsize={}", event.address, event.size),
                                            1 => format!("calloc: LEAK \taddress=0x{:x} \tsize={}", event.address, event.size),
                                            3 => format!("realloc: LEAK \taddress=0x{:x} \tsize={}", event.address, event.size),
                                            _ => String::new(),
                                        };
                                        let _ = writeln!(writer, "{}", line);
                                        let _ = writer.flush();
                                        let _ = writer.get_ref().sync_all();
                                        if let Some((src_file, src_line)) = resolve_file_line(&file, offset) {
                                            let _ = writeln!(writer, "\tsource: {}:{}", src_file, src_line);
                                            let _ = writer.flush();
                                            let _ = writer.get_ref().sync_all();
                                        }
                                        if let Some(symbol) = resolve_symbol(&file, offset) {
                                            let demangled = demangle(&symbol).to_string();
                                            let _ = writeln!(writer, "\tfile: {}\n\tfunction: {}\n", file, demangled);
                                            let _ = writer.flush();
                                            let _ = writer.get_ref().sync_all();
                                        } else {
                                            let _ = writeln!(writer, "\tfile: {}\n\tfunction: <unknown>\n", file);
                                            let _ = writer.flush();
                                            let _ = writer.get_ref().sync_all();
                                        }
                                    }
                                    if event.func_type == 2 {
                                        let _ = update_status_in_file(&filename.clone().unwrap(), event.address);
                                    }
                                }
                            }
                        }
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            } => {}
        }
    }
    Ok(())
}