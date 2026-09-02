//! Audited Win32 boundary: suspended launch -> Job assignment -> resume.
//! This is process lifetime/resource containment, NOT a filesystem/network sandbox.
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs::OpenOptions,
    io::{self, Read},
    mem::{size_of, zeroed},
    os::windows::{ffi::OsStrExt, fs::OpenOptionsExt},
    path::PathBuf,
    ptr::{null, null_mut},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::ReadFile,
    System::{
        JobObjects::*,
        Pipes::{CreatePipe, PeekNamedPipe},
        Threading::*,
    },
};

pub struct ProcessRequest {
    pub executable: PathBuf,
    pub sha256: String,
    pub arguments: Vec<String>,
    pub working_directory: PathBuf,
    pub timeout: Duration,
    pub stdout_limit: usize,
    pub stderr_limit: usize,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Exited(u32),
    TimedOut,
    Cancelled,
    OutputLimit,
}
#[derive(Debug)]
pub struct ProcessResult {
    pub outcome: Outcome,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub process_id: u32,
    pub job_empty: bool,
}
pub trait ProcessExecution {
    fn run(&self, request: &ProcessRequest, cancel: &AtomicBool) -> io::Result<ProcessResult>;
}
pub struct WindowsProcessRunner;
impl ProcessExecution for WindowsProcessRunner {
    fn run(&self, request: &ProcessRequest, cancel: &AtomicBool) -> io::Result<ProcessResult> {
        execute(request, cancel)
    }
}
fn stopped_before_spawn(outcome: Outcome) -> ProcessResult {
    ProcessResult {
        outcome,
        stdout: Vec::new(),
        stderr: Vec::new(),
        process_id: 0,
        job_empty: true,
    }
}
fn interruption(cancel: &AtomicBool, start: Instant, timeout: Duration) -> Option<Outcome> {
    if cancel.load(Ordering::Acquire) {
        Some(Outcome::Cancelled)
    } else if start.elapsed() >= timeout {
        Some(Outcome::TimedOut)
    } else {
        None
    }
}
fn terminate_and_wait(process: HANDLE) -> io::Result<()> {
    checked(unsafe { TerminateProcess(process, 1) })?;
    if unsafe { WaitForSingleObject(process, 5000) } != WAIT_OBJECT_0 {
        return Err(io::Error::other(
            "Suspended process termination not confirmed",
        ));
    }
    Ok(())
}
struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0) };
        }
    }
}
fn checked(result: windows_sys::core::BOOL) -> io::Result<()> {
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn wide(value: &OsStr) -> io::Result<Vec<u16>> {
    let value: Vec<u16> = value.encode_wide().collect();
    if value.contains(&0) {
        return Err(io::Error::other("NUL rejected"));
    }
    Ok(value.into_iter().chain(Some(0)).collect())
}
fn quote(value: &str) -> String {
    let mut out = String::from("\"");
    let mut slashes = 0;
    for c in value.chars() {
        if c == '\\' {
            slashes += 1;
        } else {
            if c == '"' {
                out.push_str(&"\\".repeat(slashes * 2 + 1));
            } else {
                out.push_str(&"\\".repeat(slashes));
            }
            slashes = 0;
            out.push(c);
        }
    }
    out.push_str(&"\\".repeat(slashes * 2));
    out.push('"');
    out
}
fn pipe() -> io::Result<(Handle, Handle)> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let (mut read, mut write) = (null_mut(), null_mut());
    checked(unsafe { CreatePipe(&mut read, &mut write, &attributes, 0) })?;
    let pair = (Handle(read), Handle(write));
    checked(unsafe { SetHandleInformation(pair.0.0, HANDLE_FLAG_INHERIT, 0) })?;
    Ok(pair)
}
fn drain(pipe: &Handle, output: &mut Vec<u8>, limit: usize) -> io::Result<bool> {
    // At most 64 KiB per turn prevents a producer starving timeout/cancel checks.
    for _ in 0..16 {
        let mut available = 0;
        if unsafe {
            PeekNamedPipe(
                pipe.0,
                null_mut(),
                0,
                null_mut(),
                &mut available,
                null_mut(),
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
                Ok(false)
            } else {
                Err(error)
            };
        }
        if available == 0 {
            return Ok(false);
        }
        let mut buffer = [0u8; 4096];
        let mut read = 0;
        checked(unsafe {
            ReadFile(
                pipe.0,
                buffer.as_mut_ptr(),
                available.min(buffer.len() as u32),
                &mut read,
                null_mut(),
            )
        })?;
        let take = (read as usize).min(limit.saturating_sub(output.len()));
        output.extend_from_slice(&buffer[..take]);
        if take < read as usize {
            return Ok(true);
        }
    }
    Ok(false)
}
pub fn execute(request: &ProcessRequest, cancel: &AtomicBool) -> io::Result<ProcessResult> {
    let start = Instant::now();
    if let Some(reason) = interruption(cancel, start, request.timeout) {
        return Ok(stopped_before_spawn(reason));
    }
    if !request.executable.is_absolute()
        || !request.working_directory.is_absolute()
        || request.timeout.is_zero()
        || request.timeout > Duration::from_secs(600)
        || request.stdout_limit == 0
        || request.stdout_limit > 16 * 1024 * 1024
        || request.stderr_limit == 0
        || request.stderr_limit > 4 * 1024 * 1024
        || request.arguments.iter().any(|a| a.contains('\0'))
    {
        return Err(io::Error::other("Unsafe process request"));
    }
    // Reject network/device paths before potentially blocking canonicalization.
    fn fixed_disk_path(path: &std::path::Path) -> bool {
        use std::path::{Component, Prefix};
        let drive = match path.components().next() {
            Some(Component::Prefix(p)) => match p.kind() {
                Prefix::Disk(d) | Prefix::VerbatimDisk(d) => d,
                _ => return false,
            },
            _ => return false,
        };
        let root = [drive as u16, b':' as u16, b'\\' as u16, 0];
        unsafe { windows_sys::Win32::Storage::FileSystem::GetDriveTypeW(root.as_ptr()) == 3 }
    }
    if !fixed_disk_path(&request.executable) || !fixed_disk_path(&request.working_directory) {
        return Err(io::Error::other("Local fixed disk paths required"));
    }
    let executable = request.executable.canonicalize()?;
    let working_directory = request.working_directory.canonicalize()?;
    if !fixed_disk_path(&working_directory) || !working_directory.is_dir() {
        return Err(io::Error::other(
            "Resolved working directory must be a local directory",
        ));
    }
    if !fixed_disk_path(&executable) {
        return Err(io::Error::other("Resolved executable must be local"));
    }
    if executable
        .extension()
        .and_then(|s| s.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
        != Some("exe")
    {
        return Err(io::Error::other("Only approved native executables"));
    }
    // Deny write/delete sharing for the verified image through completion.
    let mut image = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&executable)?;
    let metadata = image.metadata()?;
    if !metadata.is_file() || metadata.len() > 512 * 1024 * 1024 {
        return Err(io::Error::other("Image is not regular or exceeds 512 MiB"));
    }
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        if let Some(reason) = interruption(cancel, start, request.timeout) {
            return Ok(stopped_before_spawn(reason));
        }
        let n = image.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    if format!("{:x}", digest.finalize()) != request.sha256.to_ascii_lowercase() {
        return Err(io::Error::other("Executable hash mismatch"));
    }
    let application = wide(executable.as_os_str())?;
    let directory = wide(working_directory.as_os_str())?;
    let name = executable
        .to_str()
        .ok_or_else(|| io::Error::other("Non-Unicode executable path"))?;
    let command = std::iter::once(name)
        .chain(request.arguments.iter().map(String::as_str))
        .map(quote)
        .collect::<Vec<_>>()
        .join(" ");
    let mut command = wide(OsStr::new(&command))?;
    if command.len() > 32767 {
        return Err(io::Error::other("Command line too long"));
    }
    let job = Handle(unsafe { CreateJobObjectW(null(), null()) });
    if job.0.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    limits.BasicLimitInformation.ActiveProcessLimit = 8;
    limits.ProcessMemoryLimit = 256 * 1024 * 1024;
    checked(unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    })?;
    let (out_read, out_write) = pipe()?;
    let (err_read, err_write) = pipe()?;
    let (in_read, in_write) = pipe()?;
    // Closed stdin is inherited by the child. Only these three handles can be inherited.
    checked(unsafe { SetHandleInformation(in_read.0, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) })?;
    drop(in_write);
    let handles = [in_read.0, out_write.0, err_write.0];
    let mut bytes = 0;
    unsafe { InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut bytes) };
    let mut attributes = vec![0usize; bytes.div_ceil(size_of::<usize>())];
    let attributes_ptr = attributes.as_mut_ptr().cast();
    checked(unsafe { InitializeProcThreadAttributeList(attributes_ptr, 1, 0, &mut bytes) })?;
    struct Attributes(LPPROC_THREAD_ATTRIBUTE_LIST);
    impl Drop for Attributes {
        fn drop(&mut self) {
            unsafe { DeleteProcThreadAttributeList(self.0) }
        }
    }
    let _attributes_guard = Attributes(attributes_ptr);
    checked(unsafe {
        UpdateProcThreadAttribute(
            attributes_ptr,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            handles.as_ptr().cast(),
            size_of_val(&handles),
            null_mut(),
            null(),
        )
    })?;
    let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = in_read.0;
    startup.StartupInfo.hStdOutput = out_write.0;
    startup.StartupInfo.hStdError = err_write.0;
    startup.lpAttributeList = attributes_ptr;
    let mut info: PROCESS_INFORMATION = unsafe { zeroed() };
    let environment = [0u16, 0u16];
    if let Some(reason) = interruption(cancel, start, request.timeout) {
        return Ok(stopped_before_spawn(reason));
    }
    checked(unsafe {
        CreateProcessW(
            application.as_ptr(),
            command.as_mut_ptr(),
            null(),
            null(),
            1,
            CREATE_SUSPENDED
                | CREATE_NO_WINDOW
                | CREATE_UNICODE_ENVIRONMENT
                | EXTENDED_STARTUPINFO_PRESENT,
            environment.as_ptr().cast(),
            directory.as_ptr(),
            &startup.StartupInfo,
            &mut info,
        )
    })?;
    let process = Handle(info.hProcess);
    let main_thread = Handle(info.hThread);
    if unsafe { AssignProcessToJobObject(job.0, process.0) } == 0 {
        let err = io::Error::last_os_error();
        terminate_and_wait(process.0)?;
        return Err(err);
    }
    if let Some(reason) = interruption(cancel, start, request.timeout) {
        terminate_and_wait(process.0)?;
        return Ok(ProcessResult {
            process_id: info.dwProcessId,
            ..stopped_before_spawn(reason)
        });
    }
    // No child code has run before successful assignment. Job drop kills on errors.
    if unsafe { ResumeThread(main_thread.0) } == u32::MAX {
        let error = io::Error::last_os_error();
        terminate_and_wait(process.0)?;
        return Err(error);
    }
    drop(main_thread);
    drop(out_write);
    drop(err_write);
    drop(in_read);
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let outcome = loop {
        if cancel.load(Ordering::Acquire) {
            break Outcome::Cancelled;
        }
        if start.elapsed() >= request.timeout {
            break Outcome::TimedOut;
        }
        if drain(&out_read, &mut stdout, request.stdout_limit)?
            || drain(&err_read, &mut stderr, request.stderr_limit)?
        {
            break Outcome::OutputLimit;
        }
        if unsafe { WaitForSingleObject(process.0, 0) } == WAIT_OBJECT_0 {
            let mut code = 0;
            checked(unsafe { GetExitCodeProcess(process.0, &mut code) })?;
            break Outcome::Exited(code);
        }
        thread::sleep(Duration::from_millis(5));
    };
    checked(unsafe { TerminateJobObject(job.0, 1) })?;
    if unsafe { WaitForSingleObject(process.0, 5000) } != WAIT_OBJECT_0 {
        return Err(io::Error::other("Process termination not confirmed"));
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
    loop {
        checked(unsafe {
            QueryInformationJobObject(
                job.0,
                JobObjectBasicAccountingInformation,
                (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                null_mut(),
            )
        })?;
        if accounting.ActiveProcesses == 0 {
            break;
        }
        if Instant::now() > deadline {
            return Err(io::Error::other("Job termination not confirmed"));
        }
        thread::sleep(Duration::from_millis(5));
    }
    let overflow = drain(&out_read, &mut stdout, request.stdout_limit)?
        | drain(&err_read, &mut stderr, request.stderr_limit)?;
    let outcome = if overflow {
        Outcome::OutputLimit
    } else {
        outcome
    };
    Ok(ProcessResult {
        outcome,
        stdout,
        stderr,
        process_id: info.dwProcessId,
        job_empty: true,
    })
}
