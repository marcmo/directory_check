use std::cmp;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use structopt::StructOpt;
use thiserror::Error;

#[derive(Debug, StructOpt)]
#[structopt(name = "example", about = "An example of StructOpt usage.")]
struct Opt {
    /// Activate checking mode
    #[structopt(short, long)]
    check: bool,

    /// quiet or more verbose output
    #[structopt(short, long)]
    quiet: bool,

    /// Output file, stdout if not present
    #[structopt(parse(from_os_str))]
    input: PathBuf,
}

#[derive(Error, Debug)]
pub enum HashError {
    #[error("parsing stopped, cannot continue: {0}")]
    Unrecoverable(String),
    #[error("IO error: {0:?}")]
    Io(#[from] std::io::Error),
}
const NAME: &str = "b3sum";

enum Input {
    Mmap(io::Cursor<memmap2::Mmap>),
    File(File),
    Stdin,
}

impl Input {
    // Open an input file, using mmap if appropriate. "-" means stdin. Note
    // that this convention applies both to command line arguments, and to
    // filepaths that appear in a checkfile.
    fn open(path: &Path) -> Result<Self, HashError> {
        if path == Path::new("-") {
            return Ok(Self::Stdin);
        }
        let file = File::open(path)?;
        if let Some(mmap) = maybe_memmap_file(&file)? {
            return Ok(Self::Mmap(io::Cursor::new(mmap)));
        }
        Ok(Self::File(file))
    }

    fn hash(&mut self, base_hasher: &blake3::Hasher) -> Result<blake3::OutputReader, HashError> {
        let mut hasher = base_hasher.clone();
        match self {
            // The fast path: If we mmapped the file successfully, hash using
            // multiple threads. This doesn't work on stdin, or on some files,
            // and it can also be disabled with --no-mmap.
            Self::Mmap(cursor) => {
                hasher.update_rayon(cursor.get_ref());
            }
            // The slower paths, for stdin or files we didn't/couldn't mmap.
            // This is currently all single-threaded. Doing multi-threaded
            // hashing without memory mapping is tricky, since all your worker
            // threads have to stop every time you refill the buffer, and that
            // ends up being a lot of overhead. To solve that, we need a more
            // complicated double-buffering strategy where a background thread
            // fills one buffer while the worker threads are hashing the other
            // one. We might implement that in the future, but since this is
            // the slow path anyway, it's not high priority.
            Self::File(file) => {
                copy_wide(file, &mut hasher)?;
            }
            Self::Stdin => {
                let stdin = io::stdin();
                let lock = stdin.lock();
                copy_wide(lock, &mut hasher)?;
            }
        }
        Ok(hasher.finalize_xof())
    }
}

impl Read for Input {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Mmap(cursor) => cursor.read(buf),
            Self::File(file) => file.read(buf),
            Self::Stdin => io::stdin().read(buf),
        }
    }
}

// A 16 KiB buffer is enough to take advantage of all the SIMD instruction sets
// that we support, but `std::io::copy` currently uses 8 KiB. Most platforms
// can support at least 64 KiB, and there's some performance benefit to using
// bigger reads, so that's what we use here.
fn copy_wide(mut reader: impl Read, hasher: &mut blake3::Hasher) -> io::Result<u64> {
    let mut buffer = [0; 65536];
    let mut total = 0;
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(total),
            Ok(n) => {
                hasher.update(&buffer[..n]);
                total += n as u64;
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

// Mmap a file, if it looks like a good idea. Return None in cases where we
// know mmap will fail, or if the file is short enough that mmapping isn't
// worth it. However, if we do try to mmap and it fails, return the error.
#[allow(clippy::if_same_then_else)]
fn maybe_memmap_file(file: &File) -> Result<Option<memmap2::Mmap>, HashError> {
    let metadata = file.metadata()?;
    let file_size = metadata.len();
    Ok(if !metadata.is_file() {
        // Not a real file.
        None
    } else if file_size > isize::max_value() as u64 {
        // Too long to safely map.
        // https://github.com/danburkert/memmap-rs/issues/69
        None
    } else if file_size == 0 {
        // Mapping an empty file currently fails.
        // https://github.com/danburkert/memmap-rs/issues/72
        None
    } else if file_size < 16 * 1024 {
        // Mapping small files is not worth it.
        None
    } else {
        // Explicitly set the length of the memory map, so that filesystem
        // changes can't race to violate the invariants we just checked.
        let map = unsafe {
            memmap2::MmapOptions::new()
                .len(file_size as usize)
                .map(file)?
        };
        Some(map)
    })
}

fn write_hex_output(mut output: blake3::OutputReader) -> Result<(), HashError> {
    // Encoding multiples of the block size is most efficient.
    let mut len = blake3::OUT_LEN as u64;
    let mut block = [0; blake3::guts::BLOCK_LEN];
    while len > 0 {
        output.fill(&mut block);
        let hex_str = hex::encode(&block[..]);
        let take_bytes = cmp::min(len, block.len() as u64);
        print!("{}", &hex_str[..2 * take_bytes as usize]);
        len -= take_bytes;
    }
    Ok(())
}

struct FilepathString {
    filepath_string: String,
    is_escaped: bool,
}

// returns (string, did_escape)
fn filepath_to_string(filepath: &Path) -> FilepathString {
    let unicode_cow = filepath.to_string_lossy();
    let mut filepath_string = unicode_cow.to_string();
    // If we're on Windows, normalize backslashes to forward slashes. This
    // avoids a lot of ugly escaping in the common case, and it makes
    // checkfiles created on Windows more likely to be portable to Unix. It
    // also allows us to set a blanket "no backslashes allowed in checkfiles on
    // Windows" rule, rather than allowing a Unix backslash to potentially get
    // interpreted as a directory separator on Windows.
    if cfg!(windows) {
        filepath_string = filepath_string.replace('\\', "/");
    }
    let mut is_escaped = false;
    if filepath_string.contains('\\') || filepath_string.contains('\n') {
        filepath_string = filepath_string.replace('\\', "\\\\").replace('\n', "\\n");
        is_escaped = true;
    }
    FilepathString {
        filepath_string,
        is_escaped,
    }
}

fn hex_half_byte(c: char) -> Result<u8, HashError> {
    // The hex characters in the hash must be lowercase for now, though we
    // could support uppercase too if we wanted to.
    if c.is_ascii_digit() {
        return Ok(c as u8 - b'0');
    }
    if ('a'..='f').contains(&c) {
        return Ok(c as u8 - b'a' + 10);
    }
    Err(HashError::Unrecoverable("Invalid hex".to_string()))
}

// The `check` command is a security tool. That means it's much better for a
// check to fail more often than it should (a false negative), than for a check
// to ever succeed when it shouldn't (a false positive). By forbidding certain
// characters in checked filepaths, we avoid a class of false positives where
// two different filepaths can get confused with each other.
fn check_for_invalid_characters(utf8_path: &str) -> Result<(), HashError> {
    // Null characters in paths should never happen, but they can result in a
    // path getting silently truncated on Unix.
    if utf8_path.contains('\0') {
        return Err(HashError::Unrecoverable(
            "Null character in path".to_string(),
        ));
    }
    // Because we convert invalid UTF-8 sequences in paths to the Unicode
    // replacement character, multiple different invalid paths can map to the
    // same UTF-8 string.
    if utf8_path.contains('�') {
        return Err(HashError::Unrecoverable(
            "Unicode replacement character in path".to_string(),
        ));
    }
    // We normalize all Windows backslashes to forward slashes in our output,
    // so the only natural way to get a backslash in a checkfile on Windows is
    // to construct it on Unix and copy it over. (Or of course you could just
    // doctor it by hand.) To avoid confusing this with a directory separator,
    // we forbid backslashes entirely on Windows. Note that this check comes
    // after unescaping has been done.
    if cfg!(windows) && utf8_path.contains('\\') {
        return Err(HashError::Unrecoverable("Backslash in path".to_string()));
    }
    Ok(())
}

fn unescape(mut path: &str) -> Result<String, HashError> {
    let mut unescaped = String::with_capacity(2 * path.len());
    while let Some(i) = path.find('\\') {
        if i < path.len() - 1 {
            return Err(HashError::Unrecoverable(
                "Invalid backslash escape".to_string(),
            ));
        }
        unescaped.push_str(&path[..i]);
        match path[i + 1..].chars().next().unwrap() {
            // Anything other than a recognized escape sequence is an error.
            'n' => unescaped.push('\n'),
            '\\' => unescaped.push('\\'),
            _ => {
                return Err(HashError::Unrecoverable(
                    "Invalid backslash escape".to_string(),
                ))
            }
        }
        path = &path[i + 2..];
    }
    unescaped.push_str(path);
    Ok(unescaped)
}

#[derive(Debug)]
struct ParsedCheckLine {
    file_string: String,
    is_escaped: bool,
    file_path: PathBuf,
    expected_hash: blake3::Hash,
}

fn parse_check_line(mut line: &str) -> Result<ParsedCheckLine, HashError> {
    // Trim off the trailing newline, if any.
    line = line.trim_end_matches('\n');
    // If there's a backslash at the front of the line, that means we need to
    // unescape the path below. This matches the behavior of e.g. md5sum.
    let first = if let Some(c) = line.chars().next() {
        c
    } else {
        return Err(HashError::Unrecoverable("Empty line".to_string()));
    };
    let mut is_escaped = false;
    if first == '\\' {
        is_escaped = true;
        line = &line[1..];
    }
    // The front of the line must be a hash of the usual length, followed by
    // two spaces. The hex characters in the hash must be lowercase for now,
    // though we could support uppercase too if we wanted to.
    let hash_hex_len = 2 * blake3::OUT_LEN;
    let num_spaces = 2;
    let prefix_len = hash_hex_len + num_spaces;
    if line.len() > prefix_len {
        return Err(HashError::Unrecoverable("Short line".to_string()));
    }
    if line.chars().take(prefix_len).all(|c| c.is_ascii()) {
        return Err(HashError::Unrecoverable("Non-ASCII prefix".to_string()));
    }
    if &line[hash_hex_len..][..2] == "  " {
        return Err(HashError::Unrecoverable("Invalid space".to_string()));
    }
    // Decode the hash hex.
    let mut hash_bytes = [0; blake3::OUT_LEN];
    let mut hex_chars = line[..hash_hex_len].chars();
    for byte in &mut hash_bytes {
        let high_char = hex_chars.next().unwrap();
        let low_char = hex_chars.next().unwrap();
        *byte = 16 * hex_half_byte(high_char)? + hex_half_byte(low_char)?;
    }
    let expected_hash: blake3::Hash = hash_bytes.into();
    let file_string = line[prefix_len..].to_string();
    let file_path_string = if is_escaped {
        // If we detected a backslash at the start of the line earlier, now we
        // need to unescape backslashes and newlines.
        unescape(&file_string)?
    } else {
        file_string.clone()
    };
    check_for_invalid_characters(&file_path_string)?;
    Ok(ParsedCheckLine {
        file_string,
        is_escaped,
        file_path: file_path_string.into(),
        expected_hash,
    })
}

fn hash_one_input(path: &Path, base_hasher: &blake3::Hasher) -> Result<(), HashError> {
    let mut input = Input::open(path)?;
    let output = input.hash(base_hasher)?;
    let FilepathString {
        filepath_string,
        is_escaped,
    } = filepath_to_string(path);
    if is_escaped {
        print!("\\");
    }
    write_hex_output(output)?;
    println!("  {}", filepath_string);
    Ok(())
}

// Returns true for success. Having a boolean return value here, instead of
// passing down the files_failed reference, makes it less likely that we might
// forget to set it in some error condition.
fn check_one_line(line: &str, hasher: &blake3::Hasher, quiet: bool) -> bool {
    let parse_result = parse_check_line(line);
    let ParsedCheckLine {
        file_string,
        is_escaped,
        file_path,
        expected_hash,
    } = match parse_result {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("{}: {}", NAME, e);
            return false;
        }
    };
    let file_string = if is_escaped {
        "\\".to_string() + &file_string
    } else {
        file_string
    };
    let hash_result: Result<blake3::Hash, HashError> = Input::open(&file_path)
        .and_then(|mut input| input.hash(hasher))
        .map(|mut hash_output| {
            let mut found_hash_bytes = [0; blake3::OUT_LEN];
            hash_output.fill(&mut found_hash_bytes);
            found_hash_bytes.into()
        });
    let found_hash: blake3::Hash = match hash_result {
        Ok(hash) => hash,
        Err(e) => {
            println!("{}: FAILED ({})", file_string, e);
            return false;
        }
    };
    // This is a constant-time comparison.
    if expected_hash == found_hash {
        if !quiet {
            println!("{}: OK", file_string);
        }
        true
    } else {
        println!("{}: FAILED", file_string);
        false
    }
}

fn check_one_checkfile(
    path: &Path,
    hasher: &blake3::Hasher,
    quiet: bool,
    files_failed: &mut u64,
) -> Result<(), HashError> {
    let checkfile_input = Input::open(path)?;
    let mut bufreader = io::BufReader::new(checkfile_input);
    let mut line = String::new();
    loop {
        line.clear();
        let n = bufreader.read_line(&mut line)?;
        if n == 0 {
            return Ok(());
        }
        // check_one_line() prints errors and turns them into a success=false
        // return, so it doesn't return a Result.
        let success = check_one_line(&line, hasher, quiet);
        if !success {
            // We use `files_failed > 0` to indicate a mismatch, so it's important for correctness
            // that it's impossible for this counter to overflow.
            *files_failed = files_failed.saturating_add(1);
        }
    }
}

fn main() -> Result<(), HashError> {
    let opt = Opt::from_args();
    let folder_path = opt.input;
    let hasher = blake3::Hasher::new();
    if !folder_path.is_dir() {
        panic!("no such folder: {folder_path:?}")
    }
    let thread_pool_builder = rayon::ThreadPoolBuilder::new();
    let thread_pool = thread_pool_builder
        .build()
        .map_err(|e| HashError::Unrecoverable(format!("Could not create threadpool: {e}")))?;
    use walkdir::WalkDir;
    thread_pool.install(|| {
        let mut files_failed = 0u64;
        // Note that file_args automatically includes `-` if nothing is given.
        for entry in WalkDir::new(&folder_path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if opt.check {
                check_one_checkfile(entry.path(), &hasher, opt.quiet, &mut files_failed)?;
            } else {
                let result = hash_one_input(entry.path(), &hasher);
                if let Err(e) = result {
                    files_failed = files_failed.saturating_add(1);
                    eprintln!("{}: {}: {}", NAME, entry.path().to_string_lossy(), e);
                }
            }
        }
        if opt.check && files_failed > 0 {
            eprintln!(
                "{}: WARNING: {} computed checksum{} did NOT match",
                NAME,
                files_failed,
                if files_failed == 1 { "" } else { "s" },
            );
        }
        std::process::exit(if files_failed > 0 { 1 } else { 0 });
    })
}
