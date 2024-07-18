use android_hardware_security_see_storage::aidl::android::hardware::security::see::storage::{
    IFile::IFile, ISecureStorage as SecureStorage, IStorageSession::IStorageSession,
};
use binder::ExceptionCode;

pub(crate) enum Exists {
    Must,
    MustNot,
    Unknown,
}

pub(crate) fn ensure_deleted(
    ss: &(impl IStorageSession + ?Sized),
    fname: &str,
    expectation: Exists,
) -> Result<(), String> {
    // Try to delete file
    let rc = ss.deleteFile(fname);
    match rc {
        Ok(()) => {
            if let Exists::MustNot = expectation {
                return Err(format!(
                    "deleteFile succeeded, but the file (name: {}) shouldn't have exisited",
                    fname
                ));
            }
        }
        Err(e)
            if e.exception_code() == ExceptionCode::SERVICE_SPECIFIC
                && e.service_specific_error() == SecureStorage::ERR_NOT_FOUND =>
        {
            if let Exists::Must = expectation {
                return Err(format!(
                    "deleteFile failed (for {}) with ERR_NOT_FOUND, but the file should have existed",
                    fname
                ));
            }
            ss.commitChanges().map_err(|e| format!("commitChanges failed with: {}", e))?;
            return Ok(());
        }
        Err(e) => {
            return Err(format!("deleteFile failed (for {}) with unexpected error: {}", fname, e))
        }
    };
    ss.commitChanges().map_err(|e| format!("commitChanges failed with: {}", e))?;

    // If delete succeeded, try again to make sure it doesn't exist now
    ensure_deleted(ss, fname, Exists::MustNot)
        .map_err(|s| format!("while ensuring non-existence, {}", s))
}

fn check_pattern32(offset: usize, buf: &[u8]) -> Result<(), String> {
    const U32_SIZE: usize = std::mem::size_of::<u32>();
    let mut pattern: u32 = (offset / U32_SIZE).try_into().unwrap();

    let mut chunks = buf.chunks_exact(U32_SIZE);
    for chunk in &mut chunks {
        let actual = u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        if actual != pattern {
            return Err(format!("Expected to read {}, but found {}", pattern, actual));
        }
        pattern += 1;
    }

    let rem = chunks.remainder();
    for byte in rem {
        if *byte != 0 {
            return Err(format!(
                "Expected unpatterned portion of read to be zeroed; found {:x?}",
                rem
            ));
        }
    }
    Ok(())
}

fn fill_pattern32(offset: usize, buf: &mut [u8]) {
    const U32_SIZE: usize = std::mem::size_of::<u32>();
    let mut pattern: u32 = (offset / U32_SIZE).try_into().unwrap();

    for chunk in buf.chunks_exact_mut(U32_SIZE) {
        let bytes = pattern.to_ne_bytes();
        for i in 0..U32_SIZE {
            chunk[i] = bytes[i];
        }
        pattern += 1;
    }
}

fn check_valid_size(chunk_len: usize) -> Result<(), String> {
    if chunk_len % std::mem::size_of::<u32>() != 0 {
        return Err(format!("Chunk size ({}) not 32-bit aligned.", chunk_len));
    }
    Ok(())
}

pub(crate) fn write_pattern(
    file: &dyn IFile,
    offset: usize,
    chunks: usize,
    chunk_len: usize,
) -> Result<(), String> {
    check_valid_size(chunk_len)?;
    let mut buf = vec![0; chunk_len];

    for i in 0..chunks {
        let chunk_offset = offset + i * chunk_len;
        fill_pattern32(chunk_offset, &mut buf);
        let written = file
            .write(chunk_offset.try_into().unwrap(), &buf)
            .map_err(|e| format!("Encountered error calling write (chunk {}): {}", i, e))?;
        if written != chunk_len.try_into().unwrap() {
            return Err(format!(
                "Wrote {} bytes to chunk {}, but expected to write {}",
                written, i, chunk_len,
            ));
        }
    }

    Ok(())
}

pub(crate) fn read_pattern(
    file: &dyn IFile,
    offset: usize,
    chunks: usize,
    chunk_len: usize,
) -> Result<(), String> {
    check_valid_size(chunk_len)?;

    for i in 0..chunks {
        let chunk_offset = offset + i * chunk_len;
        let read = file
            .read(chunk_len.try_into().unwrap(), chunk_offset.try_into().unwrap())
            .map_err(|e| format!("Encountered error calling read (chunk {}): {}", i, e))?;
        if read.len() != chunk_len {
            return Err(format!(
                "Read {} bytes from chunk {}, but expected to read {}",
                read.len(),
                i,
                chunk_len,
            ));
        }
        check_pattern32(chunk_offset, &*read).map_err(|e| format!("For chunk {}: {}", i, e))?;
    }

    Ok(())
}
