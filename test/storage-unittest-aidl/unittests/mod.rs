use android_hardware_security_see_storage::aidl::android::hardware::security::see::storage::{
    CreationMode::CreationMode, FileMode::FileMode, ISecureStorage as SecureStorage,
    IStorageSession::IStorageSession, OpenOptions::OpenOptions,
};
use binder::ExceptionCode;
use test::{assert_ok, expect, fail};

mod helpers;
use helpers::{ensure_deleted, Exists};

const CREATE_EXCLUSIVE: &'static OpenOptions = &OpenOptions {
    createMode: CreationMode::CREATE_EXCLUSIVE,
    accessMode: FileMode::READ_WRITE,
    truncateOnOpen: true,
};

const NO_CREATE: &'static OpenOptions = &OpenOptions {
    createMode: CreationMode::NO_CREATE,
    accessMode: FileMode::READ_WRITE,
    truncateOnOpen: false,
};

pub(crate) fn create_delete(ss: &(impl IStorageSession + ?Sized)) {
    let fname = "test_create_delete_file";
    assert_ok!(ensure_deleted(ss, fname, Exists::Unknown));

    {
        // Create file
        let _file = assert_ok!(ss.openFile(fname, CREATE_EXCLUSIVE));
        assert_ok!(ss.commitChanges());

        // Try to create file again
        match ss.openFile(fname, CREATE_EXCLUSIVE) {
            Ok(_) => fail!("openFile (on existing file) unexpectedly succeeded"),
            Err(e)
                if e.exception_code() == ExceptionCode::SERVICE_SPECIFIC
                    && e.service_specific_error() == SecureStorage::ERR_ALREADY_EXISTS =>
            {
                ()
            }
            Err(e) => fail!("openFile (on existing file) failed with: {}", e),
        };
        assert_ok!(ss.commitChanges());

        // File closes
    }

    assert_ok!(ensure_deleted(ss, fname, Exists::Must));
}

pub(crate) fn create_move_delete(ss: &(impl IStorageSession + ?Sized)) {
    let fname1 = "test_create_move_delete_1_file";
    let fname2 = "test_create_move_delete_2_file";

    assert_ok!(ensure_deleted(ss, fname1, Exists::Unknown));
    assert_ok!(ensure_deleted(ss, fname2, Exists::Unknown));

    {
        // Create file
        let file = assert_ok!(ss.openFile(fname1, CREATE_EXCLUSIVE));
        assert_ok!(ss.commitChanges());

        // Move fname1 -> fname2
        assert_ok!(file.rename(fname2, CreationMode::CREATE_EXCLUSIVE));
        assert_ok!(ss.commitChanges());

        // Try to create fname2, with file still alive
        match ss.openFile(fname2, CREATE_EXCLUSIVE) {
            Ok(_) => fail!("openFile unexpectedly succeeded"),
            Err(e)
                if e.exception_code() == ExceptionCode::SERVICE_SPECIFIC
                    && e.service_specific_error() == SecureStorage::ERR_ALREADY_EXISTS =>
            {
                ()
            }
            Err(e) => fail!("openFile failed with unexpected error: {}", e),
        };
        assert_ok!(ss.commitChanges());

        // file closes
    }

    // Try to create fname2, now that file is closed
    match ss.openFile(fname2, CREATE_EXCLUSIVE) {
        Ok(_) => fail!("openFile unexpectedly succeeded"),
        Err(e)
            if e.exception_code() == ExceptionCode::SERVICE_SPECIFIC
                && e.service_specific_error() == SecureStorage::ERR_ALREADY_EXISTS =>
        {
            ()
        }
        Err(e) => fail!("openFile failed with unexpected error: {}", e),
    };
    assert_ok!(ss.commitChanges());

    {
        // Recreate fname1
        let file = assert_ok!(ss.openFile(fname1, CREATE_EXCLUSIVE));
        assert_ok!(ss.commitChanges());

        // Move doesn't work now that fname2 exists
        match file.rename(fname2, CreationMode::CREATE_EXCLUSIVE) {
            Ok(_) => panic!("rename unexpectedly succeeded"),
            Err(e)
                if e.exception_code() == ExceptionCode::SERVICE_SPECIFIC
                    && e.service_specific_error() == SecureStorage::ERR_ALREADY_EXISTS =>
            {
                ()
            }
            Err(e) => panic!("rename failed with unexpected error: {}", e),
        };

        // file closes
    }

    assert_ok!(ensure_deleted(ss, fname1, Exists::Must));
    assert_ok!(ensure_deleted(ss, fname2, Exists::Must));
}

pub(crate) fn file_list(ss: &(impl IStorageSession + ?Sized)) {
    use core::array::from_fn;
    use std::collections::HashSet;

    let fnames: [String; 100] = from_fn(|i| format!("test_file_list_{:02}_file", i));
    for fname in &fnames {
        assert_ok!(ensure_deleted(ss, fname, Exists::Unknown), "file: {}", fname);
    }

    {
        let dir = assert_ok!(ss.openDir(""));
        let filenames = assert_ok!(dir.readNextFilenames(0));
        expect!(filenames.is_empty(), "Found unexpected files: {:?}", filenames);
    }

    // Create, commit, and close file #0
    {
        let _file = assert_ok!(ss.openFile(&fnames[0], CREATE_EXCLUSIVE));
        assert_ok!(ss.commitChanges());
    }
    // Create and close (don't commit) other files
    for fname in &fnames[1..] {
        let _file = assert_ok!(ss.openFile(fname, CREATE_EXCLUSIVE), "for fname {}", fname);
    }

    let mut read_file_names = HashSet::new();
    {
        let dir = assert_ok!(ss.openDir(""));
        let mut filenames = assert_ok!(dir.readNextFilenames(0));
        while !filenames.is_empty() {
            for filename in filenames {
                let existed = read_file_names.replace(filename);
                if let Some(previous) = existed {
                    fail!("NextFilenameResult returned file more than once: {}", previous);
                }
            }
            filenames = assert_ok!(dir.readNextFilenames(0));
        }
    }
    assert_ok!(ss.commitChanges());

    // Clean up
    for fname in &fnames {
        assert_ok!(ensure_deleted(ss, fname, Exists::Must), "file: {}", fname);
    }

    let expected = fnames.into_iter().collect::<HashSet<_>>();
    let missing = expected.difference(&read_file_names).collect::<Vec<_>>();
    let extra = read_file_names.difference(&expected).collect::<Vec<_>>();

    expect!(missing.is_empty(), "Did not find the following expected files: {:?}", missing);
    expect!(extra.is_empty(), "Found the following unexpected files: {:?}", extra);
}

pub(crate) fn write_read_sequential(ss: &(impl IStorageSession + ?Sized)) {
    use helpers::{read_pattern, write_pattern};

    let fname = "test_write_read_sequential";
    let chunks = 32;
    let chunk_len = 2048;

    assert_ok!(ensure_deleted(ss, fname, Exists::Unknown));

    {
        let file = assert_ok!(ss.openFile(fname, CREATE_EXCLUSIVE));
        assert_ok!(ss.commitChanges());

        assert_ok!(write_pattern(&*file, 0, chunks, chunk_len));
        assert_ok!(ss.commitChanges());

        assert_ok!(read_pattern(&*file, 0, chunks, chunk_len));
    } // file closes

    {
        let file = assert_ok!(ss.openFile(fname, NO_CREATE));
        assert_ok!(read_pattern(&*file, 0, chunks, chunk_len));
    } // file closes

    assert_ok!(ensure_deleted(ss, fname, Exists::Must));
}
