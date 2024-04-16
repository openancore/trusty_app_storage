#![feature(c_str_literals)]

#[cfg(test)]
mod unittests;

#[cfg(test)]
mod tests {
    use crate::define_tests_for;
    use android_hardware_security_see_storage::aidl::android::hardware::security::see::storage::{
        FileAvailability::FileAvailability, FileIntegrity::FileIntegrity,
        FileProperties::FileProperties, ISecureStorage::ISecureStorage,
        IStorageSession::IStorageSession,
    };
    use binder::{Status, StatusCode, Strong};
    use core::ffi::CStr;
    use rpcbinder::RpcSession;
    use test::assert_ok;

    //This line is needed in order to run the unit tests in Trusty
    test::init!();

    fn connect() -> Result<Strong<dyn ISecureStorage>, StatusCode> {
        const STORAGE_AIDL_PORT_NAME: &CStr = c"com.android.hardware.security.see.storage";

        RpcSession::new().setup_trusty_client(STORAGE_AIDL_PORT_NAME)
    }

    fn start_session(properties: &FileProperties) -> Result<Strong<dyn IStorageSession>, Status> {
        connect()?.startSession(properties)
    }

    #[test]
    fn ping() {
        use binder::IBinder as _;

        let secure_storage = assert_ok!(connect());
        assert_ok!(secure_storage.as_binder().ping_binder());
    }

    const TP: &'static FileProperties = &FileProperties {
        integrity: FileIntegrity::TAMPER_PROOF_AT_REST,
        availability: FileAvailability::AFTER_USERDATA,
        persistent: false,
    };
    const TDEA: &'static FileProperties = &FileProperties {
        integrity: FileIntegrity::TAMPER_DETECT,
        availability: FileAvailability::BEFORE_USERDATA,
        persistent: false,
    };
    #[cfg(feature = "has_ns")]
    const TDP: &'static FileProperties = &FileProperties {
        integrity: FileIntegrity::TAMPER_DETECT,
        availability: FileAvailability::AFTER_USERDATA,
        persistent: true,
    };
    #[cfg(feature = "has_ns")]
    const TD: &'static FileProperties = &FileProperties {
        integrity: FileIntegrity::TAMPER_DETECT,
        availability: FileAvailability::AFTER_USERDATA,
        persistent: false,
    };

    define_tests_for!(tp, TP);
    define_tests_for!(tdea, TDEA);
    #[cfg(feature = "has_ns")]
    define_tests_for!(tdp, TDP);
    #[cfg(feature = "has_ns")]
    define_tests_for!(td, TD);

    #[macro_export]
    macro_rules! define_tests_for {
        ($mod_name:ident, $file_properties:ident) => {
            mod $mod_name {
                use super::$file_properties;
                use test::assert_ok;
                use $crate::{tests::start_session, unittests};

                #[test]
                fn create_delete() {
                    let ss = assert_ok!(start_session($file_properties));
                    unittests::create_delete(&*ss);
                }
                #[test]
                fn create_move_delete() {
                    let ss = assert_ok!(start_session($file_properties));
                    unittests::create_move_delete(&*ss);
                }
                #[test]
                fn file_list() {
                    let ss = assert_ok!(start_session($file_properties));
                    unittests::file_list(&*ss);
                }
                #[test]
                fn write_read_sequential() {
                    let ss = assert_ok!(start_session($file_properties));
                    unittests::write_read_sequential(&*ss);
                }
            }
        };
    }
}
