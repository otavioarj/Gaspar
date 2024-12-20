//
// https://github.com/DimaKoz/meat-grinder/blob/master/distribution/const_properties.c

//

#ifndef GASPARZINHO_SYSPROPERTY_H
#define GASPARZINHO_SYSPROPERTY_H
// The user-visible version string. E.g., "1.0" or "3.4b5".
const char *const ANDROID_OS_BUILD_VERSION_RELEASE = "ro.build.version.release";
// The internal value used by the underlying source control to represent this build.
const char *const ANDROID_OS_BUILD_VERSION_INCREMENTAL = "ro.build.version.incremental";
// The current development codename, or the string "REL" if this is a release build.
const char *const ANDROID_OS_BUILD_VERSION_CODENAME = "ro.build.version.codename";
// The user-visible SDK version of the framework.
const char *const ANDROID_OS_BUILD_VERSION_SDK = "ro.build.version.sdk";

// * The end-user-visible name for the end product.
const char *const ANDROID_OS_BUILD_MODEL = "ro.product.model";
// The manufacturer of the product/hardware.
const char *const ANDROID_OS_BUILD_MANUFACTURER = "ro.product.manufacturer";
// The name of the underlying board, like= "goldfish".
const char *const ANDROID_OS_BUILD_BOARD = "ro.product.board";
// The brand (e.g., carrier) the software is customized for, if any.
const char *const ANDROID_OS_BUILD_BRAND = "ro.product.brand";
// The name of the industrial design.
const char *const ANDROID_OS_BUILD_DEVICE = "ro.product.device";
// The name of the overall product.
const char *const ANDROID_OS_BUILD_PRODUCT = "ro.product.name";
// The name of the hardware (from the kernel command line or /proc).
const char *const ANDROID_OS_BUILD_HARDWARE = "ro.hardware";
// The name of the instruction set (CPU type + ABI convention) of native code.
const char *const ANDROID_OS_BUILD_CPU_ABI = "ro.product.cpu.abi";
// The name of the second instruction set (CPU type + ABI convention) of native code.
const char *const ANDROID_OS_BUILD_CPU_ABI2 = "ro.product.cpu.abi2";

// A build ID string meant for displaying to the user.
const char *const ANDROID_OS_BUILD_DISPLAY = "ro.build.display.id";
const char *const ANDROID_OS_BUILD_HOST = "ro.build.host";
const char *const ANDROID_OS_BUILD_USER = "ro.build.user";
// Either a changelist number, or a label like= "M4-rc20".
const char *const ANDROID_OS_BUILD_ID = "ro.build.id";
// The type of build, like= "user" or= "eng".
const char *const ANDROID_OS_BUILD_TYPE = "ro.build.type";
// Comma-separated tags describing the build, like= "unsigned,debug".
const char *const ANDROID_OS_BUILD_TAGS = "ro.build.tags";

// A string that uniquely identifies this build. 'BRAND/PRODUCT/DEVICE:RELEASE/ID/VERSION.INCREMENTAL:TYPE/TAGS'.
const char *const ANDROID_OS_BUILD_FINGERPRINT = "ro.build.fingerprint";

const char *const ANDROID_OS_SECURE = "ro.secure";

const char *const ANDROID_OS_DEBUGGABLE = "ro.debuggable";
const char *const ANDROID_OS_SYS_INITD = "sys.initd";
const char *const ANDROID_OS_BUILD_SELINUX = "ro.build.selinux";
//see https://android.googlesource.com/platform/system/core/+/master/adb/services.cpp#86
const char *const SERVICE_ADB_ROOT = "service.adb.root";
#endif //GASPARZINHO_SYSPROPERTY_H
