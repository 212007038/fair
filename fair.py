###############################################################################
# fair.py
#
# A python script that will verify the CP binary readback file FROM the vendor.
#
#


# region Import region

import os
import argparse  # command line parser
from struct import *
from intelhex import IntelHex
from hashlib import sha1

# endregion

# region Global region

__version__ = '1.0'  # version of script

###############################################################################
##### CP #########
# FLASH MAP defines
CP_FLASH_BOOTLOADER_SIZE = 0x2000                                          # Bootloader region size(8K)
CP_DFU1_SIZE = 0x6000                                                      # DFU1 region size(24K)
CP_DFU2_SIZE = CP_DFU1_SIZE                                                   # DFU2 region size(24K)
CP_MAIN_APP_SIZE = 0x10000                                                 # MainApp region size(64K)
CP_BOOTLOADER_START_ADDRESS = 0x00000000
CP_DFU1_START_ADDRESS = (CP_BOOTLOADER_START_ADDRESS + CP_FLASH_BOOTLOADER_SIZE) # 0x08002000
CP_DFU2_START_ADDRESS = (CP_DFU1_START_ADDRESS + CP_DFU1_SIZE)                   # 0x08008000
CP_MAIN_APP_START_ADDRESS = (CP_DFU2_START_ADDRESS + CP_DFU2_SIZE)               # 0x0800e000
CP_MAIN_APP_END_ADDRESS = (CP_MAIN_APP_START_ADDRESS + CP_MAIN_APP_SIZE)         # 0x0801e000


# Offset to the version with reference to start address of the corresponding image
CP_VERSION_POINTER_OFFSET = 0xf4
# Offset to the checksum with reference to start address of the corresponding image
CP_CHECKSUM_POINTER_OFFSET = 0xf8
# Offset to the compatibility version with reference to MainAPP start address
CP_COMPATIBILITY_VERSION_POINTER_OFFSET = 0xfc


###############################################################################
##### AP #########
AP_MAIN_APP_STARTING_ADDR = 0x00000000  # Main ACQ SW starting address
AP_MAIN_APP_ENDING_ADDR = 0x0001FDFF    # Main ACQ SW ending address, last page of FLASH is left as data sheet says
AP_FLASH_START_ADDR = AP_MAIN_APP_STARTING_ADDR    # Flash start address
AP_FLASH_END_ADDR = 0x0001FFFF          # Flash end address
AP_SW_VEAP_SION_INVALID = 0x00000000    # Invalid software version
AP_CHECKSUM_POINTER_OFFSET = 0x00E4
AP_VERSION_POINTER_OFFSET = 0x00E0

# The number of segments we expect in our hex file.
EXPECTED_SEGMENT_COUNT = 5

# endregion

# region Function region
def calc_sha1(start_address, end_address, hf):
    """Return the sha1 of the given address range from the given list.

    Args:
        start_address : The start address of the data.
        end_address : The end address of the data.
        hf : the list containing the data

    Returns:
        The sha1 value of the section data.

    """
    byte_count = end_address-start_address
    image = [hf[start_address + i] for i in xrange(byte_count)]
    image_sha1 = sha1(bytearray(image)).hexdigest()
    return image_sha1


# endregion

# region Arguments region

###############################################################################

parser = argparse.ArgumentParser(description="Process an exported LeCroy CSV file (from spreadsheet view)")
parser.add_argument('-i', dest='binary_filename',
                    help='Name of binary file to read and test', required=True)
parser.add_argument('-x', dest='hex_filename',
                    help='Name of GE hex file to read and compare against', required=True)
parser.add_argument('-e', dest='ee_filename',
                    help='Name of vendor binary file containing the readback for EE content.', required=True)
parser.add_argument('-o', dest='option_filename',
                    help='Name of vendor binary file containing the readback for option content.', required=True)
parser.add_argument('--version', action='version', help='Print version.',
                    version='%(prog)s Version {version}'.format(version=__version__))
parser.add_argument('-v', dest='verbose', default=False, action='store_true',
                    help='verbose output flag', required=False)

# Parse the command line arguments
args = parser.parse_args()

###############################################################################
# Test for existence of the binary file.
if os.path.isfile(args.binary_filename) is False:
    print('ERROR, ' + args.binary_filename + ' does not exist')
    print('\n\n')
    parser.print_help()
    exit(-1)

###############################################################################
# Test for existence of the hex file.
if os.path.isfile(args.hex_filename) is False:
    print('ERROR, ' + args.hex_filename + ' does not exist')
    print('\n\n')
    parser.print_help()
    exit(-1)

###############################################################################
# Test for existence of the ee file.
if os.path.isfile(args.ee_filename) is False:
    print('ERROR, ' + args.ee_filename + ' does not exist')
    print('\n\n')
    parser.print_help()
    exit(-1)

###############################################################################
# Test for existence of the option file.
if os.path.isfile(args.option_filename) is False:
    print('ERROR, ' + args.option_filename + ' does not exist')
    print('\n\n')
    parser.print_help()
    exit(-1)


# endregion

# region CP read region

###############################################################################
# Open and read entire binary into variable
with open(args.binary_filename, "rb") as f:
    binary_data = f.read()


###############################################################################
# Test boot...
offset = CP_BOOTLOADER_START_ADDRESS + CP_VERSION_POINTER_OFFSET
(boot_version_offset, actual_boot_bytesize) = unpack_from("<LL", binary_data[offset:])
actual_boot_bytesize += 4   # adjust for crc at end
boot_version = unpack_from("<L", binary_data[boot_version_offset:])[0]
offset = CP_BOOTLOADER_START_ADDRESS + actual_boot_bytesize-4
boot_crc = unpack_from("<L", binary_data[offset:])[0]

if args.verbose is True:
    print("Boot byte size: {}  Boot Version: {}.{}.{}.{}    Boot image CRC: 0x{:08x}".format(
        actual_boot_bytesize,
        (boot_version & 0xff000000) >> 24,
        (boot_version & 0x00ff0000) >> 16,
        (boot_version & 0x0000ff00) >> 8,
        (boot_version & 0x000000ff),
        boot_crc))

# Grab the entire image and calc a sha1...
vendor_boot_image = unpack_from(">{0}B".format(str(actual_boot_bytesize)), binary_data[CP_BOOTLOADER_START_ADDRESS:])
actual_boot_image_sha1 = sha1(bytearray(vendor_boot_image)).hexdigest()

###############################################################################
# Test DFU...
offset = CP_DFU1_START_ADDRESS + CP_VERSION_POINTER_OFFSET
(dfu_version_offset, actual_dfu_bytesize) = unpack_from("<LL", binary_data[offset:])
actual_dfu_bytesize += 4   # adjust for crc at end
offset = CP_DFU1_START_ADDRESS + dfu_version_offset
dfu_version = unpack_from("<L", binary_data[offset:])[0]
offset = CP_DFU1_START_ADDRESS + actual_dfu_bytesize-4
dfu_crc = unpack_from("<L", binary_data[offset:])[0]

if args.verbose is True:
    print("DFU byte size: {}  DFU Version: {}.{}.{}.{}    DFU image CRC: 0x{:08x}".format(
        actual_dfu_bytesize,
        (dfu_version & 0xff000000) >> 24,
        (dfu_version & 0x00ff0000) >> 16,
        (dfu_version & 0x0000ff00) >> 8,
        (dfu_version & 0x000000ff),
        dfu_crc))

# Grab the entire image and calc a sha1...
vendor_dfu_image = unpack_from(">{0}B".format(str(actual_dfu_bytesize)), binary_data[CP_DFU1_START_ADDRESS:])
actual_dfu_image_sha1 = sha1(bytearray(vendor_dfu_image)).hexdigest()

###############################################################################
# Test main...
offset = CP_MAIN_APP_START_ADDRESS + CP_VERSION_POINTER_OFFSET
(main_version_offset, actual_main_bytesize) = unpack_from("<LL", binary_data[offset:])
actual_main_bytesize += 4   # adjust for crc at end
offset = CP_MAIN_APP_START_ADDRESS + main_version_offset
main_version = unpack_from("<L", binary_data[offset:])[0]
offset = CP_MAIN_APP_START_ADDRESS + actual_main_bytesize-4
main_crc = unpack_from("<L", binary_data[offset:])[0]

if args.verbose is True:
    print("Main byte size: {}  Main Version: {}.{}.{}.{}    MAIN image CRC: 0x{:08x}".format(
        actual_main_bytesize,
        (main_version & 0xff000000) >> 24,
        (main_version & 0x00ff0000) >> 16,
        (main_version & 0x0000ff00) >> 8,
        (main_version & 0x000000ff),
        main_crc))

# Grab the entire image and calc a sha1...
vendor_main_image = unpack_from(">{0}B".format(str(actual_main_bytesize)), binary_data[CP_MAIN_APP_START_ADDRESS:])
actual_main_image_sha1 = sha1(bytearray(vendor_main_image)).hexdigest()

# endregion

# region EE read region
###############################################################################
# Open and read entire binary into variable
with open(args.ee_filename, "rb") as f:
    binary_data = f.read()

# Read the 2nd of 16 256-byte blocks.
# That's where our stuff is.
# Grab the entire image and calc a sha1...
vendor_ee_image = unpack_from(">256B", binary_data[256:])
actual_ee_image_sha1 = sha1(bytearray(vendor_ee_image)).hexdigest()

# endregion

# region Option read region
###############################################################################
# Open and read entire binary into variable
with open(args.option_filename, "rb") as f:
    binary_data = f.read()

# Read the first 16-bytes.
vendor_option_image = unpack_from(">16B", binary_data[0:])
actual_option_image_sha1 = sha1(bytearray(vendor_option_image)).hexdigest()

# endregion

###############################################################################
# Create a IntelHex object with command line given filename.
hex_file = IntelHex(args.hex_filename)

###############################################################################
# Sanity check the segments in our GE hex file.
# Segments call will return a list of tuples contains start and stop address.  They are in lo/hi address order.
# This should match what we've extracted from the binary.
segments = hex_file.segments()
if len(segments) != EXPECTED_SEGMENT_COUNT:
    print("Number of segments found in {}: {}".format(os.path.basename(args.hex_filename), len(segments)))
    print("FAIL, expected section count of {} did NOT MATCH actual segment count of {}.".
          format(EXPECTED_SEGMENT_COUNT, len(segments)))

###############################################################################
# Show start/end address of segments if requested.
if args.verbose is True:
    print("Segment details:")
    for addresses in segments:
        print("\tStart address: {0:8X}  End address: {1:8X}".format(addresses[0], addresses[1]))

###############################################################################
# Read and calculate SHA1 of each section from the GE hex file (expected).
expected_boot_image_sha1 = calc_sha1(segments[0][0], segments[0][1], hex_file)
expected_dfu_image_sha1 = calc_sha1(segments[1][0], segments[1][1], hex_file)
expected_main_image_sha1 = calc_sha1(segments[2][0], segments[2][1], hex_file)
expected_ee_image_sha1 = calc_sha1(segments[3][0], segments[3][1], hex_file)
expected_option_image_sha1 = calc_sha1(segments[4][0], segments[4][1], hex_file)

###############################################################################
if args.verbose is True:
    print("Actual boot sha1 : {}, expected boot sha1 {}".format(actual_boot_image_sha1, expected_boot_image_sha1))
    print("Actual DFU sha1 : {}, expected DFU sha1 {}".format(actual_dfu_image_sha1, expected_dfu_image_sha1))
    print("Actual main sha1 : {}, expected main sha1 {}".format(actual_main_image_sha1, expected_main_image_sha1))
    print("Actual ee sha1 : {}, expected ee sha1 {}".format(actual_ee_image_sha1, expected_ee_image_sha1))
    print("Actual option sha1 : {}, expected option sha1 {}".format(actual_option_image_sha1, expected_option_image_sha1))

###############################################################################
# Compare actual against expected...
if actual_boot_image_sha1 != expected_boot_image_sha1:
    print("FAIL, actual boot image DOES NOT MATCH expected boot image")
else:
    print("PASS, boot matches")

if actual_dfu_image_sha1 != expected_dfu_image_sha1:
    print("FAIL, actual DFU image DOES NOT MATCH expected boot image")
else:
    print("PASS, DFU matches")

if actual_main_image_sha1 != expected_main_image_sha1:
    print("FAIL, actual main image DOES NOT MATCH expected boot image")
else:
    print("PASS, main matches")

if actual_ee_image_sha1 != expected_ee_image_sha1:
    print("FAIL, actual EE image DOES NOT MATCH expected boot image")
else:
    print("PASS, EE matches")

if actual_option_image_sha1 != expected_option_image_sha1:
    print("FAIL, actual option image DOES NOT MATCH expected boot image")
else:
    print("PASS, option section matches")

exit(0)
