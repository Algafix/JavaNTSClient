package nts.NTSKERecords;

public class Constants {
    public enum NTSNextProtocols {
        NTPv4(0),
        UNASSIGNED(32767),
        RESERVED(65535);

        private final int value;

        NTSNextProtocols(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }

        /**
         * Returns the byte representation of the NTSNextProtocols value in 2 bytes.
         * @return a byte array containing the two-byte representation of the value.
         */
        public byte[] getBytesValue() {
            return new byte[] {
                (byte) (value >> 8),
                (byte) (value & 0xFF)
            };
        }

        public static NTSNextProtocols fromValue(int value) {
            for (NTSNextProtocols protocol : NTSNextProtocols.values()) {
                if (protocol.value == value) {
                    return protocol;
                }
            }
            throw new IllegalArgumentException("Unknown NTSNextProtocol value: " + value);
        }

        public static NTSNextProtocols fromBytes(byte[] bytes) {
            if (bytes.length != 2) {
                throw new IllegalArgumentException("ErrorCode must be represented by 2 bytes.");
            }
            int value = ((bytes[0] & 0xFF) << 8) | (bytes[1] & 0xFF);
            return fromValue(value);
        }

    }

    public enum AEADAlgorithms {
        AEAD_AES_128_GCM(1),
        AEAD_AES_256_GCM(2),
        AEAD_AES_128_CCM(3),
        AEAD_AES_256_CCM(4),
        AEAD_AES_128_GCM_8(5),
        AEAD_AES_256_GCM_8(6),
        AEAD_AES_128_GCM_12(7),
        AEAD_AES_256_GCM_12(8),
        AEAD_AES_128_CCM_SHORT(9),
        AEAD_AES_256_CCM_SHORT(10),
        AEAD_AES_128_CCM_SHORT_8(11),
        AEAD_AES_256_CCM_SHORT_8(12),
        AEAD_AES_128_CCM_SHORT_12(13),
        AEAD_AES_256_CCM_SHORT_12(14),
        AEAD_AES_SIV_CMAC_256(15),  // Mandatory supported AEAD algorithm for NTSKE
        AEAD_AES_SIV_CMAC_384(16),
        AEAD_AES_SIV_CMAC_512(17),
        AEAD_AES_128_CCM_8(18),
        AEAD_AES_256_CCM_8(19),
        AEAD_AES_128_OCB_TAGLEN128(20),
        AEAD_AES_128_OCB_TAGLEN96(21),
        AEAD_AES_128_OCB_TAGLEN64(22),
        AEAD_AES_192_OCB_TAGLEN128(23),
        AEAD_AES_192_OCB_TAGLEN96(24),
        AEAD_AES_192_OCB_TAGLEN64(25),
        AEAD_AES_256_OCB_TAGLEN128(26),
        AEAD_AES_256_OCB_TAGLEN96(27),
        AEAD_AES_256_OCB_TAGLEN64(28),
        AEAD_CHACHA20_POLY1305(29),
        AEAD_AES_128_GCM_SIV(30),
        AEAD_AES_256_GCM_SIV(31),
        AEAD_AEGIS128L(32),
        AEAD_AEGIS256(33),

        UNASSIGNED(32767),
        RESERVED(65535);

        private final int value;

        AEADAlgorithms(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }

        /**
         * Returns the byte representation of the AEADAlgorithm value in 2 bytes.
         * @return a byte array containing the two-byte representation of the value.
         */
        public byte[] getBytesValue() {
            return new byte[] {
                (byte) (value >> 8),
                (byte) (value & 0xFF)
            };
        }

        public static AEADAlgorithms fromValue(int value) {
            for (AEADAlgorithms algorithm : AEADAlgorithms.values()) {
                if (algorithm.value == value) {
                    return algorithm;
                }
            }
            throw new IllegalArgumentException("Unknown AEADAlgorithm value: " + value);
        }

        public static AEADAlgorithms fromBytes(byte[] bytes) {
            if (bytes.length != 2) {
                throw new IllegalArgumentException("ErrorCode must be represented by 2 bytes.");
            }
            int value = ((bytes[0] & 0xFF) << 8) | (bytes[1] & 0xFF);
            return fromValue(value);
        }
    }

    public enum ErrorCodes {
        UNRECOGNIZED_CRITICAL_RECORD(0),
        BAD_REQUEST(1),
        INTERNAL_SERVER_ERROR(2);

        private final int value;

        ErrorCodes(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }

        /**
         * Returns the byte representation of the ErrorCode value in 2 bytes.
         * @return a byte array containing the two-byte representation of the value.
         */
        public byte[] getBytesValue() {
            return new byte[] {
                (byte) (value >> 8),
                (byte) (value & 0xFF)
            };
        }

        public static ErrorCodes fromValue(int value) {
            for (ErrorCodes code : ErrorCodes.values()) {
                if (code.value == value) {
                    return code;
                }
            }
            throw new IllegalArgumentException("Unknown ErrorCode value: " + value);
        }

        public static ErrorCodes fromBytes(byte[] bytes) {
            if (bytes.length != 2) {
                throw new IllegalArgumentException("ErrorCode must be represented by 2 bytes.");
            }
            int value = ((bytes[0] & 0xFF) << 8) | (bytes[1] & 0xFF);
            return fromValue(value);
        }

    }

    
}
