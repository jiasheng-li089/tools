package cn.ljs.apkv2channeltools.utils;

import android.content.Context;
import android.util.Log;
import android.util.Pair;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;

/**
 * <p> Description: Utility of APK parsing</p>
 * <p/>
 * <p> Copyright: Copyright (c) 2018 </p>
 * <p> Create Time: 18/3/2018 16:28 </p>
 *
 * @author Json.Lee
 * @version 1.0
 */
public class APKUtils {

    private static final String TAG = APKUtils.class.getSimpleName();

    /**
     * the size of v2 signature block
     */
    private static final int APK_SIGN_BLOCK_MIN_SIZE = 32;
    // The most significant 16 bytes of data in the v2 signature block magic
    private static final long APK_SIG_BLOCK_MAGIC_HI = 0x3234206b636f6c42L;
    // The less significant 8 bhtes of data in the v2 signature block magic
    private static final long APK_SIG_BLOCK_MAGIC_LO = 0x20676953204b5041L;
    // the key of the v2 sinature block
    private static final int APK_SIGNATURE_SCHEME_V2_BLOCK_ID = 0x7109871a;
    // the key of the written meta data block
    private static final int APK_CHANNEL_BLOCK_ID = 0x71098719;

    /**
     * get the meta data from the apk
     *
     * @param context
     * @return the data written with the python tool
     */
    public static byte[] getApkV2ChannelInfo(Context context) {
        try {
            return getApkExtraInfoInSignatureBlock(context, APK_CHANNEL_BLOCK_ID);
        } catch (ApkExtraInfoNotFoundException e) {
            throw new ChannelNotFoundException("v2 channel info not found.", e);
        }
    }

    public static byte[] getApkV2SignatureInfo(String filePath) {
        try {
            return getApkExtraInfoInSignatureBlock(filePath, APK_SIGNATURE_SCHEME_V2_BLOCK_ID);
        } catch (ApkExtraInfoNotFoundException e) {
            throw new SignatureNotFoundException("v2 signing not found", e);
        }
    }

    /**
     * get the signature info from the apk
     *
     * @param context
     * @return
     */
    public static byte[] getApkV2SignatureInfo(Context context) {
        try {
            return getApkExtraInfoInSignatureBlock(context, APK_SIGNATURE_SCHEME_V2_BLOCK_ID);
        } catch (ApkExtraInfoNotFoundException e) {
            throw new SignatureNotFoundException("v2 signing not found", e);
        }
    }

    /**
     * get the extra info from the signature block
     *
     * @param context 
     * @param key     the key for the extra info
     * @return
     */
    public static byte[] getApkExtraInfo(Context context, String key) {
        return getApkExtraInfoInSignatureBlock(context.getApplicationInfo().sourceDir,
                convertStringToId(key));
    }


    private static int convertStringToId(String key) {
        if (null == key) {
            throw new NullPointerException("key should not be null");
        }

        byte[] data = key.getBytes(Charset.forName("utf-8"));

        int result = 0x00;

        int shiftIndex = 0;
        while (shiftIndex < 4 && shiftIndex < data.length) {
            result |= (data[shiftIndex] << ((3 - shiftIndex) * 8));
            shiftIndex++;
        }
        return result;
    }

    /**
     * get the extra info from the signature block
     *
     * @param file   file path of the apk file
     * @param signId the key for the extra info
     * @return 
     */
    private static byte[] getApkExtraInfoInSignatureBlock(String file, int signId) {
        File apkFile = new File(file);

        try {
            RandomAccessFile apk = new RandomAccessFile(apkFile, "r");

            // locate the ecod section of the apk (zip) file
            Pair<ByteBuffer, Long> ecodPair = ZipUtils.findZipEndOfCentralDirectoryRecord(apk);

            ByteBuffer ecod = ecodPair.first;
            long ecodOffset = ecodPair.second;

            if (ZipUtils.isZip64EndOfCentralDirectoryLocatorPresent(apk, ecodOffset)) {
                throw new SignatureNotFoundException("ZIP64 APK not support");
            }

            // get the offset of the central directory in the zip file
            long centralDirOffset = getCentralDirOffset(ecod, ecodOffset);
            Pair<ByteBuffer, Long> signBlockAnfOffsetInFile = findApkSigningBlock(apk, centralDirOffset);

            ByteBuffer signBlock = signBlockAnfOffsetInFile.first;
//            long apkSignBlockOffset = signBlockAnfOffsetInFile.second;

            ByteBuffer apkSignatureSchemeV2Block = findApkExtraInfoInSignatureBlock(signBlock, signId);

            byte[] tmp = new byte[apkSignatureSchemeV2Block.limit() - apkSignatureSchemeV2Block.position()];
            apkSignatureSchemeV2Block.get(tmp, 0, tmp.length);
            return tmp;
        } catch (FileNotFoundException e) {
            Log.e(TAG, String.format("read %s error, file not found", file),
                    e);
        } catch (IOException e) {
            Log.e(TAG, String.format("read %s error", file), e);
        }
        return null;
    }

    private static byte[] getApkExtraInfoInSignatureBlock(Context context, int signId) {
        String filePath = context.getApplicationInfo().sourceDir;
        return getApkExtraInfoInSignatureBlock(filePath, signId);
    }

    /**
     * get the offset of the central directory in the zip file
     *
     * @param eocd       the data of the EOCD section
     * @param eocdOffset the offset of the EOCD section in the zip file
     * @return
     */
    private static long getCentralDirOffset(ByteBuffer eocd, long eocdOffset) {
        long centeralDirOffset = ZipUtils.getZipEocdCentralDirectoryOffset(eocd);
        if (centeralDirOffset >= eocdOffset) {
            throw new SignatureNotFoundException("ZIP Central Directory offset out of range: " + centeralDirOffset
                    + ". ZIP End of Central Directory offset: " + eocdOffset);
        }
        long centralDirSize = ZipUtils.getZipEocdCentralDirectorySizeBytes(eocd);
        if (centeralDirOffset + centralDirSize != eocdOffset) {
            throw new SignatureNotFoundException("ZIP Central Directory is not immediately followed by End of" +
                    "Central Directory");
        }
        return centeralDirOffset;
    }

    private static Pair<ByteBuffer, Long> findApkSigningBlock(RandomAccessFile apk, long centralDirOffset)
            throws IOException {
        if (centralDirOffset < APK_SIGN_BLOCK_MIN_SIZE) {
            throw new SignatureNotFoundException("APK too small for APK Signing Block, ZIP Central Directory " +
                    "offset: " + centralDirOffset);
        }

        // read ths magic and offset in file from ths footer section of the block:
        // * unit64: size of block
        // * 16 bytes: magic

        ByteBuffer footer = ByteBuffer.allocate(24);
        footer.order(ByteOrder.LITTLE_ENDIAN);
        apk.seek(centralDirOffset - footer.capacity());
        apk.readFully(footer.array(), footer.arrayOffset(), footer.capacity());

        if (footer.getLong(8) != APK_SIG_BLOCK_MAGIC_LO
                || footer.getLong(16) != APK_SIG_BLOCK_MAGIC_HI) {
            throw new SignatureNotFoundException("No APK Signing Block before ZIP Central Directory");
        }

        // read and compare size fields
        long apkSignBlockSizeInFooter = footer.getLong(0);
        if (apkSignBlockSizeInFooter < footer.capacity()
                || apkSignBlockSizeInFooter > Integer.MAX_VALUE - 8) {
            throw new SignatureNotFoundException("APK Signing Block size out of range: " + apkSignBlockSizeInFooter);
        }

        int totalSize = (int) (apkSignBlockSizeInFooter + 8);
        long apkSignBlockOffset = centralDirOffset - totalSize;

        if (apkSignBlockOffset < 0) {
            throw new SignatureNotFoundException("APK Signing Block offset out of range: " + apkSignBlockOffset);
        }

        ByteBuffer apkSignBlock = ByteBuffer.allocate(totalSize);
        apkSignBlock.order(ByteOrder.LITTLE_ENDIAN);
        apk.seek(apkSignBlockOffset);
        apk.readFully(apkSignBlock.array(), apkSignBlock.arrayOffset(), apkSignBlock.capacity());
        long apkSignBlockSizeInHeader = apkSignBlock.getLong(0);

        if (apkSignBlockSizeInHeader != apkSignBlockSizeInFooter) {
            throw new SignatureNotFoundException("APK Signing Block size in header and footer do not match: "
                    + apkSignBlockSizeInHeader + " vs " + apkSignBlockSizeInFooter);
        }
        return Pair.create(apkSignBlock, apkSignBlockOffset);
    }

    private static ByteBuffer findApkExtraInfoInSignatureBlock(ByteBuffer signBlock, int signId) {
        assertByteOrderLittleEndian(signBlock);

        ByteBuffer pairs = sliceFromTo(signBlock, 8, signBlock.capacity() - 24);

        int entryCount = 0;

        while (pairs.hasRemaining()) {
            entryCount++;

            if (pairs.remaining() < 8) {
                throw new ApkExtraInfoNotFoundException("Insufficient data to read size of APK Signing Block " +
                        "entry #" + entryCount);
            }
            long lenLong = pairs.getLong();
            if (lenLong < 4 || lenLong > Integer.MAX_VALUE) {
                throw new ApkExtraInfoNotFoundException("APK Signing Block entry #" + entryCount
                        + " size out of range: " + lenLong);
            }

            int len = (int) lenLong;
            int nextEntryPos = pairs.position() + len;
            if (len > pairs.remaining()) {
                throw new ApkExtraInfoNotFoundException("APK Signing Block entry #" + entryCount + " size out " +
                        "of range:" + len + ", available: " + pairs.remaining());
            }

            int id = pairs.getInt();
            if (id == signId) {
                return getByteBuffer(pairs, len - 4);
            }
            pairs.position(nextEntryPos);
        }
        throw new ApkExtraInfoNotFoundException("No APK Extra Info in APK Signing Block");
    }

    private static ByteBuffer findApkSignatureSchemeV2Block(ByteBuffer signBlock) {
        assertByteOrderLittleEndian(signBlock);

        ByteBuffer pairs = sliceFromTo(signBlock, 8, signBlock.capacity() - 24);

        int entryCount = 0;

        while (pairs.hasRemaining()) {
            entryCount++;

            if (pairs.remaining() < 8) {
                throw new SignatureNotFoundException("Insufficient data to read size of APK Signing Block " +
                        "entry #" + entryCount);
            }
            long lenLong = pairs.getLong();
            if (lenLong < 4 || lenLong > Integer.MAX_VALUE) {
                throw new SignatureNotFoundException("APK Signing Block entry #" + entryCount
                        + " size out of range: " + lenLong);
            }

            int len = (int) lenLong;
            int nextEntryPos = pairs.position() + len;
            if (len > pairs.remaining()) {
                throw new SignatureNotFoundException("APK Signing Block entry #" + entryCount + " size out " +
                        "of range:" + len + ", available: " + pairs.remaining());
            }

            int id = pairs.getInt();
            if (id == APK_SIGNATURE_SCHEME_V2_BLOCK_ID) {
                return getByteBuffer(pairs, len - 4);
            }
            pairs.position(nextEntryPos);
        }
        throw new SignatureNotFoundException("No APK Signature Scheme v2 block in APK Signing Block");
    }

    /**
     * read the sub buffer from the buffer
     *
     * @param buffer the source buffer
     * @param start  start position of the source buffer
     * @param end    end position of the source buffer
     * @return
     */
    private static ByteBuffer sliceFromTo(ByteBuffer buffer, int start, int end) {
        if (start < 0) {
            throw new IllegalArgumentException("start: " + start);
        }
        if (end < start) {
            throw new IllegalArgumentException("end < start: " + end + " > " + start);
        }
        if (end > buffer.capacity()) {
            throw new IllegalArgumentException("end > capacity: " + end + " > " + buffer.capacity());
        }

        int originalLimit = buffer.limit();
        int originalPosition = buffer.position();

        try {
            buffer.position(0);
            buffer.limit(end);
            buffer.position(start);
            ByteBuffer result = buffer.slice();
            result.order(buffer.order());
            return result;
        } finally {
            buffer.position(0);
            buffer.limit(originalLimit);
            buffer.position(originalPosition);
        }
    }

    private static ByteBuffer getByteBuffer(ByteBuffer source, int size) {
        if (size < 0) {
            throw new IllegalArgumentException("size: " + size);
        }

        int originalLimit = source.limit();
        int postion = source.position();
        int limit = postion + size;

        if (limit < postion || limit > originalLimit) {
            // overflow
            throw new BufferUnderflowException();
        }

        source.limit(limit);
        try {
            ByteBuffer result = source.slice();
            result.order(source.order());
            source.position(limit);

            return result;
        } finally {
            source.limit(originalLimit);
        }
    }

    private static void assertByteOrderLittleEndian(ByteBuffer buffer) {
        if (buffer.order() != ByteOrder.LITTLE_ENDIAN) {
            throw new IllegalArgumentException("ByteBuffer is not Little Endian.");
        }
    }

    public static class ChannelNotFoundException extends RuntimeException {

        public ChannelNotFoundException() {
            super();
        }

        public ChannelNotFoundException(String msg) {
            super(msg);
        }

        public ChannelNotFoundException(String msg, Throwable e) {
            super(msg, e);
        }
    }

    public static class ApkExtraInfoNotFoundException extends RuntimeException {

        public ApkExtraInfoNotFoundException() {
            super();
        }

        public ApkExtraInfoNotFoundException(String msg) {
            super(msg);
        }

        public ApkExtraInfoNotFoundException(String msg, Throwable e) {
            super(msg, e);
        }
    }

    public static class SignatureNotFoundException extends RuntimeException {

        public SignatureNotFoundException(String msg) {
            super(msg);
        }

        public SignatureNotFoundException() {
            super();
        }

        public SignatureNotFoundException(String detailMessage, Throwable throwable) {
            super(detailMessage, throwable);
        }
    }

    public static class BufferUnderflowException extends RuntimeException {

        public BufferUnderflowException() {
            super();
        }

        public BufferUnderflowException(String msg) {
            super(msg);
        }
    }
}
