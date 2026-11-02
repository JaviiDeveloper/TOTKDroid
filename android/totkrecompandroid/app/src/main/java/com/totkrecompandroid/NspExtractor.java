// Extract exefs/ and romfs/ from an NSP (PFS0 container holding encrypted NCAs) using the player's own prod.keys.
// The NSP holds NCAs (encrypted game partitions) and tickets (title keys). The flow:
//   1. Parse PFS0 → find .nca files and .tik (tickets)
//   2. Read title keys from tickets (common ticket: RSA-2048, key at 0x180, rights_id at 0x2A0)
//   3. Parse prod.keys for header_key and titlekek_XX
//   4. Decrypt NCA headers (AES-128-XTS with header_key) to find the Program NCA
//   5. Decrypt the title key with the matching titlekek, or decrypt the key area with key_area_key_application_XX
//   6. Decrypt and extract exefs (PFS0) and romfs sections from the Program NCA
//
// All crypto uses javax.crypto (AES/ECB, AES/CTR); XTS mode is built on top of ECB.
package com.totkrecompandroid;

import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class NspExtractor {
    private static final String TAG = "NspExtractor";
    private static final int MEDIA_UNIT = 0x200;

    public interface Progress {
        void update(long done, long total);
    }

    // ---- PFS0 (NSP container) ----

    static class Pfs0Entry {
        String name;
        long offset; // absolute offset in the file
        long size;
    }

    static List<Pfs0Entry> parsePfs0(FileChannel f, long base) throws IOException {
        f.position(base);
        byte[] head = new byte[16];
        if (readFully(f, head) != 16) throw new IOException("PFS0: too short");
        if (head[0] != 'P' || head[1] != 'F' || head[2] != 'S' || head[3] != '0')
            throw new IOException("Not a PFS0 container");
        ByteBuffer hb = ByteBuffer.wrap(head).order(ByteOrder.LITTLE_ENDIAN);
        int nFiles = hb.getInt(4);
        int strSize = hb.getInt(8);
        byte[] table = new byte[nFiles * 24];
        if (readFully(f, table) != table.length) throw new IOException("PFS0: entry table truncated");
        byte[] strings = new byte[strSize];
        if (readFully(f, strings) != strings.length) throw new IOException("PFS0: string table truncated");
        long dataBase = base + 16 + (long) nFiles * 24 + strSize;
        List<Pfs0Entry> entries = new ArrayList<>();
        ByteBuffer tb = ByteBuffer.wrap(table).order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i < nFiles; i++) {
            Pfs0Entry e = new Pfs0Entry();
            long off = tb.getLong(i * 24);
            e.size = tb.getLong(i * 24 + 8);
            int nameOff = tb.getInt(i * 24 + 16);
            int end = nameOff;
            while (end < strings.length && strings[end] != 0) end++;
            e.name = new String(strings, nameOff, end - nameOff, StandardCharsets.UTF_8);
            e.offset = dataBase + off;
            entries.add(e);
        }
        return entries;
    }

    // ---- Tickets (title keys) ----

    static Map<String, byte[]> readTickets(FileChannel f, List<Pfs0Entry> nspEntries) throws IOException {
        Map<String, byte[]> keys = new HashMap<>(); // rights_id_hex -> title_key (encrypted)
        for (Pfs0Entry e : nspEntries) {
            if (!e.name.endsWith(".tik")) continue;
            if (e.size < 0x2B0) continue;
            f.position(e.offset);
            byte[] tik = new byte[(int) Math.min(e.size, 0x400)];
            readFully(f, tik);
            ByteBuffer tb = ByteBuffer.wrap(tik).order(ByteOrder.LITTLE_ENDIAN);
            int sigType = tb.getInt(0);
            if (sigType != 0x10004) continue; // RSA-2048 SHA-256 (common ticket)
            byte[] titleKey = new byte[16];
            System.arraycopy(tik, 0x180, titleKey, 0, 16);
            byte[] rightsId = new byte[16];
            System.arraycopy(tik, 0x2A0, rightsId, 0, 16);
            keys.put(hex(rightsId), titleKey);
        }
        return keys;
    }

    // ---- prod.keys parsing ----

    static Map<String, byte[]> parseKeys(InputStream in) throws IOException {
        Map<String, byte[]> keys = new HashMap<>();
        BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
        String line;
        while ((line = br.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#") || line.startsWith(";")) continue;
            int eq = line.indexOf('=');
            if (eq < 0) continue;
            String name = line.substring(0, eq).trim().toLowerCase();
            String val = line.substring(eq + 1).trim();
            if (val.length() % 2 != 0) continue;
            try {
                keys.put(name, unhex(val));
            } catch (Exception ignored) {
            }
        }
        return keys;
    }

    // ---- AES-128-XTS (for NCA header decryption) ----
    // XTS uses two 16-byte keys: key1 for data, key2 for the tweak. Each sector (0x200 bytes) has a sector number
    // as its tweak, encrypted with key2. Each 16-byte block is XOR'd with the tweak, decrypted with key1, XOR'd again.
    // After each block the tweak is multiplied by x in GF(2^128).

    static byte[] aesXtsDecrypt(byte[] data, byte[] key, long sectorStart, int sectorSize) throws Exception {
        if (key.length != 32) throw new IllegalArgumentException("XTS key must be 32 bytes");
        byte[] key1 = new byte[16], key2 = new byte[16];
        System.arraycopy(key, 0, key1, 0, 16);
        System.arraycopy(key, 16, key2, 0, 16);

        Cipher tweakCipher = Cipher.getInstance("AES/ECB/NoPadding");
        tweakCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key2, "AES"));
        Cipher dataCipher = Cipher.getInstance("AES/ECB/NoPadding");
        dataCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key1, "AES"));

        byte[] out = new byte[data.length];
        int nSectors = data.length / sectorSize;
        for (int s = 0; s < nSectors; s++) {
            // tweak = AES-ECB-encrypt(sector_number as 16-byte LE, key2)
            byte[] tweakPlain = new byte[16];
            long sn = sectorStart + s;
            for (int i = 0; i < 8; i++) tweakPlain[i] = (byte) (sn >>> (i * 8));
            byte[] tweak = tweakCipher.doFinal(tweakPlain);

            int sOff = s * sectorSize;
            int nBlocks = sectorSize / 16;
            for (int b = 0; b < nBlocks; b++) {
                int bOff = sOff + b * 16;
                byte[] block = new byte[16];
                for (int i = 0; i < 16; i++) block[i] = (byte) (data[bOff + i] ^ tweak[i]);
                byte[] dec = dataCipher.doFinal(block);
                for (int i = 0; i < 16; i++) out[bOff + i] = (byte) (dec[i] ^ tweak[i]);
                gf128Mul(tweak);
            }
        }
        return out;
    }

    // Multiply by x in GF(2^128): shift left one bit, XOR 0x87 if the top bit was set
    private static void gf128Mul(byte[] v) {
        boolean carry = (v[15] & 0x80) != 0;
        for (int i = 15; i > 0; i--)
            v[i] = (byte) (((v[i] & 0xFF) << 1) | ((v[i - 1] & 0x80) >>> 7));
        v[0] = (byte) ((v[0] & 0xFF) << 1);
        if (carry) v[0] ^= 0x87;
    }

    // ---- NCA header parsing ----

    static class NcaHeader {
        byte[] magic = new byte[4]; // "NCA3"
        int distributionType;
        int contentType; // 0=Program, 1=Meta, 2=Control, 3=Manual, 4=Data, 5=PublicData
        int keyGenOld;
        int kaekIndex; // 0=Application, 1=Ocean, 2=System
        long contentSize;
        long programId;
        int sdkVersion;
        int keyGen;
        byte[] rightsId = new byte[16];
        int[][] sections = new int[4][4]; // start_offset, end_offset, ?, crypto_type per section (in media units)
        byte[][] sectionHashes = new byte[4][32];
        byte[][] keyArea = new byte[4][16]; // 4 encrypted keys
        // FS headers (parsed separately)
        byte[] fsHeaders; // 0x800 bytes (4 x 0x200)
    }

    static NcaHeader parseNcaHeader(byte[] decrypted) {
        if (decrypted.length < 0xC00) return null;
        NcaHeader h = new NcaHeader();
        ByteBuffer b = ByteBuffer.wrap(decrypted).order(ByteOrder.LITTLE_ENDIAN);
        System.arraycopy(decrypted, 0x200, h.magic, 0, 4);
        h.distributionType = decrypted[0x204] & 0xFF;
        h.contentType = decrypted[0x205] & 0xFF;
        h.keyGenOld = decrypted[0x206] & 0xFF;
        h.kaekIndex = decrypted[0x207] & 0xFF;
        h.contentSize = b.getLong(0x208);
        h.programId = b.getLong(0x210);
        h.sdkVersion = b.getInt(0x214);
        h.keyGen = decrypted[0x220] & 0xFF;
        System.arraycopy(decrypted, 0x230, h.rightsId, 0, 16);
        for (int i = 0; i < 4; i++) {
            int off = 0x240 + i * 0x10;
            h.sections[i][0] = b.getInt(off);     // start (media units)
            h.sections[i][1] = b.getInt(off + 4); // end (media units)
            h.sections[i][2] = b.getInt(off + 8);
            h.sections[i][3] = b.getInt(off + 12);
        }
        for (int i = 0; i < 4; i++)
            System.arraycopy(decrypted, 0x280 + i * 0x20, h.sectionHashes[i], 0, 0x20);
        for (int i = 0; i < 4; i++)
            System.arraycopy(decrypted, 0x300 + i * 0x10, h.keyArea[i], 0, 0x10);
        h.fsHeaders = new byte[0x800];
        System.arraycopy(decrypted, 0x400, h.fsHeaders, 0, 0x800);
        return h;
    }

    // ---- FS header parsing (one per section, 0x200 bytes each) ----

    static class FsHeader {
        int version;
        int fsType;        // 0=RomFS, 1=PFS0
        int hashType;
        int encryptionType; // 1=AesXts, 2=AesCtr, 3=AesCtrEx, 4=AesCtrSkipLayerHash, ...
        long ctrUpper;     // upper 64 bits of the CTR IV (generation | secure_value)
        // PFS0 superblock
        long pfs0Offset, pfs0Size;
        // RomFS (IVFC) level 6 (the data level)
        long romfsOffset, romfsSize;
        // BKTR PatchInfo (encryptionType == 3, AesCtrEx): bucket tree offsets within the section data
        long indirectOffset, indirectSize;   // relocation table
        int indirectEntryCount;
        long aesCtrExOffset, aesCtrExSize;   // subsection table (CTR generation per region)
        int aesCtrExEntryCount;
    }

    static FsHeader parseFsHeader(byte[] raw, int index) {
        if (raw.length < (index + 1) * 0x200) return null;
        int base = index * 0x200;
        ByteBuffer b = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);
        FsHeader h = new FsHeader();
        h.version = b.getShort(base) & 0xFFFF;
        h.fsType = raw[base + 2] & 0xFF;
        h.hashType = raw[base + 3] & 0xFF;
        h.encryptionType = raw[base + 4] & 0xFF;
        // CTR upper value at +0x140 (8 bytes, big-endian in the NCA spec — stored as the section's generation | secure_value)
        h.ctrUpper = b.getLong(base + 0x140);
        if (h.fsType == 1) { // PFS0: superblock at +0x08
            h.pfs0Offset = b.getLong(base + 0x38);
            h.pfs0Size = b.getLong(base + 0x40);
        } else if (h.hashType == 3 || h.hashType == 2) { // IVFC (RomFS): level 6 at the last IVFC level entry
            // IVFC header at +0x08: magic, level count, then level entries at +0x18 (each 0x18 bytes: offset, size, block_size, reserved)
            int ivfcBase = base + 0x08;
            int levelCount = b.getInt(ivfcBase + 0x08);
            if (levelCount < 1) levelCount = 6; // typical
            int lastLevel = Math.min(levelCount, 6) - 1;
            int lvOff = ivfcBase + 0x10 + lastLevel * 0x18;
            h.romfsOffset = b.getLong(lvOff);
            h.romfsSize = b.getLong(lvOff + 8);
        }
        if (h.encryptionType == 3) { // AesCtrEx (BKTR): PatchInfo at +0x100
            h.indirectOffset = b.getLong(base + 0x100);
            h.indirectSize = b.getLong(base + 0x108);
            h.indirectEntryCount = b.getInt(base + 0x118);
            h.aesCtrExOffset = b.getLong(base + 0x120);
            h.aesCtrExSize = b.getLong(base + 0x128);
            h.aesCtrExEntryCount = b.getInt(base + 0x138);
        }
        return h;
    }

    // ---- AES-128-CTR decryption of an NCA section ----

    static void decryptSectionCtr(FileChannel f, long ncaBase, NcaHeader nca, int sectionIdx,
                                  byte[] decKey, long innerOffset, long size, OutputStream out,
                                  Progress progress, long[] progressState) throws Exception {
        int startMedia = nca.sections[sectionIdx][0];
        long sectionAbsStart = ncaBase + (long) startMedia * MEDIA_UNIT;

        FsHeader fs = parseFsHeader(nca.fsHeaders, sectionIdx);
        if (fs == null) throw new IOException("No FS header for section " + sectionIdx);

        // Build the CTR IV: upper 64 bits from the FS header (big-endian), lower 64 bits = offset / 16
        // The NCA spec: the IV's upper 32 bits are the generation (secure value), next 32 bits are the section index-based counter
        // For AES-CTR in NCAs: IV = [section_ctr_upper (8 bytes BE)] [offset_within_section / 0x10 (8 bytes BE)]
        long readOffset = innerOffset;
        long absOffset = sectionAbsStart + readOffset;
        f.position(absOffset);

        byte[] iv = new byte[16];
        // Upper 8 bytes: the generation/secure value, stored big-endian
        // In the NCA, the upper part of the CTR is stored at FS header +0x140 as a big-endian u64 composed of
        // (generation << 32) | secure_value. But many implementations just use the section start offset.
        // Standard: upper 4 bytes = section_ctr[0..3] (BE), next 4 bytes = section_ctr[4..7] (BE)
        // The actual CTR upper from the raw header bytes (big-endian as stored):
        ByteBuffer fsRaw = ByteBuffer.wrap(nca.fsHeaders).order(ByteOrder.BIG_ENDIAN);
        long ctrVal = fsRaw.getLong(sectionIdx * 0x200 + 0x140);
        for (int i = 0; i < 8; i++) iv[i] = (byte) (ctrVal >>> (56 - i * 8));
        // Lower 8 bytes: offset / 16 (big-endian)
        long ctrLow = readOffset / 16;
        for (int i = 0; i < 8; i++) iv[8 + i] = (byte) (ctrLow >>> (56 - i * 8));

        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decKey, "AES"), new IvParameterSpec(iv));

        byte[] buf = new byte[1 << 20]; // 1 MB chunks
        long remaining = size;
        while (remaining > 0) {
            int toRead = (int) Math.min(buf.length, remaining);
            int read = readFully(f, buf, 0, toRead);
            if (read <= 0) throw new IOException("Unexpected EOF in NCA section");
            byte[] dec = cipher.update(buf, 0, read);
            if (dec != null) out.write(dec);
            remaining -= read;
            if (progress != null && progressState != null) {
                progressState[0] += read;
                progress.update(progressState[0], progressState[1]);
            }
        }
        byte[] fin = cipher.doFinal();
        if (fin != null && fin.length > 0) out.write(fin);
    }

    // ---- Extract exefs (PFS0 inside the section) ----

    static void extractExefs(FileChannel f, long ncaBase, NcaHeader nca, int sectionIdx,
                             byte[] decKey, File outDir, Progress progress, long[] progressState) throws Exception {
        FsHeader fs = parseFsHeader(nca.fsHeaders, sectionIdx);
        if (fs == null) throw new IOException("No FS header for exefs section");

        int startMedia = nca.sections[sectionIdx][0];
        long sectionStart = ncaBase + (long) startMedia * MEDIA_UNIT;
        long sectionSize = ((long) nca.sections[sectionIdx][1] - startMedia) * MEDIA_UNIT;

        // Decrypt the whole section header area to parse PFS0
        // The PFS0 superblock tells where the PFS0 is within the section; for exefs it's typically at offset 0
        long pfs0Off = fs.pfs0Offset;
        // Read and decrypt enough to parse the PFS0 header (first 64KB should be plenty)
        long headerReadSize = Math.min(64 * 1024, sectionSize - pfs0Off);
        java.io.ByteArrayOutputStream headerBuf = new java.io.ByteArrayOutputStream();
        decryptSectionCtr(f, ncaBase, nca, sectionIdx, decKey, pfs0Off, headerReadSize, headerBuf, null, null);
        byte[] headerData = headerBuf.toByteArray();

        // Parse PFS0 from the decrypted header
        if (headerData.length < 16) throw new IOException("exefs PFS0 header too short");
        ByteBuffer hb = ByteBuffer.wrap(headerData).order(ByteOrder.LITTLE_ENDIAN);
        if (headerData[0] != 'P' || headerData[1] != 'F' || headerData[2] != 'S' || headerData[3] != '0')
            throw new IOException("exefs section is not PFS0 (magic: " + hex(headerData, 0, 4) + ")");
        int nFiles = hb.getInt(4);
        int strSize = hb.getInt(8);
        long dataStart = 16L + (long) nFiles * 24 + strSize;

        outDir.mkdirs();
        for (int i = 0; i < nFiles; i++) {
            int tOff = 16 + i * 24;
            long fileOff = hb.getLong(tOff);
            long fileSize = hb.getLong(tOff + 8);
            int nameOff = hb.getInt(tOff + 16);
            int nameBase = 16 + nFiles * 24;
            int end = nameBase + nameOff;
            while (end < nameBase + strSize && headerData[end] != 0) end++;
            String name = new String(headerData, nameBase + nameOff, end - (nameBase + nameOff), StandardCharsets.UTF_8);

            Log.i(TAG, "exefs: " + name + " (" + fileSize + " bytes)");
            File outFile = new File(outDir, name);
            try (FileOutputStream fos = new FileOutputStream(outFile)) {
                decryptSectionCtr(f, ncaBase, nca, sectionIdx, decKey,
                        pfs0Off + dataStart + fileOff, fileSize, fos, progress, progressState);
            }
        }
    }

    // ---- Extract romfs section (write as romfs.bin, the raw decrypted RomFS image) ----

    static void extractRomfs(FileChannel f, long ncaBase, NcaHeader nca, int sectionIdx,
                             byte[] decKey, File outFile, Progress progress, long[] progressState) throws Exception {
        FsHeader fs = parseFsHeader(nca.fsHeaders, sectionIdx);
        if (fs == null) throw new IOException("No FS header for romfs section");

        int startMedia = nca.sections[sectionIdx][0];
        long sectionSize = ((long) nca.sections[sectionIdx][1] - startMedia) * MEDIA_UNIT;

        // The romfs data starts at the IVFC level 6 offset within the section
        long romfsOff = fs.romfsOffset;
        long romfsSize = fs.romfsSize;
        if (romfsSize <= 0) romfsSize = sectionSize - romfsOff;

        Log.i(TAG, "romfs: offset=" + romfsOff + " size=" + romfsSize);
        try (FileOutputStream fos = new FileOutputStream(outFile)) {
            decryptSectionCtr(f, ncaBase, nca, sectionIdx, decKey, romfsOff, romfsSize, fos, progress, progressState);
        }
    }

    // ---- BKTR (Binary Key Table Relocation): update NCA romfs is a delta against the base NCA ----

    static class BktrRelocationEntry {
        long virtualOffset;
        long physicalOffset;
        int isPatch; // 0 = read from base NCA, 1 = read from update NCA
    }

    static class BktrSubsectionEntry {
        long offset;       // physical offset within the update section
        int encryption;
        int generation;    // CTR generation value for this region
    }

    private static final int BKTR_NODE_SIZE = 0x4000;

    static List<BktrRelocationEntry> parseBktrRelocations(byte[] data, int entryCount) {
        ByteBuffer bb = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        int entrySize = 20; // u64 + u64 + u32
        int entriesPerBucket = (BKTR_NODE_SIZE - 16) / entrySize;
        int numBuckets = Math.max(1, (entryCount + entriesPerBucket - 1) / entriesPerBucket);
        int bucketsStart = BKTR_NODE_SIZE; // skip L1 (header) node
        List<BktrRelocationEntry> entries = new ArrayList<>();
        int remaining = entryCount;
        for (int b = 0; b < numBuckets && remaining > 0; b++) {
            int bucketOff = bucketsStart + b * BKTR_NODE_SIZE;
            if (bucketOff + 16 > data.length) break;
            int count = bb.getInt(bucketOff + 4);
            int eOff = bucketOff + 16;
            for (int i = 0; i < count && remaining > 0; i++) {
                if (eOff + entrySize > data.length) break;
                BktrRelocationEntry e = new BktrRelocationEntry();
                e.virtualOffset = bb.getLong(eOff);
                e.physicalOffset = bb.getLong(eOff + 8);
                e.isPatch = bb.getInt(eOff + 16);
                entries.add(e);
                eOff += entrySize;
                remaining--;
            }
        }
        return entries;
    }

    static List<BktrSubsectionEntry> parseBktrSubsections(byte[] data, int entryCount) {
        ByteBuffer bb = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        int entrySize = 16; // u64 + u32 + u32
        int entriesPerBucket = (BKTR_NODE_SIZE - 16) / entrySize;
        int numBuckets = Math.max(1, (entryCount + entriesPerBucket - 1) / entriesPerBucket);
        int bucketsStart = BKTR_NODE_SIZE;
        List<BktrSubsectionEntry> entries = new ArrayList<>();
        int remaining = entryCount;
        for (int b = 0; b < numBuckets && remaining > 0; b++) {
            int bucketOff = bucketsStart + b * BKTR_NODE_SIZE;
            if (bucketOff + 16 > data.length) break;
            int count = bb.getInt(bucketOff + 4);
            int eOff = bucketOff + 16;
            for (int i = 0; i < count && remaining > 0; i++) {
                if (eOff + entrySize > data.length) break;
                BktrSubsectionEntry e = new BktrSubsectionEntry();
                e.offset = bb.getLong(eOff);
                e.encryption = bb.getInt(eOff + 8);
                e.generation = bb.getInt(eOff + 12);
                entries.add(e);
                eOff += entrySize;
                remaining--;
            }
        }
        return entries;
    }

    // Find the relocation entry covering a given virtual offset (binary search)
    private static int findRelocation(List<BktrRelocationEntry> entries, long virtualOffset) {
        int lo = 0, hi = entries.size() - 1, result = 0;
        while (lo <= hi) {
            int mid = (lo + hi) >>> 1;
            if (entries.get(mid).virtualOffset <= virtualOffset) {
                result = mid;
                lo = mid + 1;
            } else {
                hi = mid - 1;
            }
        }
        return result;
    }

    // Find the subsection entry covering a given physical offset in the update section
    private static int findSubsection(List<BktrSubsectionEntry> entries, long physOffset) {
        int lo = 0, hi = entries.size() - 1, result = 0;
        while (lo <= hi) {
            int mid = (lo + hi) >>> 1;
            if (entries.get(mid).offset <= physOffset) {
                result = mid;
                lo = mid + 1;
            } else {
                hi = mid - 1;
            }
        }
        return result;
    }

    // AES-CTR decryption with an explicit CTR generation override (for AesCtrEx sections)
    static void decryptSectionCtrGen(FileChannel f, long ncaBase, NcaHeader nca, int sectionIdx,
                                     byte[] decKey, long innerOffset, long size, int ctrGeneration,
                                     OutputStream out, Progress progress, long[] progressState) throws Exception {
        int startMedia = nca.sections[sectionIdx][0];
        long sectionAbsStart = ncaBase + (long) startMedia * MEDIA_UNIT;
        f.position(sectionAbsStart + innerOffset);

        byte[] iv = new byte[16];
        ByteBuffer fsRaw = ByteBuffer.wrap(nca.fsHeaders).order(ByteOrder.BIG_ENDIAN);
        long ctrVal = fsRaw.getLong(sectionIdx * 0x200 + 0x140);
        for (int i = 0; i < 8; i++) iv[i] = (byte) (ctrVal >>> (56 - i * 8));
        if (ctrGeneration >= 0) {
            // Override upper 4 bytes with the subsection's generation
            iv[0] = (byte) (ctrGeneration >>> 24);
            iv[1] = (byte) (ctrGeneration >>> 16);
            iv[2] = (byte) (ctrGeneration >>> 8);
            iv[3] = (byte) ctrGeneration;
        }
        long ctrLow = innerOffset / 16;
        for (int i = 0; i < 8; i++) iv[8 + i] = (byte) (ctrLow >>> (56 - i * 8));

        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decKey, "AES"), new IvParameterSpec(iv));

        byte[] buf = new byte[1 << 20];
        long remaining = size;
        while (remaining > 0) {
            int toRead = (int) Math.min(buf.length, remaining);
            int read = readFully(f, buf, 0, toRead);
            if (read <= 0) throw new IOException("Unexpected EOF in NCA section");
            byte[] dec = cipher.update(buf, 0, read);
            if (dec != null) out.write(dec);
            remaining -= read;
            if (progress != null && progressState != null) {
                progressState[0] += read;
                progress.update(progressState[0], progressState[1]);
            }
        }
        byte[] fin = cipher.doFinal();
        if (fin != null && fin.length > 0) out.write(fin);
    }

    // Extract romfs via BKTR: the update NCA's romfs section is a delta against the base NCA's romfs
    static void extractRomfsBktr(
            FileChannel baseFile, long baseNcaOff, NcaHeader baseNca, int baseSection, byte[] baseKey,
            FileChannel updateFile, long updateNcaOff, NcaHeader updateNca, int updateSection, byte[] updateKey,
            File outFile, Progress progress, long[] progressState) throws Exception {

        FsHeader updateFs = parseFsHeader(updateNca.fsHeaders, updateSection);
        if (updateFs == null) throw new IOException("No FS header for update romfs section");
        FsHeader baseFs = parseFsHeader(baseNca.fsHeaders, baseSection);
        if (baseFs == null) throw new IOException("No FS header for base romfs section");

        // Decrypt the relocation table from the update section (use FS header's CTR — the BKTR tables use it)
        Log.i(TAG, "BKTR: reading relocation table (" + updateFs.indirectEntryCount + " entries)...");
        java.io.ByteArrayOutputStream relBuf = new java.io.ByteArrayOutputStream();
        decryptSectionCtr(updateFile, updateNcaOff, updateNca, updateSection, updateKey,
                updateFs.indirectOffset, updateFs.indirectSize, relBuf, null, null);
        List<BktrRelocationEntry> relocations = parseBktrRelocations(relBuf.toByteArray(), updateFs.indirectEntryCount);
        Log.i(TAG, "BKTR: parsed " + relocations.size() + " relocation entries");

        // Decrypt the subsection table (for AesCtrEx CTR generations)
        Log.i(TAG, "BKTR: reading subsection table (" + updateFs.aesCtrExEntryCount + " entries)...");
        java.io.ByteArrayOutputStream subBuf = new java.io.ByteArrayOutputStream();
        decryptSectionCtr(updateFile, updateNcaOff, updateNca, updateSection, updateKey,
                updateFs.aesCtrExOffset, updateFs.aesCtrExSize, subBuf, null, null);
        List<BktrSubsectionEntry> subsections = parseBktrSubsections(subBuf.toByteArray(), updateFs.aesCtrExEntryCount);
        Log.i(TAG, "BKTR: parsed " + subsections.size() + " subsection entries");

        // The virtual romfs layout comes from the update FS header's IVFC
        long romfsOff = updateFs.romfsOffset;
        long romfsSize = updateFs.romfsSize;
        if (romfsSize <= 0) {
            int startM = updateNca.sections[updateSection][0];
            long sectionSize = ((long) updateNca.sections[updateSection][1] - startM) * MEDIA_UNIT;
            romfsSize = sectionSize - romfsOff;
        }
        Log.i(TAG, "BKTR romfs: virtual offset=" + romfsOff + " size=" + romfsSize);

        // Write romfs by iterating over the virtual address space
        try (FileOutputStream fos = new FileOutputStream(outFile)) {
            long pos = romfsOff;
            long end = romfsOff + romfsSize;
            while (pos < end) {
                int ri = findRelocation(relocations, pos);
                BktrRelocationEntry rel = relocations.get(ri);
                long nextVirt = (ri + 1 < relocations.size()) ? relocations.get(ri + 1).virtualOffset : Long.MAX_VALUE;
                long chunkEnd = Math.min(end, nextVirt);
                long chunkSize = chunkEnd - pos;
                long physOff = rel.physicalOffset + (pos - rel.virtualOffset);

                if (rel.isPatch == 0) {
                    // Read from base NCA's romfs section (standard AES-CTR)
                    decryptSectionCtr(baseFile, baseNcaOff, baseNca, baseSection, baseKey,
                            physOff, chunkSize, fos, progress, progressState);
                } else {
                    // Read from update NCA's section with AesCtrEx: find the right CTR generation
                    // May span multiple subsection entries, so split at subsection boundaries
                    long subPos = physOff;
                    long subRemaining = chunkSize;
                    while (subRemaining > 0) {
                        int si = findSubsection(subsections, subPos);
                        BktrSubsectionEntry sub = subsections.get(si);
                        long nextSubOff = (si + 1 < subsections.size()) ? subsections.get(si + 1).offset : Long.MAX_VALUE;
                        long subChunk = Math.min(subRemaining, nextSubOff - subPos);
                        decryptSectionCtrGen(updateFile, updateNcaOff, updateNca, updateSection, updateKey,
                                subPos, subChunk, sub.generation, fos, progress, progressState);
                        subPos += subChunk;
                        subRemaining -= subChunk;
                    }
                }
                pos = chunkEnd;
            }
        }
    }

    // ---- The main extraction: NSP + keys → exefs/ + romfs.bin ----

    public static class Result {
        public boolean ok;
        public String error;
        public int gameVersion; // from nativeGameVersion on the extracted main
    }

    // Scan an NSP for its Program NCA(s): returns (entry, header, decKey) for each
    private static class ProgramNca {
        Pfs0Entry entry;
        NcaHeader header;
        byte[] decKey;
        boolean hasBktrRomfs; // true if the romfs section uses BKTR (= update NCA)
    }

    private static List<ProgramNca> findProgramNcas(FileChannel raf, long base,
            byte[] headerKey, Map<String, byte[]> prodKeys, Map<String, byte[]> titleKeys) throws Exception {
        List<Pfs0Entry> entries = parsePfs0(raf, base);
        Log.i(TAG, "NSP: " + entries.size() + " entries");
        Map<String, byte[]> tkeys = readTickets(raf, entries);
        titleKeys.putAll(tkeys);
        Log.i(TAG, "Tickets: " + tkeys.size() + " title key(s)");

        List<ProgramNca> ncas = new ArrayList<>();
        for (Pfs0Entry e : entries) {
            if (!e.name.endsWith(".nca") || e.name.endsWith(".cnmt.nca")) continue;
            raf.position(e.offset);
            byte[] encHeader = new byte[0xC00];
            if (readFully(raf, encHeader) != encHeader.length) continue;
            byte[] decHeader;
            try { decHeader = aesXtsDecrypt(encHeader, headerKey, 0, MEDIA_UNIT); }
            catch (Exception ex) { Log.w(TAG, "Can't decrypt header of " + e.name + ": " + ex); continue; }
            NcaHeader nca = parseNcaHeader(decHeader);
            if (nca == null) continue;
            String magic = new String(nca.magic, StandardCharsets.US_ASCII);
            if (!"NCA3".equals(magic) && !"NCA2".equals(magic)) continue;
            Log.i(TAG, e.name + ": type=" + nca.contentType + " size=" + e.size + " rights_id=" + hex(nca.rightsId));
            if (nca.contentType != 0) continue;
            byte[] decKey = deriveDecKey(nca, prodKeys, titleKeys);
            if (decKey == null) { Log.w(TAG, "Can't derive key for " + e.name); continue; }

            ProgramNca p = new ProgramNca();
            p.entry = e; p.header = nca; p.decKey = decKey;
            // Check if romfs section uses BKTR
            for (int i = 0; i < 4; i++) {
                if (nca.sections[i][0] == 0 && nca.sections[i][1] == 0) continue;
                FsHeader fs = parseFsHeader(nca.fsHeaders, i);
                if (fs != null && fs.fsType == 0 && fs.encryptionType == 3) p.hasBktrRomfs = true;
            }
            ncas.add(p);
        }
        return ncas;
    }

    public static Result extract(ParcelFileDescriptor baseNspFd, ParcelFileDescriptor updateNspFd,
                                 InputStream keysStream, File destDir, Progress progress) {
        Result result = new Result();
        File exefsDir = new File(destDir, "exefs");
        File romfsFile = new File(destDir, "romfs.bin");
        FileChannel baseRaf = null, updateRaf = null;
        try {
            Map<String, byte[]> keys = parseKeys(keysStream);
            byte[] headerKey = keys.get("header_key");
            if (headerKey == null || headerKey.length != 32)
                throw new IOException("header_key not found in prod.keys (need a 32-byte hex value)");

            Map<String, byte[]> titleKeys = new HashMap<>();

            // Open NSPs via FileChannel (SAF content:// fds don't support /proc/self/fd/ access)
            baseRaf = new FileInputStream(baseNspFd.getFileDescriptor()).getChannel();
            Log.i(TAG, "Scanning base NSP...");
            List<ProgramNca> baseNcas = findProgramNcas(baseRaf, 0, headerKey, keys, titleKeys);

            updateRaf = new FileInputStream(updateNspFd.getFileDescriptor()).getChannel();
            Log.i(TAG, "Scanning update NSP...");
            List<ProgramNca> updateNcas = findProgramNcas(updateRaf, 0, headerKey, keys, titleKeys);

            // Identify base and update Program NCAs:
            // - Base: largest Program NCA without BKTR romfs
            // - Update: Program NCA with BKTR romfs (the update's romfs is a delta against the base)
            ProgramNca baseNca = null, updateNca = null;

            // Check update NSP for the update NCA (BKTR romfs)
            for (ProgramNca p : updateNcas) {
                if (p.hasBktrRomfs && (updateNca == null || p.entry.size > updateNca.entry.size))
                    updateNca = p;
            }
            // Check base NSP for the base NCA (no BKTR)
            for (ProgramNca p : baseNcas) {
                if (!p.hasBktrRomfs && (baseNca == null || p.entry.size > baseNca.entry.size))
                    baseNca = p;
            }

            if (updateNca == null)
                throw new IOException("No update Program NCA found (no BKTR romfs section) — is this really the update NSP?");
            if (baseNca == null)
                throw new IOException("No base Program NCA found — is this really the base game NSP?");

            Log.i(TAG, "Base NCA: " + baseNca.entry.name + " (" + baseNca.entry.size + " bytes)");
            Log.i(TAG, "Update NCA: " + updateNca.entry.name + " (" + updateNca.entry.size + " bytes, BKTR)");

            // exefs comes from the update NCA (complete replacement, not BKTR)
            int updateExefsSection = -1, updateRomfsSection = -1;
            for (int i = 0; i < 4; i++) {
                if (updateNca.header.sections[i][0] == 0 && updateNca.header.sections[i][1] == 0) continue;
                FsHeader fs = parseFsHeader(updateNca.header.fsHeaders, i);
                if (fs == null) continue;
                if (fs.fsType == 1 && updateExefsSection < 0) updateExefsSection = i;
                else if (fs.fsType == 0 && updateRomfsSection < 0) updateRomfsSection = i;
            }
            if (updateExefsSection < 0) throw new IOException("No exefs section in update NCA");
            if (updateRomfsSection < 0) throw new IOException("No romfs section in update NCA");

            // romfs base section
            int baseRomfsSection = -1;
            for (int i = 0; i < 4; i++) {
                if (baseNca.header.sections[i][0] == 0 && baseNca.header.sections[i][1] == 0) continue;
                FsHeader fs = parseFsHeader(baseNca.header.fsHeaders, i);
                if (fs != null && fs.fsType == 0 && baseRomfsSection < 0) baseRomfsSection = i;
            }
            if (baseRomfsSection < 0) throw new IOException("No romfs section in base NCA");

            long totalSize = baseNca.entry.size + updateNca.entry.size;
            long[] progressState = {0, totalSize};

            // Extract exefs from update NCA
            Log.i(TAG, "Extracting exefs from update NCA (section " + updateExefsSection + ")...");
            extractExefs(updateRaf, updateNca.entry.offset, updateNca.header, updateExefsSection,
                    updateNca.decKey, exefsDir, progress, progressState);

            // Extract romfs via BKTR (base + update)
            Log.i(TAG, "Extracting romfs via BKTR (base section " + baseRomfsSection +
                    ", update section " + updateRomfsSection + ")...");
            extractRomfsBktr(baseRaf, baseNca.entry.offset, baseNca.header, baseRomfsSection, baseNca.decKey,
                    updateRaf, updateNca.entry.offset, updateNca.header, updateRomfsSection, updateNca.decKey,
                    romfsFile, progress, progressState);

            result.ok = true;
        } catch (Exception e) {
            Log.e(TAG, "NSP extraction failed", e);
            result.error = e.getMessage() != null ? e.getMessage() : e.toString();
            result.ok = false;
        } finally {
            close(baseRaf);
            close(updateRaf);
        }
        return result;
    }

    // Derive the content decryption key for an NCA: from a title key (rights_id set) or the key area
    private static byte[] deriveDecKey(NcaHeader nca, Map<String, byte[]> prodKeys,
                                       Map<String, byte[]> titleKeys) throws Exception {
        int keyGen = Math.max(nca.keyGenOld, nca.keyGen);
        if (keyGen < 1) keyGen = 1; // minimum generation
        String genHex = String.format("%02x", keyGen - 1);

        String rightsHex = hex(nca.rightsId);
        boolean hasRights = !rightsHex.matches("0+");

        if (hasRights) {
            // Title key decryption: titlekek_XX decrypts the title key from the ticket
            byte[] encTitleKey = titleKeys.get(rightsHex);
            if (encTitleKey == null)
                throw new IOException("No ticket for rights_id " + rightsHex);

            byte[] titlekek = prodKeys.get("titlekek_" + genHex);
            if (titlekek == null) {
                // Try without leading zero
                titlekek = prodKeys.get("titlekek_" + (keyGen - 1));
            }
            if (titlekek == null)
                throw new IOException("titlekek_" + genHex + " not found in prod.keys");

            Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(titlekek, "AES"));
            return c.doFinal(encTitleKey);
        } else {
            // Key area decryption
            String[] kaekNames = {"key_area_key_application_", "key_area_key_ocean_", "key_area_key_system_"};
            int idx = Math.min(nca.kaekIndex, 2);
            byte[] kaek = prodKeys.get(kaekNames[idx] + genHex);
            if (kaek == null)
                throw new IOException(kaekNames[idx] + genHex + " not found in prod.keys");

            Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(kaek, "AES"));
            // Key area index 0 = Application key, used for section decryption (AES-CTR areas use index 2 for some NCAs)
            // For Program NCAs the content key is typically key area entry 2 (the CTR key)
            byte[] decKey = c.doFinal(nca.keyArea[2]);
            if (allZero(decKey)) decKey = c.doFinal(nca.keyArea[0]); // fallback
            return decKey;
        }
    }

    // ---- Utilities ----

    private static boolean allZero(byte[] b) {
        for (byte v : b) if (v != 0) return false;
        return true;
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte v : b) sb.append(String.format("%02x", v & 0xFF));
        return sb.toString();
    }

    static String hex(byte[] b, int off, int len) {
        StringBuilder sb = new StringBuilder(len * 2);
        for (int i = off; i < off + len && i < b.length; i++) sb.append(String.format("%02x", b[i] & 0xFF));
        return sb.toString();
    }

    static byte[] unhex(String s) {
        int len = s.length() / 2;
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++)
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return out;
    }

    // FileChannel read helpers (FileChannel.read takes ByteBuffer, not byte[])
    private static int readFully(FileChannel ch, byte[] buf) throws IOException {
        return readFully(ch, buf, 0, buf.length);
    }

    private static int readFully(FileChannel ch, byte[] buf, int off, int len) throws IOException {
        ByteBuffer bb = ByteBuffer.wrap(buf, off, len);
        int total = 0;
        while (bb.hasRemaining()) {
            int n = ch.read(bb);
            if (n < 0) break;
            total += n;
        }
        return total;
    }

    private static void close(Closeable c) {
        if (c != null) try { c.close(); } catch (IOException ignored) {}
    }
}
