import java.io.*;

/**
 * Mirrors the read sequence of
 *   org.eclipse.mat.parser.internal.SnapshotImpl.readFromFile
 * on a MAT `.index` file, so an index MAT would reject can be pinpointed in
 * milliseconds instead of by launching MAT (-Xmx48g, minutes, and it deletes
 * the index files it cannot read).
 *
 * Sequence (from javap of SnapshotImpl.readFromFile):
 *   readUTF() -> version ("MAT_01")
 *   readUTF() -> parser id
 *   readObject() -> XSnapshotInfo
 *   readObject() -> HashMapIntObject  (classcache)
 *   readObject() -> HashMapIntObject  (roots)
 *   readObject() -> HashMapIntObject  (rootsPerThread)
 *   readObject() -> HashMapIntObject  (loaderLabels)
 *   readObject() -> BitField          (arrayObjects)
 *
 * Exit code 0 = every step succeeded (MAT would accept), 1 = rejected.
 */
public class IndexProbe {
    static class Count extends InputStream {
        final InputStream in;
        long n = 0;
        Count(InputStream in) { this.in = in; }
        public int read() throws IOException { int c = in.read(); if (c >= 0) n++; return c; }
        public int read(byte[] b, int off, int len) throws IOException {
            int r = in.read(b, off, len);
            if (r > 0) n += r;
            return r;
        }
        public long skip(long s) throws IOException { long r = in.skip(s); n += r; return r; }
        public int available() throws IOException { return in.available(); }
        public void close() throws IOException { in.close(); }
    }

    static void hexdump(String path, long off) {
        try (RandomAccessFile f = new RandomAccessFile(path, "r")) {
            long start = Math.max(0, off - 32);
            f.seek(start);
            byte[] buf = new byte[96];
            int r = f.read(buf);
            StringBuilder hex = new StringBuilder();
            StringBuilder asc = new StringBuilder();
            for (int i = 0; i < r; i++) {
                long abs = start + i;
                if (abs == off) { hex.append("["); asc.append("["); }
                hex.append(String.format("%02x ", buf[i]));
                asc.append(buf[i] >= 32 && buf[i] < 127 ? (char) buf[i] : '.');
                if (abs == off) { hex.append("]"); asc.append("]"); }
                if ((i + 1) % 16 == 0 && i + 1 < r) { hex.append("\n           "); asc.append("\n           "); }
            }
            System.out.println("  bytes around " + off + ":\n           " + hex + "\n           " + asc);
        } catch (IOException e) {
            System.out.println("  (hexdump failed: " + e + ")");
        }
    }

    static void fail(String what, String path, long off, Throwable t) {
        System.out.println("  REJECT: " + what + " FAILED at offset " + off + " :: " + t);
        hexdump(path, off);
        System.exit(1);
    }

    public static void main(String[] args) throws Exception {
        String path = args[0];
        Count cis = new Count(new FileInputStream(path));
        ObjectInputStream in = new ObjectInputStream(cis);
        System.out.println("file: " + path);
        System.out.println("  after OIS stream header: offset=" + cis.n);

        try {
            String v = in.readUTF();
            System.out.println("  readUTF#1 version  = '" + v + "'  offset=" + cis.n);
        } catch (Throwable t) { fail("readUTF#1(version)", path, cis.n, t); }

        try {
            String p = in.readUTF();
            System.out.println("  readUTF#2 parserId = '" + p + "'  offset=" + cis.n);
        } catch (Throwable t) { fail("readUTF#2(parserId)", path, cis.n, t); }

        String[] names = {
            "XSnapshotInfo",
            "classcache   HashMapIntObject<ClassImpl>",
            "roots        HashMapIntObject<XGCRootInfo[]>",
            "rootsPerThread HashMapIntObject<List<XGCRootInfo[]>>",
            "loaderLabels HashMapIntObject<String>",
            "arrayObjects BitField",
        };
        for (int i = 0; i < names.length; i++) {
            try {
                Object o = in.readObject();
                String info = "";
                if (o instanceof org.eclipse.mat.collect.HashMapIntObject) {
                    info = " size=" + ((org.eclipse.mat.collect.HashMapIntObject<?>) o).size();
                }
                System.out.println("  readObject[" + i + "] " + names[i] + " -> "
                    + (o == null ? "null" : o.getClass().getName()) + info + "  offset=" + cis.n);
            } catch (Throwable t) {
                fail(names[i], path, cis.n, t);
            }
        }
        System.out.println("  ACCEPT: all 8 reads succeeded");
        System.exit(0);
    }
}
