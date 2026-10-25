package common.crypto;

import java.util.Arrays;

/** Small, table-based AES-128 block cipher implementation for coursework. */
public final class ManualAes128 {
    private static final int[] S = hexTable("637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
            + "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
            + "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
            + "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
            + "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
            + "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
            + "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9f"
            + "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16");
    private static final int[] INV = inverseTable();
    private static final int[] RCON = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

    private ManualAes128() { }

    public static byte[] encryptBlock(byte[] block, byte[] key) {
        checkBlockAndKey(block, key);
        byte[] state = block.clone(), roundKeys = expandKey(key);
        addRoundKey(state, roundKeys, 0);
        for (int round = 1; round < 10; round++) {
            subBytes(state, S); shiftRows(state, false); mixColumns(state, false); addRoundKey(state, roundKeys, round);
        }
        subBytes(state, S); shiftRows(state, false); addRoundKey(state, roundKeys, 10);
        Arrays.fill(roundKeys, (byte) 0);
        return state;
    }

    public static byte[] decryptBlock(byte[] block, byte[] key) {
        checkBlockAndKey(block, key);
        byte[] state = block.clone(), roundKeys = expandKey(key);
        addRoundKey(state, roundKeys, 10);
        for (int round = 9; round > 0; round--) {
            shiftRows(state, true); subBytes(state, INV); addRoundKey(state, roundKeys, round); mixColumns(state, true);
        }
        shiftRows(state, true); subBytes(state, INV); addRoundKey(state, roundKeys, 0);
        Arrays.fill(roundKeys, (byte) 0);
        return state;
    }

    private static void checkBlockAndKey(byte[] block, byte[] key) {
        if (block == null || block.length != 16) throw new IllegalArgumentException("AES bloğu 16 byte olmalı.");
        if (key == null || key.length != 16) throw new IllegalArgumentException("AES-128 anahtarı 16 byte olmalı.");
    }

    private static byte[] expandKey(byte[] key) {
        byte[] expanded = new byte[176]; System.arraycopy(key, 0, expanded, 0, 16);
        int generated = 16, round = 1; byte[] temp = new byte[4];
        while (generated < expanded.length) {
            System.arraycopy(expanded, generated - 4, temp, 0, 4);
            if (generated % 16 == 0) {
                byte first = temp[0]; temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = first;
                for (int i = 0; i < 4; i++) temp[i] = (byte) S[temp[i] & 0xff];
                temp[0] ^= (byte) RCON[round++];
            }
            for (int i = 0; i < 4; i++, generated++) expanded[generated] = (byte) (expanded[generated - 16] ^ temp[i]);
        }
        return expanded;
    }

    private static void addRoundKey(byte[] state, byte[] keys, int round) {
        int offset = round * 16; for (int i = 0; i < 16; i++) state[i] ^= keys[offset + i];
    }
    private static void subBytes(byte[] state, int[] table) { for (int i = 0; i < 16; i++) state[i] = (byte) table[state[i] & 0xff]; }
    private static void shiftRows(byte[] state, boolean inverse) {
        byte[] copy = state.clone();
        for (int row = 0; row < 4; row++) for (int col = 0; col < 4; col++) {
            int sourceCol = (col + (inverse ? 4 - row : row)) & 3;
            state[col * 4 + row] = copy[sourceCol * 4 + row];
        }
    }
    private static void mixColumns(byte[] s, boolean inverse) {
        for (int c = 0; c < 4; c++) {
            int i = c * 4, a=s[i]&255, b=s[i+1]&255, d=s[i+2]&255, e=s[i+3]&255;
            if (!inverse) {
                s[i]=(byte)(mul(a,2)^mul(b,3)^d^e); s[i+1]=(byte)(a^mul(b,2)^mul(d,3)^e);
                s[i+2]=(byte)(a^b^mul(d,2)^mul(e,3)); s[i+3]=(byte)(mul(a,3)^b^d^mul(e,2));
            } else {
                s[i]=(byte)(mul(a,14)^mul(b,11)^mul(d,13)^mul(e,9)); s[i+1]=(byte)(mul(a,9)^mul(b,14)^mul(d,11)^mul(e,13));
                s[i+2]=(byte)(mul(a,13)^mul(b,9)^mul(d,14)^mul(e,11)); s[i+3]=(byte)(mul(a,11)^mul(b,13)^mul(d,9)^mul(e,14));
            }
        }
    }
    private static int mul(int a, int b) {
        int result = 0;
        while (b != 0) { if ((b & 1) != 0) result ^= a; a = ((a << 1) ^ ((a & 0x80) != 0 ? 0x11b : 0)) & 0xff; b >>>= 1; }
        return result;
    }
    private static int[] inverseTable() { int[] t = new int[256]; for (int i = 0; i < 256; i++) t[S[i]] = i; return t; }
    private static int[] hexTable(String hex) { int[] t = new int[hex.length()/2]; for (int i=0;i<t.length;i++) t[i]=Integer.parseInt(hex.substring(i*2,i*2+2),16); return t; }
}
