package app.sample;

import java.util.List;

public class Function {
    private String md5;
    private String sha256;
    private Long size;
    private String arch;
    private int bits;
    private List<String> ops;
    private int offset;
    private List<Long> minHashes;
    private int nmbBands;

    /**
     * @param arch the arch to set
     */
    public void setArch(String arch) {
        this.arch = arch;
    }

    /**
     * @return the arch
     */
    public String getArch() {
        return arch;
    }

    /**
     * @param bits the bits to set
     */
    public void setBits(int bits) {
        this.bits = bits;
    }

    /**
     * @return the bits
     */
    public int getBits() {
        return bits;
    }

    /**
     * @param md5 the md5 to set
     */
    public void setMd5(String md5) {
        this.md5 = md5;
    }

    /**
     * @return the md5
     */
    public String getMd5() {
        return md5;
    }

    /**
     * @param offset the offset to set
     */
    public void setOffset(int offset) {
        this.offset = offset;
    }

    /**
     * @return the offset
     */
    public int getOffset() {
        return offset;
    }

    /**
     * @param ops the ops to set
     */
    public void setOps(List<String> ops) {
        this.ops = ops;
    }

    /**
     * @return the ops
     */
    public List<String> getOps() {
        return ops;
    }

    /**
     * @param sha256 the sha256 to set
     */
    public void setSha256(String sha256) {
        this.sha256 = sha256;
    }

    /**
     * @return the sha256
     */
    public String getSha256() {
        return sha256;
    }

    /**
     * @param size the size to set
     */
    public void setSize(Long size) {
        this.size = size;
    }

    /**
     * @return the size
     */
    public Long getSize() {
        return size;
    }

    /**
     * @return the minHashes
     */
    public List<Long> getMinHashes() {
        return minHashes;
    }

    /**
     * @param minHashes the minHashes to set
     */
    public void setMinHashes(List<Long> minHashes) {
        this.minHashes = minHashes;
    }

    /**
     * @return the nmbBands
     */
    public int getNmbBands() {
        return nmbBands;
    }

    /**
     * @param nmbBands the nmbBands to set
     */
    public void setNmbBands(int nmbBands) {
        this.nmbBands = nmbBands;
    }

}