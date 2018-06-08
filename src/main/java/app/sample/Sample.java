package app.sample;

import java.util.HashSet;
import java.util.List;

import com.google.gson.JsonArray;

public class Sample {
    private String sha256;
    private String md5;
    private List<Function> functions;
    private HashSet<String> strings;
    private JsonArray imports;
    private JsonArray exports;
    private String arch;
    private int bits;
    private int id;

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
     * @param exports the exports to set
     */
    public void setExports(JsonArray exports) {
        this.exports = exports;
    }

    /**
     * @return the exports
     */
    public JsonArray getExports() {
        return exports;
    }

    /**
     * @param functions the functions to set
     */
    public void setFunctions(List<Function> functions) {
        this.functions = functions;
    }

    /**
     * @return the functions
     */
    public List<Function> getFunctions() {
        return functions;
    }

    /**
     * @param id the id to set
     */
    public void setId(int id) {
        this.id = id;
    }

    /**
     * @return the id
     */
    public int getId() {
        return id;
    }

    /**
     * @param imports the imports to set
     */
    public void setImports(JsonArray imports) {
        this.imports = imports;
    }

    /**
     * @return the imports
     */
    public JsonArray getImports() {
        return imports;
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
     * @param strings the strings to set
     */
    public void setStrings(HashSet<String> strings) {
        this.strings = strings;
    }

    /**
     * @return the strings
     */
    public HashSet<String> getStrings() {
        return strings;
    }

}