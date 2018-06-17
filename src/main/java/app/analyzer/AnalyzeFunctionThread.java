package app.analyzer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.radare.r2pipe.R2Pipe;

import app.sample.Function;

public class AnalyzeFunctionThread implements Runnable {
    Thread thread;
    private ConcurrentLinkedQueue<JsonObject> queue;
    private String filepath;
    private JsonObject config;
    private List<String> sha256Fns;
    private List<Function> functions;
    private int[] randomNmbr = new int[199];

    AnalyzeFunctionThread(ConcurrentLinkedQueue<JsonObject> queue, String filepath, JsonObject config,
            List<String> sha256Fns, List<Function> functions) {
        this.queue = queue;
        this.filepath = filepath;
        this.config = config;
        this.sha256Fns = sha256Fns;
        this.functions = functions;
        this.randomNmbr = new int[] { 1400141918, 1088051807, 296695290, 788941711, 1015302657, 711102612, 202305079,
                650261255, 1856646168, 194348387, 2118047015, 1279545195, 771757151, 1592680454, 205239508, 1880364191,
                479349330, 1319333579, 1906787552, 1367109751, 1597606134, 1417342103, 1310937971, 976782070, 180169654,
                1169913489, 127128227, 1473180006, 1871267270, 1762231795, 151522164, 506467913, 1842465463, 942911692,
                53369361, 1611264004, 1537573900, 1007620698, 275430419, 1616105509, 1886337833, 1381755661, 1045827543,
                631218441, 742228144, 433607324, 1193630307, 1185694108, 936630653, 435360002, 1558055324, 8972323,
                35533112, 99765792, 38819162, 316326700, 1154022397, 1102818969, 1629647464, 1480559931, 1490483765,
                675306858, 2008631084, 1801263370, 1386538122, 1372432893, 1522813846, 655965933, 393375551, 1662327446,
                1791129215, 1471821927, 575664584, 1473030314, 1893754284, 1685038128, 1842049137, 99690784, 440545054,
                79065993, 851392260, 796077796, 1957964654, 1763352008, 29178833, 1040525232, 997111746, 1961378667,
                393803297, 918684160, 1024372641, 1007139884, 552441763, 1891700611, 1714023245, 538846796, 1537252533,
                355789504, 1911755085, 1612661209, 1001584613, 975278848, 1427228876, 1170780023, 807071561, 529027321,
                338162749, 467330386, 435936210, 508000353, 1750724195, 1841979710, 58951741, 358896454, 245072517,
                72054992, 1722240900, 425404637, 584860238, 1554239306, 326962472, 719880103, 151817789, 1847706248,
                1627424455, 1078724381, 1978541121, 86223047, 1285950847, 706841833, 2118403401, 1397749040, 629560296,
                1169393583, 2064026925, 179491724, 713457941, 1201957364, 1466055257, 791294361, 573210502, 1651572432,
                1904058397, 264815328, 120896817, 1568720593, 870711593, 182727442, 1786974829, 1444365121, 1213965973,
                974627300, 339166070, 384571435, 1827822066, 1624375138, 1232473674, 626995394, 1135285638, 1938815019,
                747575424, 132101787, 894045411, 1831691202, 1247268786, 1152347213, 1551052509, 749917642, 2009109361,
                1227910947, 1060213828, 1541656410, 1430786153, 617966091, 997445653, 430836073, 664598542, 1010569567,
                1851568865, 2121871791, 1089600229, 421707929, 1895528166, 1907665357, 1827638733, 39395729, 1355605248,
                260630238, 877986956, 1769955839, 628685823, 1193485351, 491988776, 1260022200, 378665970, 180390575,
                514810111, 1060928997, 1492597117 };
    }

    private List<String> getShingles(int n, List<String> input) {
        List<String> shingles = new ArrayList<>();

        for (int i = 0; i < input.size() - n; i++) {
            String shingle = "";
            for (int j = 0; j < n; j++) {
                shingle += input.get(i + j) + " ";
            }
            shingles.add(shingle);
        }
        return shingles;
    }

    private List<Long> calculateMinHash(List<String> shingles) {
        List<List<Long>> allHashes = new ArrayList<>();
        List<Long> minHashes = new ArrayList<>();
        List<Long> firstHashes = new ArrayList<>();

        for (int i = 0; i < shingles.size(); i++) {
            firstHashes.add((long) shingles.get(i).hashCode());
        }
        minHashes.add(Collections.min(firstHashes));

        for (int j : this.randomNmbr) {
            List<Long> tmp = new ArrayList<>();
            for (Long hash : firstHashes) {
                tmp.add(hash ^ j);
            }
            minHashes.add(Collections.min(tmp));
        }

        return minHashes;
    }

    public void run() {
        try {
            R2Pipe r2p = new R2Pipe(filepath);
            while (!queue.isEmpty()) {
                JsonObject functionInfo = queue.remove();
                Function function = new Function();
                JsonParser jsonParser = new JsonParser();

                if (functionInfo.get("size").getAsInt() >= config.get("THRESHOLD_FCT_SIZE").getAsInt()) {
                    Integer offset = functionInfo.get("offset").getAsInt();
                    function.setOffset(offset);
                    r2p.cmd(String.format("af @ %d", offset));
                    String sha256Fn = r2p.cmd(String.format("ph sha256 %d @ %d", functionInfo.get("size").getAsInt(),
                            functionInfo.get("offset").getAsInt())).toUpperCase().replace("\n", "");

                    if (!sha256Fns.contains(sha256Fn)) {
                        String md5Fn = r2p.cmd(String.format("ph md5 %d @ %d", functionInfo.get("size").getAsInt(),
                                functionInfo.get("offset").getAsInt())).toUpperCase().replace("\n", "");

                        function.setSha256(sha256Fn);
                        function.setMd5(md5Fn);
                        String resultPdfj = r2p.cmd(String.format("pdfj @ %d", offset));
                        JsonObject fnDisas = jsonParser.parse(resultPdfj).getAsJsonObject();

                        JsonArray ops = fnDisas.get("ops").getAsJsonArray();
                        List<String> fnOps = new ArrayList<String>();
                        for (JsonElement eOp : ops) {
                            JsonObject op = eOp.getAsJsonObject();
                            if (op.has("type")) {
                                String sOp = op.get("type").getAsString();
                                fnOps.add("\"" + sOp + "\"");
                            }
                        }
                        function.setOps(fnOps);
                        function.setSize(functionInfo.get("size").getAsLong());
                        List<String> shingles = this.getShingles(5, fnOps);
                        List<Long> minHashes = this.calculateMinHash(shingles);
                        function.setMinHashes(minHashes);
                        function.setOffset(functionInfo.get("offset").getAsInt());
                        functions.add(function);
                    }
                }

            }
            r2p.quit();
        } catch (Exception e) {
            System.out.println("ANALYZEFCTTHREAD: " + e.getMessage());
        }
    }
}